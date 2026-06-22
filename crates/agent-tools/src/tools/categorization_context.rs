//! List Categorization Context tool — prerequisite for `propose_transaction_categories`.
//!
//! Returns the data the agent needs to reason about uncategorized rows:
//! taxonomies, recent few-shot examples, and the list of rows that need
//! AI/manual judgement (already filtered by rules + same-payee history). The
//! widget for this tool is a one-line compact summary; the full review widget
//! comes from `propose_transaction_categories` (which stays in
//! `wealthfolio-ai` and shares [`compute_categorization_state`]).

use chrono::{DateTime, Utc};
use log::debug;
use rust_decimal::prelude::ToPrimitive;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::env::AgentEnvironment;
use crate::scope::AgentScope;
use crate::tool::{AgentTool, AgentToolAccess, AgentToolError, AgentToolResult};
use wealthfolio_core::accounts::account_types;
use wealthfolio_spending::cash_activities::{
    CashActivity, CashActivitySearchRequest, CashActivityStatusFilter,
};

const DEFAULT_LIMIT: usize = 100;
/// Max rows per categorization call; also caps explicit `activityIds`.
pub const MAX_LIMIT: usize = 100;
const HISTORY_FETCH_LIMIT: usize = 400;
const EXAMPLES_PER_CATEGORY: usize = 3;
const MAX_TOTAL_EXAMPLES: usize = 80;
/// Max characters of a transaction's notes surfaced to the model.
pub const MAX_NOTES_LEN: usize = 100;

/// Truncate notes to [`MAX_NOTES_LEN`] characters, appending an ellipsis.
pub fn truncate_notes(s: &str) -> String {
    // Use char count consistently — byte len would spuriously truncate UTF-8 strings
    // with multi-byte characters that have fewer than MAX_NOTES_LEN characters.
    if s.chars().count() <= MAX_NOTES_LEN {
        s.to_string()
    } else {
        let mut out = s.chars().take(MAX_NOTES_LEN).collect::<String>();
        out.push('…');
        out
    }
}

/// Normalize a notes string to a payee key: lowercase, drop numeric/symbol
/// tokens, keep the first three tokens.
pub fn normalize_payee(notes: &str) -> String {
    notes
        .to_lowercase()
        .split_whitespace()
        .filter(|tok| {
            !tok.chars()
                .all(|c| c.is_ascii_digit() || c == '*' || c == '#')
        })
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryOption {
    pub category_id: String,
    pub key: String,
    pub name: String,
    pub path: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomySummary {
    pub taxonomy_id: String,
    pub taxonomy_name: String,
    pub categories: Vec<CategoryOption>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryExample {
    pub category_id: String,
    pub category_path: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    pub activity_id: String,
    pub activity_date: String,
    pub amount: f64,
    pub currency: String,
    pub notes: Option<String>,
    pub taxonomy_id: String,
    pub category_id: String,
    pub category_path: String,
    pub confidence: f32,
    /// "rule" | "history" | "ai"
    pub source: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnproposedActivity {
    pub activity_id: String,
    pub activity_date: String,
    pub amount: f64,
    pub currency: String,
    pub notes: Option<String>,
    pub reason: String,
}

/// Filters shared by `list_categorization_context` and
/// `propose_transaction_categories`.
#[derive(Debug, Default)]
pub struct CategorizationFilters {
    pub activity_ids: Option<Vec<String>>,
    pub account_ids: Option<Vec<String>>,
    pub status: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<u32>,
}

/// Result of the shared deterministic categorization pass.
pub struct CategorizationState {
    pub is_empty: bool,
    pub total: usize,
    pub proposals: Vec<Proposal>,
    pub unproposed: Vec<UnproposedActivity>,
    pub taxonomies: Vec<TaxonomySummary>,
    pub examples: Vec<CategoryExample>,
    /// (taxonomy_id, category_key) -> (taxonomy_id, category_id, path). Used to
    /// resolve agent-supplied category keys back to live IDs.
    pub key_lookup: HashMap<(String, String), (String, String, String)>,
}

/// Shared deterministic pass — fetches activities + taxonomies + history, runs
/// rules + same-payee match, returns the full state. Used by both
/// `propose_transaction_categories` (which then merges agent aiProposals) and
/// `list_categorization_context` (which exposes the agent-facing context only).
pub async fn compute_categorization_state(
    env: &dyn AgentEnvironment,
    filters: CategorizationFilters,
) -> Result<CategorizationState, AgentToolError> {
    let limit = filters
        .limit
        .map(|n| (n as usize).min(MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT)
        .max(1);

    let status = match filters.status.as_deref() {
        Some("all") => CashActivityStatusFilter::All,
        Some("needs_review") => CashActivityStatusFilter::NeedsReview,
        _ => CashActivityStatusFilter::Uncategorized,
    };

    let cash = env.cash_activity_service();
    let targets = if let Some(ids) = filters.activity_ids.as_ref() {
        validate_explicit_activity_ids(ids)?;
        let mut targets = cash
            .get_by_activity_ids(ids)
            .await
            .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?;
        let account_type_by_id = account_types_for_targets(env, &targets)?;
        retain_explicit_targets(&mut targets, &filters, status, &account_type_by_id)?;
        targets.truncate(limit);
        targets
    } else {
        let target_request = CashActivitySearchRequest {
            account_ids: filters.account_ids.clone(),
            status,
            start_date: filters.start_date.clone(),
            end_date: filters.end_date.clone(),
            limit,
            ..Default::default()
        };
        cash.search(target_request)
            .await
            .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?
            .items
    };
    if targets.is_empty() {
        return Ok(CategorizationState {
            is_empty: true,
            total: 0,
            proposals: Vec::new(),
            unproposed: Vec::new(),
            taxonomies: Vec::new(),
            examples: Vec::new(),
            key_lookup: HashMap::new(),
        });
    }
    let history_account_ids = filters.account_ids.clone().or_else(|| {
        filters.activity_ids.as_ref().map(|_| {
            let mut ids = targets
                .iter()
                .map(|item| item.activity.account_id.clone())
                .collect::<Vec<_>>();
            ids.sort();
            ids.dedup();
            ids
        })
    });

    let tax_service = env.taxonomy_service();
    let all_taxonomies = tax_service
        .get_taxonomies_with_categories()
        .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?;
    let activity_taxonomies: Vec<_> = all_taxonomies
        .into_iter()
        .filter(|t| t.taxonomy.scope == "activity")
        .collect();

    // category_id -> (taxonomy_id, taxonomy_name, category_name, path, color)
    let mut category_lookup: HashMap<String, (String, String, String, String, String)> =
        HashMap::new();
    let mut key_lookup: HashMap<(String, String), (String, String, String)> = HashMap::new();
    let mut taxonomy_summaries = Vec::with_capacity(activity_taxonomies.len());
    for entry in &activity_taxonomies {
        let cats_by_id: HashMap<&str, &_> = entry
            .categories
            .iter()
            .map(|c| (c.id.as_str(), c))
            .collect();
        let mut options = Vec::with_capacity(entry.categories.len());
        for cat in &entry.categories {
            let path = build_category_path(cat, &cats_by_id);
            category_lookup.insert(
                cat.id.clone(),
                (
                    entry.taxonomy.id.clone(),
                    entry.taxonomy.name.clone(),
                    cat.name.clone(),
                    path.clone(),
                    cat.color.clone(),
                ),
            );
            key_lookup.insert(
                (entry.taxonomy.id.clone(), cat.key.clone()),
                (entry.taxonomy.id.clone(), cat.id.clone(), path.clone()),
            );
            options.push(CategoryOption {
                category_id: cat.id.clone(),
                key: cat.key.clone(),
                name: cat.name.clone(),
                path,
                color: cat.color.clone(),
            });
        }
        taxonomy_summaries.push(TaxonomySummary {
            taxonomy_id: entry.taxonomy.id.clone(),
            taxonomy_name: entry.taxonomy.name.clone(),
            categories: options,
        });
    }

    let history_request = CashActivitySearchRequest {
        account_ids: history_account_ids,
        status: CashActivityStatusFilter::Categorized,
        limit: HISTORY_FETCH_LIMIT,
        ..Default::default()
    };
    let history_response = cash
        .search(history_request)
        .await
        .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?;

    let mut payee_map: HashMap<(String, String), HashMap<(String, String), usize>> = HashMap::new();
    for item in &history_response.items {
        let Some(notes) = item.activity.notes.as_deref() else {
            continue;
        };
        let payee_key = normalize_payee(notes);
        if payee_key.is_empty() {
            continue;
        }
        let key = (payee_key, item.activity.effective_type().to_string());
        for asg in &item.assignments {
            payee_map
                .entry(key.clone())
                .or_default()
                .entry((asg.taxonomy_id.clone(), asg.category_id.clone()))
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }
    }

    let mut per_cat_count: HashMap<String, usize> = HashMap::new();
    let mut examples = Vec::new();
    for item in &history_response.items {
        if examples.len() >= MAX_TOTAL_EXAMPLES {
            break;
        }
        let Some(notes) = item.activity.notes.as_deref() else {
            continue;
        };
        for asg in &item.assignments {
            let count = per_cat_count.entry(asg.category_id.clone()).or_insert(0);
            if *count >= EXAMPLES_PER_CATEGORY {
                continue;
            }
            let Some((_tax_id, _tax_name, _cat_name, path, _color)) =
                category_lookup.get(&asg.category_id)
            else {
                continue;
            };
            examples.push(CategoryExample {
                category_id: asg.category_id.clone(),
                category_path: path.clone(),
                notes: truncate_notes(notes),
            });
            *count += 1;
            break;
        }
    }

    let rules_service = env.categorization_rules_service();
    let all_rules = rules_service
        .list()
        .await
        .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?;
    let compiled_rules =
        wealthfolio_spending::categorization_rules::matcher::compile_rules(&all_rules);

    let total = targets.len();
    let mut proposals = Vec::new();
    let mut unproposed = Vec::new();
    for target in &targets {
        let act = &target.activity;
        let amount = act.amount.and_then(|d| d.to_f64()).unwrap_or(0.0);
        let date = act.activity_date.format("%Y-%m-%d").to_string();
        let notes_trimmed = act.notes.as_deref().map(truncate_notes);

        let notes = act.notes.as_deref().unwrap_or("");
        let notes_upper = notes.to_uppercase();
        let rule_match = wealthfolio_spending::categorization_rules::matcher::match_compiled(
            &compiled_rules,
            &notes_upper,
            notes,
            act.effective_type(),
            &act.account_id,
        );
        if let Some(m) = rule_match {
            if let (Some(tax_id), Some(cat_id)) =
                (m.rule.taxonomy_id.clone(), m.rule.category_id.clone())
            {
                if let Some((_, _, _, path, _)) = category_lookup.get(&cat_id) {
                    proposals.push(Proposal {
                        activity_id: act.id.clone(),
                        activity_date: date.clone(),
                        amount,
                        currency: act.currency.clone(),
                        notes: notes_trimmed.clone(),
                        taxonomy_id: tax_id,
                        category_id: cat_id,
                        category_path: path.clone(),
                        confidence: 0.95,
                        source: "rule".to_string(),
                        explanation: format!("Matched rule \"{}\".", m.rule.name),
                    });
                    continue;
                }
            }
        }

        let history_match = act
            .notes
            .as_deref()
            .map(normalize_payee)
            .filter(|k| !k.is_empty())
            .and_then(|key| {
                payee_map
                    .get(&(key, act.effective_type().to_string()))
                    .cloned()
            })
            .and_then(|by_cat| {
                by_cat
                    .into_iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|((tax_id, cat_id), count)| (tax_id, cat_id, count))
            });

        if let Some((tax_id, cat_id, count)) = history_match {
            if let Some((_, _, _, path, _)) = category_lookup.get(&cat_id) {
                let confidence = if count >= 3 {
                    0.92
                } else if count == 2 {
                    0.82
                } else {
                    0.7
                };
                proposals.push(Proposal {
                    activity_id: act.id.clone(),
                    activity_date: date,
                    amount,
                    currency: act.currency.clone(),
                    notes: notes_trimmed,
                    taxonomy_id: tax_id,
                    category_id: cat_id,
                    category_path: path.clone(),
                    confidence,
                    source: "history".to_string(),
                    explanation: format!("Matched same payee in {} prior transaction(s).", count),
                });
                continue;
            }
        }

        unproposed.push(UnproposedActivity {
            activity_id: act.id.clone(),
            activity_date: date,
            amount,
            currency: act.currency.clone(),
            notes: notes_trimmed,
            reason: "No rule or history match — needs AI or manual judgement.".to_string(),
        });
    }

    Ok(CategorizationState {
        is_empty: false,
        total,
        proposals,
        unproposed,
        taxonomies: taxonomy_summaries,
        examples,
        key_lookup,
    })
}

/// Reject explicit `activityIds` lists larger than [`MAX_LIMIT`].
pub fn validate_explicit_activity_ids(ids: &[String]) -> Result<(), AgentToolError> {
    if ids.len() > MAX_LIMIT {
        return Err(AgentToolError::InvalidInput(format!(
            "activityIds supports at most {MAX_LIMIT} ids"
        )));
    }
    Ok(())
}

/// Apply account/date/status filters to explicitly-requested targets,
/// mirroring what the search path enforces server-side.
pub fn retain_explicit_targets(
    targets: &mut Vec<CashActivity>,
    filters: &CategorizationFilters,
    status: CashActivityStatusFilter,
    account_type_by_id: &HashMap<String, String>,
) -> Result<(), AgentToolError> {
    let allowed_accounts: Option<HashSet<String>> = filters
        .account_ids
        .as_ref()
        .filter(|ids| !ids.is_empty())
        .map(|ids| ids.iter().cloned().collect());
    let start = parse_filter_datetime("startDate", filters.start_date.as_deref())?;
    let end = parse_filter_datetime("endDate", filters.end_date.as_deref())?;

    targets.retain(|item| {
        if let Some(account_ids) = &allowed_accounts {
            if !account_ids.contains(&item.activity.account_id) {
                return false;
            }
        }
        if let Some(start) = start.as_ref() {
            if &item.activity.activity_date < start {
                return false;
            }
        }
        if let Some(end) = end.as_ref() {
            if &item.activity.activity_date > end {
                return false;
            }
        }

        let has_category =
            is_neutral_visible_target(item, account_type_by_id) || !item.assignments.is_empty();
        match status {
            CashActivityStatusFilter::All => true,
            CashActivityStatusFilter::NeedsReview => item.activity.needs_review,
            CashActivityStatusFilter::Uncategorized => !has_category,
            CashActivityStatusFilter::Categorized => has_category,
        }
    });

    Ok(())
}

fn account_types_for_targets(
    env: &dyn AgentEnvironment,
    targets: &[CashActivity],
) -> Result<HashMap<String, String>, AgentToolError> {
    let account_ids = targets
        .iter()
        .map(|item| item.activity.account_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if account_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let accounts = env
        .account_service()
        .get_accounts_by_ids(&account_ids)
        .map_err(|e| AgentToolError::ExecutionFailed(e.to_string()))?;
    Ok(accounts
        .into_iter()
        .map(|account| (account.id, account.account_type))
        .collect())
}

fn is_neutral_visible_target(
    item: &CashActivity,
    account_type_by_id: &HashMap<String, String>,
) -> bool {
    account_type_by_id
        .get(&item.activity.account_id)
        .is_some_and(|account_type| {
            account_type == account_types::CREDIT_CARD
                && item.activity.effective_type() == "TRANSFER_IN"
                && item.activity.source_group_id.is_some()
        })
}

fn parse_filter_datetime(
    field: &str,
    value: Option<&str>,
) -> Result<Option<DateTime<Utc>>, AgentToolError> {
    value
        .map(|value| DateTime::parse_from_rfc3339(value).map(|date| date.with_timezone(&Utc)))
        .transpose()
        .map_err(|e| AgentToolError::InvalidInput(format!("Invalid {field}: {e}")))
}

/// Build "Parent / Child" path for a category, capped at depth 8 to survive
/// accidental cycles.
pub fn build_category_path(
    cat: &wealthfolio_core::taxonomies::Category,
    cats_by_id: &HashMap<&str, &wealthfolio_core::taxonomies::Category>,
) -> String {
    let mut parts = vec![cat.name.clone()];
    let mut current_parent = cat.parent_id.as_deref();
    let mut depth = 0;
    while let Some(pid) = current_parent {
        if depth > 8 {
            break;
        }
        if let Some(parent) = cats_by_id.get(pid) {
            parts.push(parent.name.clone());
            current_parent = parent.parent_id.as_deref();
        } else {
            break;
        }
        depth += 1;
    }
    parts.reverse();
    parts.join(" / ")
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCategorizationContextArgs {
    pub activity_ids: Option<Vec<String>>,
    pub account_ids: Option<Vec<String>>,
    pub status: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextSummary {
    pub total: usize,
    /// Rows pre-matched by rules or same-payee history. The agent doesn't need
    /// AI proposals for these, but they are not applied until the review widget
    /// is rendered and confirmed.
    pub deterministically_proposed: usize,
    /// Rows the agent should propose categories for via
    /// `propose_transaction_categories(aiProposals: [...])`.
    pub needs_ai_judgement: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCategorizationContextOutput {
    /// Activity-scope taxonomies — the universe of `categoryKey`s the agent may pick from.
    pub taxonomies: Vec<TaxonomySummary>,
    /// Recent user-confirmed categorizations (few-shot signal).
    pub examples: Vec<CategoryExample>,
    /// Rows the agent should infer categories for.
    pub unproposed: Vec<UnproposedActivity>,
    pub summary: ContextSummary,
    /// Instructional state for the chat agent. This is intentionally explicit
    /// because "0 need AI judgement" still requires a proposal widget when
    /// deterministic rule/history matches exist.
    pub next_step: String,
}

/// Tool returning the categorization context (taxonomies, examples,
/// unproposed rows) the agent needs before proposing categories.
pub struct ListCategorizationContext;

#[async_trait::async_trait]
impl AgentTool for ListCategorizationContext {
    fn name(&self) -> &'static str {
        "list_categorization_context"
    }

    fn description(&self) -> &'static str {
        "Prerequisite for `propose_transaction_categories`. Returns the activity-scope \
         taxonomies, recent few-shot examples, and the list of cash transactions that \
         need AI categorization (rows pre-matched by rules or same-payee history \
         are excluded from `unproposed` but are NOT applied). After receiving this result, \
         call `propose_transaction_categories` with the SAME filters to render the review \
         widget whenever `summary.total > 0`. If `unproposed` is empty / \
         `needsAiJudgement` is 0, call it with `aiProposals: []`; otherwise infer the best \
         `taxonomyId` + `categoryKey` pair for each `unproposed` row from `taxonomies` \
         using `examples` + merchant-name knowledge, then pass those as `aiProposals`. \
         Never tell the user categories were applied from this context result alone. \
         Do NOT pass `accountIds` for generic mentions like 'credit card' — the \
         spending settings already restrict to opted-in accounts."
    }

    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "activityIds": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional explicit set of activity IDs."
                },
                "accountIds": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "OMIT unless the user names a specific account by exact name or ID."
                },
                "status": {
                    "type": "string",
                    "enum": ["uncategorized", "all", "needs_review"],
                    "description": "Default: uncategorized."
                },
                "startDate": { "type": "string", "description": "Inclusive ISO 8601 lower bound." },
                "endDate":   { "type": "string", "description": "Inclusive ISO 8601 upper bound." },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "Max rows. Default 100."
                }
            }
        })
    }

    fn required_scopes(&self) -> &'static [AgentScope] {
        &[AgentScope::ClassificationRead]
    }

    fn access_level(&self) -> AgentToolAccess {
        AgentToolAccess::Read
    }

    async fn call(
        &self,
        env: Arc<dyn AgentEnvironment>,
        args: serde_json::Value,
    ) -> Result<AgentToolResult, AgentToolError> {
        debug!("list_categorization_context called");
        let args: ListCategorizationContextArgs = serde_json::from_value(args)?;

        let state = compute_categorization_state(
            env.as_ref(),
            CategorizationFilters {
                activity_ids: args.activity_ids,
                account_ids: args.account_ids,
                status: args.status,
                start_date: args.start_date,
                end_date: args.end_date,
                limit: args.limit,
            },
        )
        .await?;

        let summary = ContextSummary {
            total: state.total,
            deterministically_proposed: state.proposals.len(),
            needs_ai_judgement: state.unproposed.len(),
        };
        let next_step = next_step_instruction(&summary);

        let output = ListCategorizationContextOutput {
            taxonomies: state.taxonomies,
            examples: state.examples,
            unproposed: state.unproposed,
            summary,
            next_step,
        };
        Ok(AgentToolResult {
            content: serde_json::to_value(output)?,
        })
    }
}

fn next_step_instruction(summary: &ContextSummary) -> String {
    if summary.total == 0 {
        return "No matching transactions were found; there is no categorization widget to render."
            .to_string();
    }

    if summary.needs_ai_judgement == 0 {
        return "Call propose_transaction_categories with aiProposals: [] and the same filters to render the review widget. Rule/history matches are draft proposals, not applied categories.".to_string();
    }

    format!(
        "Infer categories for the {} unproposed row(s), then call propose_transaction_categories with those aiProposals and the same filters to render the review widget.",
        summary.needs_ai_judgement
    )
}
