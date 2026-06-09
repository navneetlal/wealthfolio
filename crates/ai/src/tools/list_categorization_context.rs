//! List Categorization Context tool — prerequisite for `propose_transaction_categories`.
//!
//! Returns the data the agent needs to reason about uncategorized rows:
//! taxonomies, recent few-shot examples, and the list of rows that need
//! AI/manual judgement (already filtered by rules + same-payee history). Rows
//! matched by rules/history are still draft proposals; the full review widget
//! comes from `propose_transaction_categories`.

use log::debug;
use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::env::AiEnvironment;
use crate::error::AiError;
use crate::tools::propose_categories::{
    compute_categorization_state, CategorizationFilters, CategoryExample, TaxonomySummary,
    UnproposedActivity,
};

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

pub struct ListCategorizationContextTool<E: AiEnvironment> {
    env: Arc<E>,
}

impl<E: AiEnvironment> ListCategorizationContextTool<E> {
    pub fn new(env: Arc<E>) -> Self {
        Self { env }
    }
}

impl<E: AiEnvironment> Clone for ListCategorizationContextTool<E> {
    fn clone(&self) -> Self {
        Self {
            env: self.env.clone(),
        }
    }
}

impl<E: AiEnvironment + 'static> Tool for ListCategorizationContextTool<E> {
    const NAME: &'static str = "list_categorization_context";

    type Error = AiError;
    type Args = ListCategorizationContextArgs;
    type Output = ListCategorizationContextOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description:
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
                    .to_string(),
            parameters: serde_json::json!({
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
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        debug!("list_categorization_context called");

        let state = compute_categorization_state(
            &self.env,
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

        Ok(ListCategorizationContextOutput {
            taxonomies: state.taxonomies,
            examples: state.examples,
            unproposed: state.unproposed,
            summary,
            next_step,
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
