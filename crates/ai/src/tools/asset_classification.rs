//! Asset classification tool.
//!
//! `prepare_asset_classification` prepares asset taxonomy assignment
//! previews for the chat widget. It never writes to the database; the
//! frontend applies accepted drafts with existing taxonomy assignment
//! mutations after user confirmation.
//!
//! The read-only companions (`list_asset_taxonomies`,
//! `get_asset_taxonomy_assignments`) and the shared asset-resolution
//! helpers live in `wealthfolio_agent_tools::tools::asset_taxonomies`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rig::{completion::ToolDefinition, tool::Tool};
use serde::{Deserialize, Serialize};
use wealthfolio_core::taxonomies::Category;

use crate::env::AiEnvironment;
use crate::error::AiError;
use wealthfolio_agent_tools::tools::asset_taxonomies::{
    asset_taxonomies, asset_to_dto, resolve_active_asset_match, validate_asset_taxonomy,
    ActiveAssetResolution, ResolvedAssetDto,
};

const AI_ASSIGNMENT_SOURCE: &str = "ai";

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareAssetClassificationArgs {
    pub asset_query: String,
    pub taxonomy_id: String,
    pub assignments: Vec<PreparedAssignmentInput>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedAssignmentInput {
    pub category_id: String,
    pub weight_basis_points: i32,
    pub source_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTaxonomyDto {
    pub taxonomy_id: String,
    pub name: String,
    pub is_single_select: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentPreviewDto {
    pub assignment_id: Option<String>,
    pub category_id: String,
    pub category_name: String,
    pub category_key: String,
    pub category_color: String,
    pub weight_basis_points: i32,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationChangesDto {
    pub add_count: usize,
    pub update_count: usize,
    pub remove_count: usize,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateAssignmentPreviewDto {
    pub asset_id: String,
    pub current_assignments: Vec<AssignmentPreviewDto>,
    pub changes: ClassificationChangesDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareAssetClassificationOutput {
    pub asset_query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_asset: Option<ResolvedAssetDto>,
    pub taxonomy: PreparedTaxonomyDto,
    pub current_assignments: Vec<AssignmentPreviewDto>,
    pub proposed_assignments: Vec<AssignmentPreviewDto>,
    pub changes: ClassificationChangesDto,
    pub unallocated_basis_points: i32,
    pub draft_status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_candidates: Vec<ResolvedAssetDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_current_assignments: Vec<CandidateAssignmentPreviewDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<String>,
}

pub struct PrepareAssetClassificationTool<E: AiEnvironment> {
    env: Arc<E>,
}

impl<E: AiEnvironment> PrepareAssetClassificationTool<E> {
    pub fn new(env: Arc<E>) -> Self {
        Self { env }
    }
}

impl<E: AiEnvironment> Clone for PrepareAssetClassificationTool<E> {
    fn clone(&self) -> Self {
        Self {
            env: self.env.clone(),
        }
    }
}

impl<E: AiEnvironment + 'static> Tool for PrepareAssetClassificationTool<E> {
    const NAME: &'static str = "prepare_asset_classification";

    type Error = AiError;
    type Args = PrepareAssetClassificationArgs;
    type Output = PrepareAssetClassificationOutput;

    async fn definition(&self, _prompt: String) -> ToolDefinition {
        ToolDefinition {
            name: Self::NAME.to_string(),
            description:
                "Prepare a non-mutating asset classification draft for the review widget. \
                 Use category IDs from list_asset_taxonomies for the selected taxonomy only. \
                 For sector allocation requests, use root/top-level categories from \
                 list_asset_taxonomies instead of detailed industry or subindustry categories. \
                 For region allocation requests based on country rows, use leaf country categories \
                 when that is the requested granularity; aggregate to root regions only for \
                 top-level/root region requests. \
                 Omit screenshot buckets such as Unknown, Other, Unclassified, or N/A when they \
                 do not exactly match an available category. Never map Other/Unknown/residual \
                 bucket weights to a plausible country, region, sector, or industry. Never invent \
                 placeholder category IDs. \
                 This tool does not apply changes; the user must confirm the widget."
                    .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "assetQuery": {
                        "type": "string",
                        "description": "Active local asset ID, ticker/display code, provider-suffixed ticker, or asset name."
                    },
                    "taxonomyId": {
                        "type": "string",
                        "description": "Asset-scoped taxonomy ID from list_asset_taxonomies."
                    },
                    "assignments": {
                        "type": "array",
                        "description": "Proposed categories for this asset and taxonomy. Empty array clears current assignments for the taxonomy.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "categoryId": { "type": "string" },
                                "weightBasisPoints": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 10000
                                },
                                "sourceLabel": {
                                    "type": "string",
                                    "description": "Original label exactly as shown by the user or screenshot before mapping to categoryId, for example 'United States'. Do not rewrite residual labels such as 'Other' or 'Unknown' as a country/category; omit those residual buckets unless they exactly match an available category."
                                }
                            },
                            "required": ["categoryId", "weightBasisPoints", "sourceLabel"]
                        }
                    }
                },
                "required": ["assetQuery", "taxonomyId", "assignments"]
            }),
        }
    }

    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        let taxonomies = asset_taxonomies(self.env.as_ref())?;
        let taxonomy = validate_asset_taxonomy(&taxonomies, &args.taxonomy_id)?;
        let category_lookup: HashMap<&str, &Category> = taxonomy
            .categories
            .iter()
            .map(|category| (category.id.as_str(), category))
            .collect();

        validate_proposed_assignments(
            taxonomy.taxonomy.is_single_select,
            &category_lookup,
            &args.assignments,
        )?;

        let proposed_assignments = args
            .assignments
            .iter()
            .filter(|assignment| assignment.weight_basis_points > 0)
            .map(|assignment| proposed_preview_dto(assignment, &category_lookup))
            .collect::<Result<Vec<_>, _>>()?;

        let total_weight: i32 = proposed_assignments
            .iter()
            .map(|assignment| assignment.weight_basis_points)
            .sum();

        let asset = match resolve_active_asset_match(self.env.as_ref(), &args.asset_query)? {
            ActiveAssetResolution::Resolved(asset) => asset,
            ActiveAssetResolution::Ambiguous(candidates) => {
                let candidate_current_assignments = candidates
                    .iter()
                    .map(|asset| {
                        let current_assignments = current_assignments_for_asset(
                            &self.env,
                            asset.id.as_str(),
                            &args.taxonomy_id,
                            &category_lookup,
                        )?;
                        Ok(CandidateAssignmentPreviewDto {
                            asset_id: asset.id.clone(),
                            changes: compute_changes(&current_assignments, &proposed_assignments),
                            current_assignments,
                        })
                    })
                    .collect::<Result<Vec<_>, AiError>>()?;

                return Ok(PrepareAssetClassificationOutput {
                    asset_query: args.asset_query,
                    resolved_asset: None,
                    taxonomy: PreparedTaxonomyDto {
                        taxonomy_id: taxonomy.taxonomy.id.clone(),
                        name: taxonomy.taxonomy.name.clone(),
                        is_single_select: taxonomy.taxonomy.is_single_select,
                    },
                    changes: ClassificationChangesDto::default(),
                    current_assignments: Vec::new(),
                    proposed_assignments,
                    unallocated_basis_points: 10000 - total_weight,
                    draft_status: "needsAssetSelection".to_string(),
                    asset_candidates: candidates
                        .iter()
                        .map(|asset| asset_to_dto(asset, "candidate"))
                        .collect(),
                    candidate_current_assignments,
                    applied_at: None,
                });
            }
            ActiveAssetResolution::NotFound(query) => {
                return Err(AiError::invalid_input(format!(
                    "Asset '{query}' was not found among active assets"
                )));
            }
        };

        let current_assignments = current_assignments_for_asset(
            &self.env,
            &asset.asset.id,
            &args.taxonomy_id,
            &category_lookup,
        )?;

        Ok(PrepareAssetClassificationOutput {
            asset_query: args.asset_query,
            resolved_asset: Some(asset.to_dto()),
            taxonomy: PreparedTaxonomyDto {
                taxonomy_id: taxonomy.taxonomy.id.clone(),
                name: taxonomy.taxonomy.name.clone(),
                is_single_select: taxonomy.taxonomy.is_single_select,
            },
            changes: compute_changes(&current_assignments, &proposed_assignments),
            current_assignments,
            proposed_assignments,
            unallocated_basis_points: 10000 - total_weight,
            draft_status: "draft".to_string(),
            asset_candidates: Vec::new(),
            candidate_current_assignments: Vec::new(),
            applied_at: None,
        })
    }
}

fn validate_proposed_assignments(
    is_single_select: bool,
    category_lookup: &HashMap<&str, &Category>,
    assignments: &[PreparedAssignmentInput],
) -> Result<(), AiError> {
    let mut seen = HashSet::new();
    for assignment in assignments {
        if !(0..=10000).contains(&assignment.weight_basis_points) {
            return Err(AiError::invalid_input(format!(
                "Weight for category '{}' must be between 0 and 10000 basis points",
                assignment.category_id
            )));
        }
        if assignment.weight_basis_points == 0 {
            continue;
        }
        if assignment.source_label.trim().is_empty() {
            return Err(AiError::invalid_input(format!(
                "sourceLabel is required for category '{}'",
                assignment.category_id
            )));
        }
        let Some(category) = category_lookup.get(assignment.category_id.as_str()) else {
            return Err(AiError::invalid_input(format!(
                "Category '{}' does not belong to the selected taxonomy",
                assignment.category_id
            )));
        };
        validate_source_label_mapping(assignment, category)?;
        if !seen.insert(assignment.category_id.as_str()) {
            return Err(AiError::invalid_input(format!(
                "Duplicate category ID '{}'",
                assignment.category_id
            )));
        }
    }

    if is_single_select {
        let non_zero_assignments = assignments
            .iter()
            .filter(|assignment| assignment.weight_basis_points > 0)
            .collect::<Vec<_>>();
        if non_zero_assignments.len() > 1 {
            return Err(AiError::invalid_input(
                "Single-select taxonomies allow only one category",
            ));
        }
        if let Some(assignment) = non_zero_assignments.first() {
            if assignment.weight_basis_points != 10000 {
                return Err(AiError::invalid_input(
                    "Single-select taxonomies require 10000 basis points",
                ));
            }
        }
    }

    Ok(())
}

fn validate_source_label_mapping(
    assignment: &PreparedAssignmentInput,
    category: &Category,
) -> Result<(), AiError> {
    let source_label = assignment.source_label.trim();
    if !is_residual_bucket_label(source_label)
        || category_matches_source_label(category, source_label)
    {
        return Ok(());
    }

    Err(AiError::invalid_input(format!(
        "Residual bucket '{}' cannot be mapped to category '{}'. Omit that bucket so it remains unallocated.",
        source_label, category.name
    )))
}

fn category_matches_source_label(category: &Category, source_label: &str) -> bool {
    let normalized_source = normalize_category_label(source_label);
    [
        category.name.as_str(),
        category.key.as_str(),
        category.id.as_str(),
    ]
    .iter()
    .any(|value| normalize_category_label(value) == normalized_source)
}

fn is_residual_bucket_label(label: &str) -> bool {
    matches!(
        normalize_category_label(label).as_str(),
        "unknown"
            | "other"
            | "unclassified"
            | "uncategorized"
            | "unallocated"
            | "not classified"
            | "not applicable"
            | "n a"
            | "na"
            | "misc"
            | "miscellaneous"
            | "remainder"
            | "remaining"
            | "residual"
            | "rest"
    )
}

fn normalize_category_label(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn current_assignments_for_asset<E: AiEnvironment>(
    env: &Arc<E>,
    asset_id: &str,
    taxonomy_id: &str,
    category_lookup: &HashMap<&str, &Category>,
) -> Result<Vec<AssignmentPreviewDto>, AiError> {
    Ok(env
        .taxonomy_service()
        .get_asset_assignments(asset_id)?
        .into_iter()
        .filter(|assignment| assignment.taxonomy_id == taxonomy_id)
        .filter_map(|assignment| current_preview_dto(&assignment, category_lookup))
        .collect())
}

fn current_preview_dto(
    assignment: &wealthfolio_core::taxonomies::AssetTaxonomyAssignment,
    category_lookup: &HashMap<&str, &Category>,
) -> Option<AssignmentPreviewDto> {
    let category = category_lookup.get(assignment.category_id.as_str())?;
    Some(AssignmentPreviewDto {
        assignment_id: Some(assignment.id.clone()),
        category_id: assignment.category_id.clone(),
        category_name: category.name.clone(),
        category_key: category.key.clone(),
        category_color: category.color.clone(),
        weight_basis_points: assignment.weight,
        source: assignment.source.clone(),
        source_label: None,
    })
}

fn proposed_preview_dto(
    assignment: &PreparedAssignmentInput,
    category_lookup: &HashMap<&str, &Category>,
) -> Result<AssignmentPreviewDto, AiError> {
    let category = category_lookup
        .get(assignment.category_id.as_str())
        .ok_or_else(|| {
            AiError::invalid_input(format!(
                "Category '{}' does not belong to the selected taxonomy",
                assignment.category_id
            ))
        })?;
    Ok(AssignmentPreviewDto {
        assignment_id: None,
        category_id: assignment.category_id.clone(),
        category_name: category.name.clone(),
        category_key: category.key.clone(),
        category_color: category.color.clone(),
        weight_basis_points: assignment.weight_basis_points,
        source: AI_ASSIGNMENT_SOURCE.to_string(),
        source_label: Some(assignment.source_label.clone()),
    })
}

fn compute_changes(
    current: &[AssignmentPreviewDto],
    proposed: &[AssignmentPreviewDto],
) -> ClassificationChangesDto {
    let current_by_category = current
        .iter()
        .map(|assignment| (assignment.category_id.as_str(), assignment))
        .collect::<HashMap<_, _>>();
    let proposed_by_category = proposed
        .iter()
        .map(|assignment| (assignment.category_id.as_str(), assignment))
        .collect::<HashMap<_, _>>();

    let mut changes = ClassificationChangesDto::default();
    for proposed_assignment in proposed {
        match current_by_category.get(proposed_assignment.category_id.as_str()) {
            None => changes.add_count += 1,
            Some(current_assignment)
                if current_assignment.weight_basis_points
                    != proposed_assignment.weight_basis_points
                    || current_assignment.source != AI_ASSIGNMENT_SOURCE =>
            {
                changes.update_count += 1;
            }
            Some(_) => changes.unchanged_count += 1,
        }
    }
    for current_assignment in current {
        if !proposed_by_category.contains_key(current_assignment.category_id.as_str()) {
            changes.remove_count += 1;
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use chrono::NaiveDateTime;
    use rig::tool::Tool;
    use wealthfolio_core::{
        assets::{Asset, AssetKind, InstrumentType, QuoteMode},
        taxonomies::{AssetTaxonomyAssignment, Category, Taxonomy, TaxonomyWithCategories},
    };

    use crate::env::test_env::{MockAssetService, MockEnvironment, MockTaxonomyService};

    fn env_with(
        assets: Vec<Asset>,
        taxonomies: Vec<TaxonomyWithCategories>,
        assignments: Vec<AssetTaxonomyAssignment>,
    ) -> Arc<MockEnvironment> {
        let mut env = MockEnvironment::new();
        env.asset_service = Arc::new(MockAssetService { assets });
        env.taxonomy_service = Arc::new(MockTaxonomyService {
            taxonomies,
            assignments,
        });
        Arc::new(env)
    }

    fn test_asset(
        id: &str,
        display_code: &str,
        symbol: &str,
        exchange_mic: Option<&str>,
        name: &str,
        is_active: bool,
    ) -> Asset {
        Asset {
            id: id.to_string(),
            kind: AssetKind::Investment,
            name: Some(name.to_string()),
            display_code: Some(display_code.to_string()),
            is_active,
            quote_mode: QuoteMode::Market,
            quote_ccy: "USD".to_string(),
            instrument_type: Some(InstrumentType::Equity),
            instrument_symbol: Some(symbol.to_string()),
            instrument_exchange_mic: exchange_mic.map(str::to_string),
            created_at: NaiveDateTime::default(),
            updated_at: NaiveDateTime::default(),
            ..Default::default()
        }
    }

    fn test_taxonomy(
        id: &str,
        scope: &str,
        is_single_select: bool,
        categories: Vec<Category>,
    ) -> TaxonomyWithCategories {
        TaxonomyWithCategories {
            taxonomy: Taxonomy {
                id: id.to_string(),
                name: "Asset Class".to_string(),
                color: "#2563eb".to_string(),
                description: None,
                is_system: false,
                is_single_select,
                sort_order: 1,
                created_at: NaiveDateTime::default(),
                updated_at: NaiveDateTime::default(),
                scope: scope.to_string(),
            },
            categories,
        }
    }

    fn test_category(taxonomy_id: &str, id: &str, name: &str) -> Category {
        Category {
            id: id.to_string(),
            taxonomy_id: taxonomy_id.to_string(),
            parent_id: None,
            name: name.to_string(),
            key: name.to_lowercase().replace(' ', "_"),
            color: "#64748b".to_string(),
            description: None,
            sort_order: 1,
            created_at: NaiveDateTime::default(),
            updated_at: NaiveDateTime::default(),
            icon: None,
        }
    }

    fn test_assignment(
        id: &str,
        asset_id: &str,
        taxonomy_id: &str,
        category_id: &str,
        weight: i32,
        source: &str,
    ) -> AssetTaxonomyAssignment {
        AssetTaxonomyAssignment {
            id: id.to_string(),
            asset_id: asset_id.to_string(),
            taxonomy_id: taxonomy_id.to_string(),
            category_id: category_id.to_string(),
            weight,
            source: source.to_string(),
            created_at: NaiveDateTime::default(),
            updated_at: NaiveDateTime::default(),
        }
    }

    fn prepared(category_id: &str, weight_basis_points: i32) -> PreparedAssignmentInput {
        prepared_with_source(category_id, weight_basis_points, category_id)
    }

    fn prepared_with_source(
        category_id: &str,
        weight_basis_points: i32,
        source_label: &str,
    ) -> PreparedAssignmentInput {
        PreparedAssignmentInput {
            category_id: category_id.to_string(),
            weight_basis_points,
            source_label: source_label.to_string(),
        }
    }

    #[tokio::test]
    async fn prepare_asset_classification_returns_draft_preview() {
        let env = env_with(
            vec![test_asset(
                "asset-aapl",
                "AAPL",
                "AAPL",
                Some("XNAS"),
                "Apple Inc.",
                true,
            )],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                false,
                vec![
                    test_category("asset-tax", "equity", "Equity"),
                    test_category("asset-tax", "cash", "Cash"),
                ],
            )],
            vec![test_assignment(
                "assignment-1",
                "asset-aapl",
                "asset-tax",
                "equity",
                10000,
                "manual",
            )],
        );

        let output = PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "AAPL".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments: vec![prepared("equity", 6000), prepared("cash", 3000)],
            })
            .await
            .unwrap();

        assert_eq!(output.draft_status, "draft");
        assert_eq!(
            output
                .resolved_asset
                .as_ref()
                .map(|asset| asset.asset_id.as_str()),
            Some("asset-aapl"),
        );
        assert_eq!(output.current_assignments.len(), 1);
        assert_eq!(output.proposed_assignments.len(), 2);
        assert_eq!(output.changes.add_count, 1);
        assert_eq!(output.changes.update_count, 1);
        assert_eq!(output.unallocated_basis_points, 1000);
    }

    #[tokio::test]
    async fn prepare_returns_asset_selection_candidates_when_query_is_ambiguous() {
        let env = env_with(
            vec![
                test_asset(
                    "asset-vt-xnas",
                    "VT",
                    "VT",
                    Some("XNAS"),
                    "Vanguard Total World Stock Index Fund ETF Shares",
                    true,
                ),
                test_asset(
                    "asset-vt-arcx",
                    "VT",
                    "VT",
                    Some("ARCX"),
                    "Vanguard Total World Stock Index Fund ETF Shares",
                    true,
                ),
            ],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                false,
                vec![test_category("asset-tax", "equity", "Equity")],
            )],
            vec![test_assignment(
                "assignment-xnas",
                "asset-vt-xnas",
                "asset-tax",
                "equity",
                10000,
                "manual",
            )],
        );

        let output = PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "VT".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments: vec![prepared("equity", 9000)],
            })
            .await
            .unwrap();

        assert_eq!(output.draft_status, "needsAssetSelection");
        assert!(output.resolved_asset.is_none());
        assert_eq!(output.asset_candidates.len(), 2);
        assert_eq!(output.asset_candidates[0].asset_id, "asset-vt-xnas");
        assert_eq!(
            output.asset_candidates[0].exchange_mic.as_deref(),
            Some("XNAS")
        );
        assert_eq!(output.asset_candidates[1].asset_id, "asset-vt-arcx");
        assert_eq!(output.proposed_assignments.len(), 1);
        assert_eq!(output.candidate_current_assignments.len(), 2);
        assert_eq!(
            output.candidate_current_assignments[0].asset_id,
            "asset-vt-xnas"
        );
        assert_eq!(
            output.candidate_current_assignments[0]
                .current_assignments
                .len(),
            1
        );
        assert_eq!(
            output.candidate_current_assignments[0].changes.update_count,
            1
        );
        assert_eq!(
            output.candidate_current_assignments[1].asset_id,
            "asset-vt-arcx"
        );
        assert_eq!(
            output.candidate_current_assignments[1]
                .current_assignments
                .len(),
            0
        );
        assert_eq!(output.candidate_current_assignments[1].changes.add_count, 1);
        assert_eq!(output.unallocated_basis_points, 1000);
    }

    #[tokio::test]
    async fn prepare_counts_source_only_difference_as_update() {
        let env = env_with(
            vec![test_asset(
                "asset-aapl",
                "AAPL",
                "AAPL",
                Some("XNAS"),
                "Apple Inc.",
                true,
            )],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                false,
                vec![test_category("asset-tax", "equity", "Equity")],
            )],
            vec![test_assignment(
                "assignment-1",
                "asset-aapl",
                "asset-tax",
                "equity",
                10000,
                "manual",
            )],
        );

        let output = PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "AAPL".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments: vec![prepared("equity", 10000)],
            })
            .await
            .unwrap();

        assert_eq!(output.changes.update_count, 1);
        assert_eq!(output.changes.unchanged_count, 0);
    }

    #[tokio::test]
    async fn prepare_rejects_duplicate_categories() {
        let error = prepare_error(vec![prepared("equity", 5000), prepared("equity", 5000)]).await;

        assert!(error.to_string().contains("Duplicate category ID"));
    }

    #[tokio::test]
    async fn prepare_rejects_single_select_multiple_categories() {
        let error =
            prepare_single_select_error(vec![prepared("equity", 5000), prepared("cash", 5000)])
                .await;

        assert!(error.to_string().contains("allow only one category"));
    }

    #[tokio::test]
    async fn prepare_rejects_single_select_partial_weight() {
        let error = prepare_single_select_error(vec![prepared("equity", 5000)]).await;

        assert!(error.to_string().contains("require 10000 basis points"));
    }

    #[tokio::test]
    async fn prepare_rejects_invalid_weights() {
        let error = prepare_error(vec![prepared("equity", -1)]).await;

        assert!(error.to_string().contains("between 0 and 10000"));
    }

    #[tokio::test]
    async fn prepare_rejects_missing_source_label() {
        let error = prepare_error(vec![prepared_with_source("equity", 10000, "")]).await;

        assert!(error.to_string().contains("sourceLabel is required"));
    }

    #[tokio::test]
    async fn prepare_rejects_residual_bucket_mapped_to_category() {
        let error = prepare_error(vec![prepared_with_source("cash", 935, "Other")]).await;

        let message = error.to_string();
        assert!(message.contains("Residual bucket"));
        assert!(message.contains("cannot be mapped"));
    }

    #[tokio::test]
    async fn prepare_allows_residual_bucket_when_category_matches_exactly() {
        let env = env_with(
            vec![test_asset(
                "asset-aapl",
                "AAPL",
                "AAPL",
                Some("XNAS"),
                "Apple Inc.",
                true,
            )],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                false,
                vec![test_category("asset-tax", "other", "Other")],
            )],
            vec![],
        );

        let output = PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "AAPL".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments: vec![prepared_with_source("other", 935, "Other")],
            })
            .await
            .unwrap();

        assert_eq!(output.proposed_assignments.len(), 1);
        assert_eq!(output.proposed_assignments[0].category_id, "other");
        assert_eq!(
            output.proposed_assignments[0].source_label.as_deref(),
            Some("Other")
        );
    }

    #[tokio::test]
    async fn prepare_allows_over_allocation_as_invalid_draft() {
        let output = prepare_success(vec![prepared("equity", 7000), prepared("cash", 4000)]).await;

        assert_eq!(output.unallocated_basis_points, -1000);
        assert_eq!(output.proposed_assignments.len(), 2);
    }

    #[tokio::test]
    async fn prepare_allows_under_allocation() {
        let output = prepare_success(vec![prepared("equity", 6000)]).await;

        assert_eq!(output.unallocated_basis_points, 4000);
    }

    #[tokio::test]
    async fn prepare_treats_zero_weight_assignments_as_removals() {
        let env = env_with(
            vec![test_asset(
                "asset-aapl",
                "AAPL",
                "AAPL",
                Some("XNAS"),
                "Apple Inc.",
                true,
            )],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                false,
                vec![
                    test_category("asset-tax", "equity", "Equity"),
                    test_category("asset-tax", "cash", "Cash"),
                ],
            )],
            vec![
                test_assignment(
                    "assignment-equity",
                    "asset-aapl",
                    "asset-tax",
                    "equity",
                    6000,
                    "ai",
                ),
                test_assignment(
                    "assignment-cash",
                    "asset-aapl",
                    "asset-tax",
                    "cash",
                    4000,
                    "manual",
                ),
            ],
        );

        let output = PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "AAPL".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments: vec![prepared("equity", 6000), prepared("cash", 0)],
            })
            .await
            .unwrap();

        assert_eq!(output.current_assignments.len(), 2);
        assert_eq!(output.proposed_assignments.len(), 1);
        assert_eq!(output.proposed_assignments[0].category_id, "equity");
        assert_eq!(output.changes.remove_count, 1);
        assert_eq!(output.changes.unchanged_count, 1);
        assert_eq!(output.changes.add_count, 0);
        assert_eq!(output.changes.update_count, 0);
        assert_eq!(output.unallocated_basis_points, 4000);
    }

    #[tokio::test]
    async fn prepare_ignores_zero_weight_unknown_category() {
        let output = prepare_success(vec![prepared("UNKNOWN", 0), prepared("equity", 10000)]).await;

        assert_eq!(output.proposed_assignments.len(), 1);
        assert_eq!(output.proposed_assignments[0].category_id, "equity");
        assert_eq!(output.unallocated_basis_points, 0);
    }

    async fn prepare_success(
        assignments: Vec<PreparedAssignmentInput>,
    ) -> PrepareAssetClassificationOutput {
        prepare_with_single_select(assignments, false)
            .await
            .unwrap()
    }

    async fn prepare_error(assignments: Vec<PreparedAssignmentInput>) -> AiError {
        prepare_with_single_select(assignments, false)
            .await
            .unwrap_err()
    }

    async fn prepare_single_select_error(assignments: Vec<PreparedAssignmentInput>) -> AiError {
        prepare_with_single_select(assignments, true)
            .await
            .unwrap_err()
    }

    async fn prepare_with_single_select(
        assignments: Vec<PreparedAssignmentInput>,
        is_single_select: bool,
    ) -> Result<PrepareAssetClassificationOutput, AiError> {
        let env = env_with(
            vec![test_asset(
                "asset-aapl",
                "AAPL",
                "AAPL",
                Some("XNAS"),
                "Apple Inc.",
                true,
            )],
            vec![test_taxonomy(
                "asset-tax",
                "asset",
                is_single_select,
                vec![
                    test_category("asset-tax", "equity", "Equity"),
                    test_category("asset-tax", "cash", "Cash"),
                ],
            )],
            vec![],
        );

        PrepareAssetClassificationTool::new(env)
            .call(PrepareAssetClassificationArgs {
                asset_query: "AAPL".to_string(),
                taxonomy_id: "asset-tax".to_string(),
                assignments,
            })
            .await
    }
}
