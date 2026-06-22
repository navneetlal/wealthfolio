//! AI assistant tools for portfolio data access.
//!
//! Read tools live in `wealthfolio-agent-tools` (shared with MCP) and are
//! exposed to rig agents through `rig_adapter::RigAgentTool`. The tools
//! remaining here implement rig-core's Tool trait directly:
//! - RecordActivityTool: Create activity drafts from natural language
//! - RecordActivitiesTool: Create multiple activity drafts from natural language
//! - ImportCsvTool: Infer CSV column mappings and validate for import
//! - ProposeCategoriesTool: Categorize activities using rules + history
//! - CreateCategorizationRuleTool: Define new categorization rules
//! - PrepareAssetClassificationTool: Resolve asset classification conflicts
//!
//! All tools are designed to work with the AiEnvironment trait for dependency injection.

pub mod asset_classification;
pub mod constants;
pub mod create_categorization_rule;
pub mod import_csv;
pub mod propose_categories;
pub mod record_activities;
pub mod record_activity;
pub mod rig_adapter;

// Re-export constants
pub use constants::*;

// Re-export migrated agent tools (DTOs and unit structs) for compatibility.
// `allocation::HoldingDto` is skipped: it collides with `holdings::HoldingDto`
// (reach it as `wealthfolio_agent_tools::tools::allocation::HoldingDto`).
pub use wealthfolio_agent_tools::tools::{
    AccountCashSummary, AccountDto, ActivityDto, AllocationDto, AssetTaxonomyAssignmentDto,
    AssetTaxonomyCategoryDto, AssetTaxonomyDto, CashBalanceEntry, CategoryExample, CategoryOption,
    ContextSummary, GetAccounts, GetAccountsArgs, GetAccountsOutput, GetAssetAllocation,
    GetAssetAllocationArgs, GetAssetAllocationOutput, GetAssetTaxonomyAssignments,
    GetAssetTaxonomyAssignmentsArgs, GetAssetTaxonomyAssignmentsOutput, GetCashBalances,
    GetCashBalancesArgs, GetCashBalancesOutput, GetGoals, GetGoalsArgs, GetGoalsOutput,
    GetHealthStatus, GetHealthStatusArgs, GetHealthStatusOutput, GetHoldings, GetHoldingsArgs,
    GetHoldingsOutput, GetIncome, GetIncomeArgs, GetIncomeOutput, GetPerformance,
    GetPerformanceArgs, GetPerformanceOutput, GetValuationHistory, GetValuationHistoryArgs,
    GetValuationHistoryOutput, GoalDto, HealthIssueDto, HoldingDto, ListAssetTaxonomies,
    ListAssetTaxonomiesArgs, ListAssetTaxonomiesOutput, ListCategorizationContext,
    ListCategorizationContextArgs, ListCategorizationContextOutput, PerformanceAttributionOutput,
    PerformanceDataQualityOutput, PerformanceReturnsOutput, PerformanceRiskOutput, Proposal,
    ResolvedAssetDto, SearchActivities, SearchActivitiesArgs, SearchActivitiesOutput,
    TaxonomySummary, TopAssetDto, UnproposedActivity, ValuationPointDto,
};

// Re-export tools
pub use asset_classification::PrepareAssetClassificationTool;
pub use create_categorization_rule::CreateCategorizationRuleTool;
pub use import_csv::ImportCsvTool;
pub use propose_categories::{AiProposal, ProposeCategoriesTool};
pub use record_activities::RecordActivitiesTool;
pub use record_activity::RecordActivityTool;
pub use rig_adapter::RigAgentTool;

use once_cell::sync::Lazy;
use std::sync::Arc;
use wealthfolio_agent_tools::AgentToolCatalog;

use crate::env::AiEnvironment;

/// Process-wide catalog of migrated agent tools, shared by every chat
/// session (tools are stateless; the environment arrives per call).
static AGENT_CATALOG: Lazy<AgentToolCatalog> = Lazy::new(AgentToolCatalog::v1_read_tools);

/// The shared agent-tool catalog exposed to rig via [`RigAgentTool`].
pub fn agent_catalog() -> &'static AgentToolCatalog {
    &AGENT_CATALOG
}

/// Container for the assistant-only rig tools, simplifying tool
/// registration across providers. Migrated read tools are not listed here;
/// they come from [`agent_catalog`].
pub struct ToolSet<E: AiEnvironment> {
    pub record_activity: RecordActivityTool<E>,
    pub record_activities: RecordActivitiesTool<E>,
    pub import_csv: ImportCsvTool<E>,
    pub propose_categories: ProposeCategoriesTool<E>,
    pub create_categorization_rule: CreateCategorizationRuleTool<E>,
    pub prepare_asset_classification: PrepareAssetClassificationTool<E>,
}

impl<E: AiEnvironment> ToolSet<E> {
    /// Create a new tool set with all portfolio tools.
    pub fn new(env: Arc<E>, base_currency: String) -> Self {
        Self {
            record_activity: RecordActivityTool::new(env.clone()),
            record_activities: RecordActivitiesTool::new(env.clone()),
            import_csv: ImportCsvTool::new(env.clone(), base_currency),
            propose_categories: ProposeCategoriesTool::new(env.clone()),
            create_categorization_rule: CreateCategorizationRuleTool::new(env.clone()),
            prepare_asset_classification: PrepareAssetClassificationTool::new(env),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::test_env::MockEnvironment;
    use rig::tool::Tool;

    #[test]
    fn test_tool_set_creation() {
        let env = Arc::new(MockEnvironment::new());
        let _tools = ToolSet::new(env, "USD".to_string());
    }

    /// Each tool's NAME constant must match what the system prompt + frontend
    /// allowlist + chat.rs allowlist branch use. Drift here means the tool is
    /// registered but never enabled. Catches typos at compile/test time.
    #[test]
    fn tool_names_are_exactly_the_strings_used_by_allowlist() {
        use crate::types::DEFAULT_TOOLS_ALLOWLIST;
        let env = Arc::new(MockEnvironment::new());
        let tools = ToolSet::new(env, "USD".to_string());

        // Every tool's NAME must be in DEFAULT_TOOLS_ALLOWLIST. The reverse is
        // checked separately (some allowlist entries are read-only data tools
        // that aren't in ToolSet's ergonomic field list, which is fine).
        let registered_names = vec![
            <RecordActivityTool<MockEnvironment> as Tool>::NAME,
            <RecordActivitiesTool<MockEnvironment> as Tool>::NAME,
            <ImportCsvTool<MockEnvironment> as Tool>::NAME,
            <ProposeCategoriesTool<MockEnvironment> as Tool>::NAME,
            <CreateCategorizationRuleTool<MockEnvironment> as Tool>::NAME,
            <PrepareAssetClassificationTool<MockEnvironment> as Tool>::NAME,
        ];
        for name in &registered_names {
            assert!(
                DEFAULT_TOOLS_ALLOWLIST.contains(name),
                "Tool {name} is registered in ToolSet but missing from DEFAULT_TOOLS_ALLOWLIST — \
                 add it or it'll never be enabled by default. Drift between tool NAME and \
                 allowlist is the most common cause of 'I added a tool and the agent ignores it'.",
            );
        }
        let _ = tools;
    }

    /// Every migrated catalog tool must stay in DEFAULT_TOOLS_ALLOWLIST under
    /// its original name — names are the contract chat threads snapshot.
    #[test]
    fn agent_catalog_names_are_in_default_allowlist() {
        use crate::types::DEFAULT_TOOLS_ALLOWLIST;
        for tool in agent_catalog().iter() {
            assert!(
                DEFAULT_TOOLS_ALLOWLIST.contains(&tool.name()),
                "Catalog tool {} missing from DEFAULT_TOOLS_ALLOWLIST",
                tool.name()
            );
        }
    }
}
