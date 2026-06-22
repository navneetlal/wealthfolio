//! Tool implementations.
//!
//! Tools migrate here from `wealthfolio-ai` one at a time; each keeps its
//! existing name, schema, and output shape (guarded by the parity
//! snapshots in `crates/ai/tests/`).

pub mod accounts;
pub mod activities;
pub mod allocation;
pub mod asset_taxonomies;
pub mod cash_balances;
pub mod categorization_context;
pub mod goals;
pub mod health;
pub mod holdings;
pub mod income;
pub mod performance;
pub mod valuation;

pub use accounts::{AccountDto, GetAccounts, GetAccountsArgs, GetAccountsOutput};
pub use activities::{ActivityDto, SearchActivities, SearchActivitiesArgs, SearchActivitiesOutput};
// `allocation::HoldingDto` is intentionally not re-exported here: it would
// collide with `holdings::HoldingDto`. Reach it as `allocation::HoldingDto`.
pub use allocation::{
    AllocationDto, GetAssetAllocation, GetAssetAllocationArgs, GetAssetAllocationOutput,
};
pub use asset_taxonomies::{
    AssetTaxonomyAssignmentDto, AssetTaxonomyCategoryDto, AssetTaxonomyDto,
    GetAssetTaxonomyAssignments, GetAssetTaxonomyAssignmentsArgs,
    GetAssetTaxonomyAssignmentsOutput, ListAssetTaxonomies, ListAssetTaxonomiesArgs,
    ListAssetTaxonomiesOutput, ResolvedAssetDto,
};
pub use cash_balances::{
    AccountCashSummary, CashBalanceEntry, GetCashBalances, GetCashBalancesArgs,
    GetCashBalancesOutput,
};
pub use categorization_context::{
    CategoryExample, CategoryOption, ContextSummary, ListCategorizationContext,
    ListCategorizationContextArgs, ListCategorizationContextOutput, Proposal, TaxonomySummary,
    UnproposedActivity,
};
pub use goals::{GetGoals, GetGoalsArgs, GetGoalsOutput, GoalDto};
pub use health::{GetHealthStatus, GetHealthStatusArgs, GetHealthStatusOutput, HealthIssueDto};
pub use holdings::{GetHoldings, GetHoldingsArgs, GetHoldingsOutput, HoldingDto};
pub use income::{GetIncome, GetIncomeArgs, GetIncomeOutput, TopAssetDto};
pub use performance::{
    GetPerformance, GetPerformanceArgs, GetPerformanceOutput, PerformanceAttributionOutput,
    PerformanceDataQualityOutput, PerformanceReturnsOutput, PerformanceRiskOutput,
};
pub use valuation::{
    GetValuationHistory, GetValuationHistoryArgs, GetValuationHistoryOutput, ValuationPointDto,
};

use std::sync::Arc;

use crate::tool::AgentTool;

/// The v1 read-only tool set, in catalog (and LLM-visible) order — the
/// read tools keep their historical relative order, but all of them are
/// now registered before the assistant's write tools (previously the two
/// kinds were interleaved).
pub fn v1_read_tools() -> Vec<Arc<dyn AgentTool>> {
    vec![
        Arc::new(GetHoldings),
        Arc::new(GetAccounts),
        Arc::new(GetCashBalances),
        Arc::new(SearchActivities),
        Arc::new(GetGoals),
        Arc::new(GetValuationHistory),
        Arc::new(GetIncome),
        Arc::new(GetAssetAllocation),
        Arc::new(GetPerformance),
        Arc::new(GetHealthStatus),
        Arc::new(ListCategorizationContext),
        Arc::new(ListAssetTaxonomies),
        Arc::new(GetAssetTaxonomyAssignments),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog order is LLM-visible (tool listing) and mirrors the
    /// read tools' historical relative order — append-only.
    #[test]
    fn v1_read_tools_names_and_order_are_stable() {
        let names: Vec<&str> = v1_read_tools().iter().map(|tool| tool.name()).collect();
        assert_eq!(
            names,
            vec![
                "get_holdings",
                "get_accounts",
                "get_cash_balances",
                "search_activities",
                "get_goals",
                "get_valuation_history",
                "get_income",
                "get_asset_allocation",
                "get_performance",
                "get_health_status",
                "list_categorization_context",
                "list_asset_taxonomies",
                "get_asset_taxonomy_assignments",
            ]
        );
    }
}
