//! Health service implementation.
//!
//! The HealthService orchestrates health checks, manages dismissals,
//! and handles fix actions.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use log::{debug, info, warn};
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::accounts::{
    account_types, is_liability_account_type, Account, AccountServiceTrait, TrackingMode,
};
use crate::activities::{Activity, ActivityServiceTrait, TransferPairResolution};
use crate::assets::{Asset, AssetServiceTrait};
use crate::errors::Result;
use crate::lots::LotRepositoryTrait;
use crate::portfolio::holdings::HoldingsServiceTrait;
use crate::portfolio::performance::is_external_transfer;
use crate::portfolio::valuation::ValuationServiceTrait;
use crate::quotes::QuoteServiceTrait;
use crate::taxonomies::TaxonomyServiceTrait;
use crate::utils::time_utils::{activity_date_in_tz, parse_user_timezone_or_default};

use super::checks::{
    AccountConfigurationCheck, AssetHoldingInfo, ClassificationCheck, ConsistencyIssueInfo,
    DataConsistencyCheck, FxIntegrityCheck, FxPairInfo, InvalidTransferGroupInfo,
    LegacyMigrationInfo, PriceStalenessCheck, QuoteSyncCheck, QuoteSyncErrorInfo,
    TransferIntegrityCheck, TransferLegDetail, UnclassifiedAssetInfo, UnconfiguredAccountInfo,
};
use super::errors::HealthError;
use super::model::{FixAction, HealthConfig, HealthIssue, HealthStatus, IssueDismissal};
use super::traits::{HealthContext, HealthDismissalStore, HealthServiceTrait};

/// Cache entry for health status.
struct CachedStatus {
    status: HealthStatus,
    cached_at: chrono::DateTime<chrono::Utc>,
}

/// Service for running health checks and managing health status.
pub struct HealthService {
    /// Storage for dismissals
    dismissal_store: Arc<dyn HealthDismissalStore>,

    /// Current configuration
    config: RwLock<HealthConfig>,

    /// Cached health status
    cached_status: RwLock<Option<CachedStatus>>,

    /// Individual check implementations
    price_check: PriceStalenessCheck,
    quote_sync_check: QuoteSyncCheck,
    fx_check: FxIntegrityCheck,
    classification_check: ClassificationCheck,
    consistency_check: DataConsistencyCheck,
    account_config_check: AccountConfigurationCheck,
    transfer_integrity_check: TransferIntegrityCheck,
}

impl HealthService {
    /// Creates a new health service.
    pub fn new(dismissal_store: Arc<dyn HealthDismissalStore>) -> Self {
        Self {
            dismissal_store,
            config: RwLock::new(HealthConfig::default()),
            cached_status: RwLock::new(None),
            price_check: PriceStalenessCheck::new(),
            quote_sync_check: QuoteSyncCheck::new(),
            fx_check: FxIntegrityCheck::new(),
            classification_check: ClassificationCheck::new(),
            consistency_check: DataConsistencyCheck::new(),
            account_config_check: AccountConfigurationCheck::new(),
            transfer_integrity_check: TransferIntegrityCheck::new(),
        }
    }

    /// Creates a health service with custom configuration.
    pub fn with_config(
        dismissal_store: Arc<dyn HealthDismissalStore>,
        config: HealthConfig,
    ) -> Self {
        Self {
            dismissal_store,
            config: RwLock::new(config),
            cached_status: RwLock::new(None),
            price_check: PriceStalenessCheck::new(),
            quote_sync_check: QuoteSyncCheck::new(),
            fx_check: FxIntegrityCheck::new(),
            classification_check: ClassificationCheck::new(),
            consistency_check: DataConsistencyCheck::new(),
            account_config_check: AccountConfigurationCheck::new(),
            transfer_integrity_check: TransferIntegrityCheck::new(),
        }
    }

    /// Runs all health checks with the provided data.
    ///
    /// This is the main entry point for running checks. The caller is responsible
    /// for gathering the necessary data from the portfolio.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_checks_with_data(
        &self,
        base_currency: &str,
        total_portfolio_value: f64,
        holdings: &[AssetHoldingInfo],
        latest_quote_times: &std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
        quote_sync_errors: &[QuoteSyncErrorInfo],
        fx_pairs: &[FxPairInfo],
        unclassified_assets: &[UnclassifiedAssetInfo],
        consistency_issues: &[ConsistencyIssueInfo],
        legacy_migration_info: &Option<LegacyMigrationInfo>,
        unconfigured_accounts: &[UnconfiguredAccountInfo],
        configured_timezone: Option<&str>,
        client_timezone: Option<&str>,
        invalid_transfer_groups: &[InvalidTransferGroupInfo],
    ) -> Result<HealthStatus> {
        let config = self.config.read().await.clone();
        let ctx = HealthContext::new(config, base_currency, total_portfolio_value);

        info!(
            "Running health checks for portfolio (base currency: {})",
            base_currency
        );

        let mut all_issues = Vec::new();

        // Run price staleness check
        debug!(
            "Running price staleness check on {} holdings",
            holdings.len()
        );
        let price_issues = self.price_check.analyze(holdings, latest_quote_times, &ctx);
        debug!("Price staleness check found {} issues", price_issues.len());
        all_issues.extend(price_issues);

        // Run quote sync error check
        debug!(
            "Running quote sync check on {} assets with errors",
            quote_sync_errors.len()
        );
        let sync_issues = self.quote_sync_check.analyze(quote_sync_errors, &ctx);
        debug!("Quote sync check found {} issues", sync_issues.len());
        all_issues.extend(sync_issues);

        // Run FX integrity check
        debug!("Running FX integrity check on {} pairs", fx_pairs.len());
        let fx_issues = self.fx_check.analyze(fx_pairs, &ctx);
        debug!("FX integrity check found {} issues", fx_issues.len());
        all_issues.extend(fx_issues);

        // Run classification check
        debug!(
            "Running classification check on {} unclassified assets",
            unclassified_assets.len()
        );
        let class_issues = self.classification_check.analyze(unclassified_assets, &ctx);
        debug!("Classification check found {} issues", class_issues.len());
        all_issues.extend(class_issues);

        // Run legacy migration check
        debug!("Running legacy migration check");
        let migration_issues = self
            .classification_check
            .analyze_legacy_migration(legacy_migration_info, &ctx);
        debug!(
            "Legacy migration check found {} issues",
            migration_issues.len()
        );
        all_issues.extend(migration_issues);

        // Run data consistency check
        debug!(
            "Running data consistency check with {} potential issues",
            consistency_issues.len()
        );
        let consistency_health_issues = self.consistency_check.analyze(consistency_issues, &ctx);
        debug!(
            "Data consistency check found {} issues",
            consistency_health_issues.len()
        );
        all_issues.extend(consistency_health_issues);

        // Run account configuration check
        debug!(
            "Running account configuration check on {} unconfigured accounts",
            unconfigured_accounts.len()
        );
        let account_config_issues = self.account_config_check.analyze(
            unconfigured_accounts,
            configured_timezone,
            client_timezone,
            &ctx,
        );
        debug!(
            "Account configuration check found {} issues",
            account_config_issues.len()
        );
        all_issues.extend(account_config_issues);

        // Run transfer integrity check (invalid / incomplete transfer groups)
        debug!(
            "Running transfer integrity check on {} invalid groups",
            invalid_transfer_groups.len()
        );
        let transfer_issues = self
            .transfer_integrity_check
            .analyze(invalid_transfer_groups, &ctx);
        debug!(
            "Transfer integrity check found {} issues",
            transfer_issues.len()
        );
        all_issues.extend(transfer_issues);

        // Filter out dismissed issues (unless data has changed)
        let filtered_issues = self.filter_dismissed_issues(all_issues).await?;

        // Build status
        let status = HealthStatus::from_issues(filtered_issues);

        // Cache the result
        let cached = CachedStatus {
            status: status.clone(),
            cached_at: Utc::now(),
        };
        *self.cached_status.write().await = Some(cached);

        info!(
            "Health check complete: {} issues found (overall severity: {:?})",
            status.total_count(),
            status.overall_severity
        );

        Ok(status)
    }

    /// Runs all health checks by gathering data from the provided services.
    ///
    /// This is the main entry point for health checks that handles all data gathering.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_full_checks(
        &self,
        base_currency: &str,
        account_service: Arc<dyn AccountServiceTrait>,
        holdings_service: Arc<dyn HoldingsServiceTrait>,
        quote_service: Arc<dyn QuoteServiceTrait>,
        asset_service: Arc<dyn AssetServiceTrait>,
        taxonomy_service: Arc<dyn TaxonomyServiceTrait>,
        valuation_service: Arc<dyn ValuationServiceTrait>,
        activity_service: Arc<dyn ActivityServiceTrait>,
        lot_repository: Arc<dyn LotRepositoryTrait>,
        configured_timezone: Option<&str>,
        client_timezone: Option<&str>,
    ) -> Result<HealthStatus> {
        // Gather holdings data from all accounts
        let accounts = account_service.get_active_accounts()?;

        // Use a map to consolidate holdings by asset_id (same asset in multiple accounts)
        let mut holdings_map: HashMap<String, AssetHoldingInfo> = HashMap::new();
        let mut latest_quote_times: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
        let mut total_portfolio_value = 0.0;
        // Track FX pairs needed: (from_currency, to_currency) → affected market value
        let mut fx_pair_mv: HashMap<(String, String), f64> = HashMap::new();

        for account in &accounts {
            let holdings = holdings_service
                .get_holdings(&account.id, base_currency)
                .await?;

            for holding in holdings {
                // Collect FX pair info before filtering to instrument-only
                if holding.local_currency != holding.base_currency {
                    let mv = holding
                        .market_value
                        .base
                        .to_string()
                        .parse::<f64>()
                        .unwrap_or(0.0)
                        .abs();
                    *fx_pair_mv
                        .entry((
                            holding.local_currency.clone(),
                            holding.base_currency.clone(),
                        ))
                        .or_default() += mv;
                }

                if let Some(ref instrument) = holding.instrument {
                    let market_value_f64 = holding
                        .market_value
                        .base
                        .to_string()
                        .parse::<f64>()
                        .unwrap_or(0.0);
                    total_portfolio_value += market_value_f64;

                    // Determine if uses market pricing
                    let uses_market_pricing = instrument.pricing_mode.to_uppercase() == "MARKET";

                    // Consolidate by asset_id - if same asset appears in multiple accounts,
                    // combine market values
                    holdings_map
                        .entry(instrument.id.clone())
                        .and_modify(|existing| {
                            existing.market_value += market_value_f64;
                        })
                        .or_insert(AssetHoldingInfo {
                            asset_id: instrument.id.clone(),
                            symbol: instrument.symbol.clone(),
                            name: instrument.name.clone(),
                            exchange_mic: instrument.exchange_mic.clone(),
                            market_value: market_value_f64,
                            uses_market_pricing,
                        });
                }
            }
        }

        let all_holdings: Vec<AssetHoldingInfo> = holdings_map.into_values().collect();

        // Get latest quote timestamps for held assets
        let asset_ids: Vec<String> = all_holdings.iter().map(|h| h.asset_id.clone()).collect();
        if !asset_ids.is_empty() {
            if let Ok(quotes) = quote_service.get_latest_quotes(&asset_ids) {
                for (asset_id, quote) in quotes {
                    latest_quote_times.insert(asset_id, quote.timestamp);
                }
            }
        }

        // Gather legacy migration status
        let legacy_migration_info = super::gather_legacy_migration_status(
            asset_service.as_ref(),
            taxonomy_service.as_ref(),
        );

        // Gather quote sync errors
        let holding_mv_map: HashMap<String, f64> = all_holdings
            .iter()
            .map(|h| (h.asset_id.clone(), h.market_value))
            .collect();
        let quote_sync_errors = super::gather_quote_sync_errors(
            quote_service.as_ref(),
            asset_service.as_ref(),
            &holding_mv_map,
            &latest_quote_times,
        );

        // Gather FX pairs from holdings where local_currency != base_currency
        let fx_pairs: Vec<FxPairInfo> = if fx_pair_mv.is_empty() {
            Vec::new()
        } else {
            // Build instrument_key → asset_id map for FX assets only
            let fx_asset_map: HashMap<String, String> = asset_service
                .get_assets()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|a| {
                    a.instrument_key
                        .filter(|k| k.starts_with("FX:"))
                        .map(|k| (k, a.id))
                })
                .collect();

            fx_pair_mv
                .iter()
                .map(|((from_ccy, to_ccy), affected_mv)| {
                    // Check both directions since FX asset could be stored either way
                    let key_direct = format!("FX:{}/{}", from_ccy, to_ccy);
                    let key_inverse = format!("FX:{}/{}", to_ccy, from_ccy);
                    let latest_quote_time = fx_asset_map
                        .get(&key_direct)
                        .or_else(|| fx_asset_map.get(&key_inverse))
                        .and_then(|asset_id| {
                            quote_service
                                .get_latest_quotes(std::slice::from_ref(asset_id))
                                .ok()
                                .and_then(|q| q.into_values().next().map(|quote| quote.timestamp))
                        });

                    FxPairInfo {
                        pair_id: format!("{}:{}", from_ccy, to_ccy),
                        from_currency: from_ccy.clone(),
                        to_currency: to_ccy.clone(),
                        affected_mv: *affected_mv,
                        latest_quote_time,
                    }
                })
                .collect()
        };
        let unclassified_assets: Vec<UnclassifiedAssetInfo> = Vec::new();

        // Detect accounts with negative portfolio balance in their history.
        // Exclude cash and credit-card accounts; card debt is an expected liability.
        let account_ids: Vec<String> = accounts
            .iter()
            .filter(|a| {
                a.account_type != account_types::CASH && !is_liability_account_type(&a.account_type)
            })
            .map(|a| a.id.clone())
            .collect();
        let account_name_map: std::collections::HashMap<String, String> = accounts
            .iter()
            .map(|a| (a.id.clone(), a.name.clone()))
            .collect();
        let negative_balance_accounts = valuation_service
            .get_accounts_with_negative_balance(&account_ids)
            .unwrap_or_else(|e| {
                warn!("Failed to check for negative account balances: {}", e);
                Vec::new()
            });
        let mut consistency_issues: Vec<ConsistencyIssueInfo> = negative_balance_accounts
            .into_iter()
            .map(|info| {
                let name = account_name_map
                    .get(&info.account_id)
                    .cloned()
                    .unwrap_or_else(|| info.account_id.clone());
                ConsistencyIssueInfo {
                    issue_type: super::checks::ConsistencyIssueType::NegativeAccountBalance,
                    record_id: info.account_id.clone(),
                    description: name,
                    account_id: Some(info.account_id),
                    asset_id: None,
                    first_negative_date: Some(info.first_negative_date),
                    cash_balance: Some(info.cash_balance),
                    total_value_at_date: Some(info.total_value),
                    account_currency: Some(info.account_currency),
                    activity_date: None,
                    asset_symbol: None,
                    asset_name: None,
                    quantity: None,
                    proceeds: None,
                }
            })
            .collect();

        // Check CASH accounts separately — negative balance may be a normal overdraft (INFO only)
        let cash_account_ids: Vec<String> = accounts
            .iter()
            .filter(|a| a.account_type == account_types::CASH)
            .map(|a| a.id.clone())
            .collect();
        if !cash_account_ids.is_empty() {
            let negative_cash_accounts = valuation_service
                .get_accounts_with_negative_balance(&cash_account_ids)
                .unwrap_or_else(|e| {
                    warn!("Failed to check for negative cash balances: {}", e);
                    Vec::new()
                });
            for info in negative_cash_accounts {
                let name = account_name_map
                    .get(&info.account_id)
                    .cloned()
                    .unwrap_or_else(|| info.account_id.clone());
                consistency_issues.push(ConsistencyIssueInfo {
                    issue_type: super::checks::ConsistencyIssueType::NegativeCashBalance,
                    record_id: info.account_id.clone(),
                    description: name,
                    account_id: Some(info.account_id),
                    asset_id: None,
                    first_negative_date: Some(info.first_negative_date),
                    cash_balance: Some(info.cash_balance),
                    total_value_at_date: Some(info.total_value),
                    account_currency: Some(info.account_currency),
                    activity_date: None,
                    asset_symbol: None,
                    asset_name: None,
                    quantity: None,
                    proceeds: None,
                });
            }
        }

        // Gather accounts without tracking mode set
        let unconfigured_accounts: Vec<UnconfiguredAccountInfo> = accounts
            .iter()
            .filter(|acc| acc.tracking_mode == crate::accounts::TrackingMode::NotSet)
            .map(|acc| UnconfiguredAccountInfo {
                account_id: acc.id.clone(),
                account_name: acc.name.clone(),
            })
            .collect();

        // Detect invalid, incomplete, or unreviewed transfer flows across all
        // activities so the Health Center can surface them.
        let effective_timezone = effective_timezone(configured_timezone, client_timezone);
        let invalid_transfer_groups = gather_invalid_transfer_groups(
            activity_service.as_ref(),
            &account_name_map,
            effective_timezone,
        );
        let missing_lot_disposal_sells = gather_missing_lot_disposal_sells(
            activity_service.as_ref(),
            lot_repository.as_ref(),
            asset_service.as_ref(),
            &accounts,
            effective_timezone,
        )
        .await;
        consistency_issues.extend(missing_lot_disposal_sells);

        // Run checks with gathered data
        self.run_checks_with_data(
            base_currency,
            total_portfolio_value,
            &all_holdings,
            &latest_quote_times,
            &quote_sync_errors,
            &fx_pairs,
            &unclassified_assets,
            &consistency_issues,
            &legacy_migration_info,
            &unconfigured_accounts,
            configured_timezone,
            client_timezone,
            &invalid_transfer_groups,
        )
        .await
    }

    /// Filters out issues that have been dismissed (unless their data has changed).
    async fn filter_dismissed_issues(&self, issues: Vec<HealthIssue>) -> Result<Vec<HealthIssue>> {
        let dismissals = self.dismissal_store.get_dismissals().await?;

        let dismissed_map: std::collections::HashMap<String, &IssueDismissal> =
            dismissals.iter().map(|d| (d.issue_id.clone(), d)).collect();

        let mut filtered = Vec::new();

        for issue in issues {
            if let Some(dismissal) = dismissed_map.get(&issue.id) {
                // Check if data has changed since dismissal
                if dismissal.data_hash != issue.data_hash {
                    // Data changed, restore the issue
                    debug!("Restoring dismissed issue {} due to data change", issue.id);
                    if let Err(e) = self.dismissal_store.remove_dismissal(&issue.id).await {
                        warn!("Failed to remove stale dismissal: {}", e);
                    }
                    filtered.push(issue);
                }
                // Otherwise, skip the dismissed issue
            } else {
                filtered.push(issue);
            }
        }

        Ok(filtered)
    }
}

fn effective_timezone<'a>(
    configured_timezone: Option<&'a str>,
    client_timezone: Option<&'a str>,
) -> Option<&'a str> {
    configured_timezone
        .filter(|tz| !tz.trim().is_empty())
        .or_else(|| client_timezone.filter(|tz| !tz.trim().is_empty()))
}

/// Loads all activities and resolves transfer groups, returning the ones that
/// don't form a valid pair, plus posted ungrouped transfers that are not
/// explicitly marked as external.
fn gather_invalid_transfer_groups(
    activity_service: &dyn ActivityServiceTrait,
    account_names: &HashMap<String, String>,
    timezone: Option<&str>,
) -> Vec<InvalidTransferGroupInfo> {
    let activities = match activity_service.get_activities() {
        Ok(activities) => activities,
        Err(e) => {
            warn!(
                "Failed to load activities for transfer integrity check: {}",
                e
            );
            return Vec::new();
        }
    };

    invalid_transfer_groups_from_activities(&activities, account_names, timezone)
}

fn invalid_transfer_groups_from_activities(
    activities: &[Activity],
    account_names: &HashMap<String, String>,
    timezone: Option<&str>,
) -> Vec<InvalidTransferGroupInfo> {
    let tz = parse_user_timezone_or_default(timezone.unwrap_or_default());
    let resolution = TransferPairResolution::from_activities(activities);
    let by_id: HashMap<&str, &Activity> = activities.iter().map(|a| (a.id.as_str(), a)).collect();

    let mut groups: Vec<InvalidTransferGroupInfo> = resolution
        .invalid_groups()
        .iter()
        .filter_map(|group| {
            let legs: Vec<_> = group
                .activity_ids
                .iter()
                .filter_map(|id| by_id.get(id.as_str()).copied())
                .filter(|act| act.is_posted() && !is_external_transfer(act))
                .map(|act| transfer_leg_detail(act, account_names, tz))
                .collect();
            (!legs.is_empty()).then(|| InvalidTransferGroupInfo {
                group_id: group.group_id.clone(),
                legs,
            })
        })
        .collect();

    for activity in activities {
        if activity.is_posted()
            && resolution.is_ungrouped_transfer(&activity.id)
            && !is_external_transfer(activity)
        {
            groups.push(InvalidTransferGroupInfo {
                group_id: format!("ungrouped:{}", activity.id),
                legs: vec![transfer_leg_detail(activity, account_names, tz)],
            });
        }
    }

    groups
}

async fn gather_missing_lot_disposal_sells(
    activity_service: &dyn ActivityServiceTrait,
    lot_repository: &dyn LotRepositoryTrait,
    asset_service: &dyn AssetServiceTrait,
    accounts: &[Account],
    timezone: Option<&str>,
) -> Vec<ConsistencyIssueInfo> {
    let eligible_accounts: HashMap<String, &Account> = accounts
        .iter()
        .filter(|account| {
            account.is_active
                && !account.is_archived
                && account.tracking_mode == TrackingMode::Transactions
                && matches!(
                    account.account_type.as_str(),
                    account_types::SECURITIES | account_types::CRYPTOCURRENCY
                )
        })
        .map(|account| (account.id.clone(), account))
        .collect();
    if eligible_accounts.is_empty() {
        return Vec::new();
    }

    let activities = match activity_service.get_activities() {
        Ok(activities) => activities,
        Err(e) => {
            warn!(
                "Failed to load activities for missing lot disposal health check: {}",
                e
            );
            return Vec::new();
        }
    };

    let sell_activities: Vec<&Activity> = activities
        .iter()
        .filter(|activity| {
            activity.is_posted()
                && activity.asset_id.is_some()
                && eligible_accounts.contains_key(&activity.account_id)
                && activity.effective_type().eq_ignore_ascii_case("SELL")
        })
        .collect();
    if sell_activities.is_empty() {
        return Vec::new();
    }

    let sell_account_ids: std::collections::HashSet<String> = sell_activities
        .iter()
        .map(|activity| activity.account_id.clone())
        .collect();
    let mut disposal_activity_ids_by_account: HashMap<String, std::collections::HashSet<String>> =
        HashMap::new();
    for account_id in sell_account_ids {
        match lot_repository
            .get_lot_disposals_for_account(&account_id)
            .await
        {
            Ok(disposals) => {
                disposal_activity_ids_by_account.insert(
                    account_id,
                    disposals
                        .into_iter()
                        .map(|d| d.disposal_activity_id)
                        .collect(),
                );
            }
            Err(e) => {
                warn!(
                    "Failed to load lot disposals for account {} during health check: {}",
                    account_id, e
                );
            }
        }
    }

    let asset_ids: Vec<String> = sell_activities
        .iter()
        .filter_map(|activity| activity.asset_id.clone())
        .collect();
    let assets_by_id: HashMap<String, crate::assets::Asset> = asset_service
        .get_assets_by_asset_ids(&asset_ids)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "Failed to load assets for missing lot disposal health check: {}",
                e
            );
            Vec::new()
        })
        .into_iter()
        .map(|asset| (asset.id.clone(), asset))
        .collect();

    missing_lot_disposal_sells_from_data(
        accounts,
        &activities,
        &disposal_activity_ids_by_account,
        &assets_by_id,
        timezone,
    )
}

fn missing_lot_disposal_sells_from_data(
    accounts: &[Account],
    activities: &[Activity],
    disposal_activity_ids_by_account: &HashMap<String, std::collections::HashSet<String>>,
    assets_by_id: &HashMap<String, Asset>,
    timezone: Option<&str>,
) -> Vec<ConsistencyIssueInfo> {
    let eligible_accounts: HashMap<String, &Account> = accounts
        .iter()
        .filter(|account| {
            account.is_active
                && !account.is_archived
                && account.tracking_mode == TrackingMode::Transactions
                && matches!(
                    account.account_type.as_str(),
                    account_types::SECURITIES | account_types::CRYPTOCURRENCY
                )
        })
        .map(|account| (account.id.clone(), account))
        .collect();

    let tz = parse_user_timezone_or_default(timezone.unwrap_or_default());
    activities
        .iter()
        .filter(|activity| {
            activity.is_posted()
                && activity.asset_id.is_some()
                && eligible_accounts.contains_key(&activity.account_id)
                && activity.effective_type().eq_ignore_ascii_case("SELL")
        })
        .filter(|activity| {
            disposal_activity_ids_by_account
                .get(&activity.account_id)
                .is_some_and(|disposal_activity_ids| !disposal_activity_ids.contains(&activity.id))
        })
        .filter_map(|activity| {
            let account = eligible_accounts.get(&activity.account_id)?;
            let asset_id = activity.asset_id.as_ref()?;
            let asset = assets_by_id.get(asset_id);
            let asset_symbol = asset
                .and_then(|a| {
                    a.display_code
                        .clone()
                        .or_else(|| a.instrument_symbol.clone())
                })
                .or_else(|| Some(asset_id.clone()));
            let asset_name = asset.and_then(|a| a.name.clone());
            let proceeds = health_sell_net_proceeds(activity, asset);

            Some(ConsistencyIssueInfo {
                issue_type: super::checks::ConsistencyIssueType::MissingLotDisposalForSell,
                record_id: activity.id.clone(),
                description: account.name.clone(),
                account_id: Some(activity.account_id.clone()),
                asset_id: Some(asset_id.clone()),
                first_negative_date: None,
                cash_balance: None,
                total_value_at_date: None,
                account_currency: Some(activity.currency.clone()),
                activity_date: Some(activity_date_in_tz(activity.activity_date, tz)),
                asset_symbol,
                asset_name,
                quantity: activity.quantity.map(|q| q.abs()),
                proceeds: Some(proceeds),
            })
        })
        .collect()
}

fn health_sell_net_proceeds(activity: &Activity, asset: Option<&Asset>) -> Decimal {
    let has_qty = activity.quantity.is_some_and(|qty| !qty.is_zero());
    let has_unit_price = activity.unit_price.is_some_and(|price| !price.is_zero());
    let use_activity_amount =
        asset.is_some_and(|asset| asset.is_bond()) || !has_qty || !has_unit_price;

    let gross = if use_activity_amount {
        activity.amt()
    } else {
        let contract_multiplier = asset
            .map(|asset| asset.contract_multiplier())
            .unwrap_or(Decimal::ONE);
        activity.qty() * activity.price() * contract_multiplier
    };

    gross - activity.fee_amt()
}

fn transfer_leg_detail(
    activity: &Activity,
    account_names: &HashMap<String, String>,
    timezone: chrono_tz::Tz,
) -> TransferLegDetail {
    TransferLegDetail {
        account_id: activity.account_id.clone(),
        account_name: account_names
            .get(&activity.account_id)
            .cloned()
            .unwrap_or_else(|| "Account".to_string()),
        activity_type: activity.effective_type().to_string(),
        amount: activity.amount,
        currency: activity.currency.clone(),
        date: activity_date_in_tz(activity.activity_date, timezone),
    }
}

#[async_trait]
impl HealthServiceTrait for HealthService {
    async fn run_checks(&self, _base_currency: &str) -> Result<HealthStatus> {
        // This method requires external data gathering
        // In practice, the caller should use run_checks_with_data instead
        // Return cached status or empty status
        if let Some(cached) = self.cached_status.read().await.as_ref() {
            return Ok(cached.status.clone());
        }
        Ok(HealthStatus::healthy())
    }

    async fn run_checks_with_data(
        &self,
        base_currency: &str,
        total_portfolio_value: f64,
        holdings: &[AssetHoldingInfo],
        latest_quote_times: &std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
        quote_sync_errors: &[QuoteSyncErrorInfo],
        fx_pairs: &[FxPairInfo],
        unclassified_assets: &[UnclassifiedAssetInfo],
        consistency_issues: &[ConsistencyIssueInfo],
        legacy_migration_info: &Option<LegacyMigrationInfo>,
        unconfigured_accounts: &[UnconfiguredAccountInfo],
        configured_timezone: Option<&str>,
        client_timezone: Option<&str>,
        invalid_transfer_groups: &[InvalidTransferGroupInfo],
    ) -> Result<HealthStatus> {
        // Call the inherent method
        HealthService::run_checks_with_data(
            self,
            base_currency,
            total_portfolio_value,
            holdings,
            latest_quote_times,
            quote_sync_errors,
            fx_pairs,
            unclassified_assets,
            consistency_issues,
            legacy_migration_info,
            unconfigured_accounts,
            configured_timezone,
            client_timezone,
            invalid_transfer_groups,
        )
        .await
    }

    async fn get_cached_status(&self) -> Option<HealthStatus> {
        let cache = self.cached_status.read().await;
        cache.as_ref().map(|c| {
            let mut status = c.status.clone();
            // Mark as stale if older than 5 minutes
            if Utc::now() - c.cached_at > Duration::minutes(5) {
                status.mark_stale();
            }
            status
        })
    }

    async fn dismiss_issue(&self, issue_id: &str, data_hash: &str) -> Result<()> {
        let dismissal = IssueDismissal::new(issue_id, data_hash);
        self.dismissal_store.save_dismissal(&dismissal).await?;
        self.clear_cache().await;
        info!("Dismissed health issue: {}", issue_id);
        Ok(())
    }

    async fn restore_issue(&self, issue_id: &str) -> Result<()> {
        self.dismissal_store.remove_dismissal(issue_id).await?;
        self.clear_cache().await;
        info!("Restored health issue: {}", issue_id);
        Ok(())
    }

    async fn get_dismissed_ids(&self) -> Result<Vec<String>> {
        let dismissals = self.dismissal_store.get_dismissals().await?;
        Ok(dismissals.into_iter().map(|d| d.issue_id).collect())
    }

    async fn execute_fix(&self, action: &FixAction) -> Result<()> {
        info!("Executing fix action: {} ({})", action.label, action.id);

        let result = match action.id.as_str() {
            "sync_prices" | "retry_sync" => {
                // Parse asset IDs from payload
                let _asset_ids: Vec<String> = serde_json::from_value(action.payload.clone())
                    .map_err(|e| HealthError::invalid_payload(&action.id, e.to_string()))?;

                // TODO: Call quote sync service to refresh prices
                // This will be wired up when integrating with the service context
                warn!("{} fix action not yet implemented", action.id);
                Ok(())
            }
            "fetch_fx" => {
                // Parse currency pairs from payload
                let _pairs: Vec<String> = serde_json::from_value(action.payload.clone())
                    .map_err(|e| HealthError::invalid_payload(&action.id, e.to_string()))?;

                // TODO: Call FX service to refresh rates
                warn!("fetch_fx fix action not yet implemented");
                Ok(())
            }
            "migrate_classifications" => {
                // Parse asset IDs from payload
                let _asset_ids: Vec<String> = serde_json::from_value(action.payload.clone())
                    .map_err(|e| HealthError::invalid_payload(&action.id, e.to_string()))?;

                // TODO: Call taxonomy service to migrate legacy data
                warn!("migrate_classifications fix action not yet implemented");
                Ok(())
            }
            _ => Err(HealthError::UnknownFixAction(action.id.clone()).into()),
        };

        // Clear cache after fix so next check shows updated results
        self.clear_cache().await;
        result
    }

    async fn clear_cache(&self) {
        *self.cached_status.write().await = None;
        debug!("Health status cache cleared");
    }

    async fn get_config(&self) -> HealthConfig {
        self.config.read().await.clone()
    }

    async fn update_config(&self, config: HealthConfig) -> Result<()> {
        // Validate config
        if config.price_stale_warning_hours == 0 {
            return Err(HealthError::InvalidConfig(
                "price_stale_warning_hours must be > 0".to_string(),
            )
            .into());
        }
        if config.price_stale_warning_hours >= config.price_stale_critical_hours {
            return Err(HealthError::InvalidConfig(
                "price_stale_warning_hours must be < price_stale_critical_hours".to_string(),
            )
            .into());
        }
        if config.fx_stale_warning_hours == 0 {
            return Err(HealthError::InvalidConfig(
                "fx_stale_warning_hours must be > 0".to_string(),
            )
            .into());
        }
        if config.fx_stale_warning_hours >= config.fx_stale_critical_hours {
            return Err(HealthError::InvalidConfig(
                "fx_stale_warning_hours must be < fx_stale_critical_hours".to_string(),
            )
            .into());
        }

        *self.config.write().await = config;
        info!("Health configuration updated");
        Ok(())
    }

    async fn run_full_checks(
        &self,
        base_currency: &str,
        account_service: Arc<dyn AccountServiceTrait>,
        holdings_service: Arc<dyn HoldingsServiceTrait>,
        quote_service: Arc<dyn QuoteServiceTrait>,
        asset_service: Arc<dyn AssetServiceTrait>,
        taxonomy_service: Arc<dyn TaxonomyServiceTrait>,
        valuation_service: Arc<dyn ValuationServiceTrait>,
        activity_service: Arc<dyn ActivityServiceTrait>,
        lot_repository: Arc<dyn LotRepositoryTrait>,
        configured_timezone: Option<&str>,
        client_timezone: Option<&str>,
    ) -> Result<HealthStatus> {
        HealthService::run_full_checks(
            self,
            base_currency,
            account_service,
            holdings_service,
            quote_service,
            asset_service,
            taxonomy_service,
            valuation_service,
            activity_service,
            lot_repository,
            configured_timezone,
            client_timezone,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activities::{
        ActivityStatus, ACTIVITY_TYPE_TRANSFER_IN, ACTIVITY_TYPE_TRANSFER_OUT,
    };
    use crate::assets::{Asset, AssetKind, InstrumentType, QuoteMode};
    use chrono::TimeZone;
    use rust_decimal_macros::dec;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    /// Mock dismissal store for testing.
    struct MockDismissalStore {
        dismissals: RwLock<Vec<IssueDismissal>>,
    }

    impl MockDismissalStore {
        fn new() -> Self {
            Self {
                dismissals: RwLock::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl HealthDismissalStore for MockDismissalStore {
        async fn save_dismissal(&self, dismissal: &IssueDismissal) -> Result<()> {
            let mut dismissals = self.dismissals.write().await;
            dismissals.retain(|d| d.issue_id != dismissal.issue_id);
            dismissals.push(dismissal.clone());
            Ok(())
        }

        async fn remove_dismissal(&self, issue_id: &str) -> Result<()> {
            let mut dismissals = self.dismissals.write().await;
            dismissals.retain(|d| d.issue_id != issue_id);
            Ok(())
        }

        async fn get_dismissals(&self) -> Result<Vec<IssueDismissal>> {
            Ok(self.dismissals.read().await.clone())
        }

        async fn get_dismissal(&self, issue_id: &str) -> Result<Option<IssueDismissal>> {
            let dismissals = self.dismissals.read().await;
            Ok(dismissals.iter().find(|d| d.issue_id == issue_id).cloned())
        }

        async fn clear_all(&self) -> Result<()> {
            self.dismissals.write().await.clear();
            Ok(())
        }
    }

    fn transfer_activity(
        id: &str,
        account_id: &str,
        activity_type: &str,
        source_group_id: Option<&str>,
        is_external: bool,
        status: ActivityStatus,
    ) -> Activity {
        let now = Utc.with_ymd_and_hms(2026, 6, 8, 12, 0, 0).unwrap();
        Activity {
            id: id.to_string(),
            account_id: account_id.to_string(),
            asset_id: None,
            activity_type: activity_type.to_string(),
            activity_type_override: None,
            source_type: None,
            subtype: None,
            status,
            activity_date: now,
            settlement_date: None,
            quantity: None,
            unit_price: None,
            amount: Some(dec!(100)),
            fee: None,
            currency: "CAD".to_string(),
            fx_rate: None,
            notes: None,
            metadata: is_external.then(|| json!({ "flow": { "is_external": true } })),
            source_system: Some("CSV".to_string()),
            source_record_id: None,
            source_group_id: source_group_id.map(str::to_string),
            idempotency_key: None,
            import_run_id: None,
            is_user_modified: false,
            needs_review: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn health_account(id: &str, account_type: &str, tracking_mode: TrackingMode) -> Account {
        let now = Utc.with_ymd_and_hms(2026, 6, 8, 12, 0, 0).unwrap();
        Account {
            id: id.to_string(),
            name: "Business Investment".to_string(),
            account_type: account_type.to_string(),
            group: None,
            currency: "USD".to_string(),
            is_default: false,
            is_active: true,
            created_at: now.naive_utc(),
            updated_at: now.naive_utc(),
            platform_id: None,
            account_number: None,
            meta: None,
            provider: None,
            provider_account_id: None,
            is_archived: false,
            tracking_mode,
            asset_class_override: None,
        }
    }

    fn sell_activity(id: &str, account_id: &str, asset_id: &str) -> Activity {
        let now = Utc.with_ymd_and_hms(2026, 6, 2, 2, 30, 0).unwrap();
        Activity {
            id: id.to_string(),
            account_id: account_id.to_string(),
            asset_id: Some(asset_id.to_string()),
            activity_type: "SELL".to_string(),
            activity_type_override: None,
            source_type: None,
            subtype: None,
            status: ActivityStatus::Posted,
            activity_date: now,
            settlement_date: None,
            quantity: Some(dec!(1)),
            unit_price: Some(dec!(291.10598755)),
            amount: None,
            fee: None,
            currency: "USD".to_string(),
            fx_rate: None,
            notes: None,
            metadata: None,
            source_system: Some("CSV".to_string()),
            source_record_id: None,
            source_group_id: None,
            idempotency_key: None,
            import_run_id: None,
            is_user_modified: false,
            needs_review: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn health_asset(id: &str) -> Asset {
        let now = Utc.with_ymd_and_hms(2026, 6, 8, 12, 0, 0).unwrap();
        Asset {
            id: id.to_string(),
            kind: AssetKind::Investment,
            name: Some("Apple Inc.".to_string()),
            display_code: Some("AAPL".to_string()),
            notes: None,
            metadata: None,
            is_active: true,
            quote_mode: QuoteMode::Market,
            quote_ccy: "USD".to_string(),
            instrument_type: Some(InstrumentType::Equity),
            instrument_symbol: Some("AAPL".to_string()),
            instrument_exchange_mic: Some("XNAS".to_string()),
            instrument_key: None,
            provider_config: None,
            exchange_name: None,
            created_at: now.naive_utc(),
            updated_at: now.naive_utc(),
        }
    }

    #[test]
    fn ungrouped_non_external_transfer_is_reported_to_health_center() {
        let account_names = HashMap::from([("acc_tfsa".to_string(), "TFSA".to_string())]);
        let activities = vec![transfer_activity(
            "transfer-in-1",
            "acc_tfsa",
            ACTIVITY_TYPE_TRANSFER_IN,
            None,
            false,
            ActivityStatus::Posted,
        )];

        let groups = invalid_transfer_groups_from_activities(&activities, &account_names, None);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_id, "ungrouped:transfer-in-1");
        assert_eq!(groups[0].legs.len(), 1);
        assert_eq!(groups[0].legs[0].account_name, "TFSA");
        assert_eq!(groups[0].legs[0].activity_type, ACTIVITY_TYPE_TRANSFER_IN);
    }

    #[test]
    fn invalid_transfer_group_dates_use_configured_timezone() {
        let account_names = HashMap::from([("acc_tfsa".to_string(), "TFSA".to_string())]);
        let mut activity = transfer_activity(
            "transfer-in-1",
            "acc_tfsa",
            ACTIVITY_TYPE_TRANSFER_IN,
            None,
            false,
            ActivityStatus::Posted,
        );
        activity.activity_date = Utc.with_ymd_and_hms(2024, 1, 4, 2, 13, 0).unwrap();
        let activities = vec![activity];

        let groups = invalid_transfer_groups_from_activities(
            &activities,
            &account_names,
            Some("America/Toronto"),
        );

        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].legs[0].date,
            chrono::NaiveDate::from_ymd_opt(2024, 1, 3).unwrap()
        );
    }

    #[test]
    fn explicit_external_pending_and_valid_grouped_transfers_are_not_reported() {
        let account_names = HashMap::from([
            ("acc_cash".to_string(), "Cash".to_string()),
            ("acc_tfsa".to_string(), "TFSA".to_string()),
        ]);
        let activities = vec![
            transfer_activity(
                "external-transfer",
                "acc_tfsa",
                ACTIVITY_TYPE_TRANSFER_IN,
                None,
                true,
                ActivityStatus::Posted,
            ),
            transfer_activity(
                "pending-transfer",
                "acc_tfsa",
                ACTIVITY_TYPE_TRANSFER_IN,
                None,
                false,
                ActivityStatus::Pending,
            ),
            transfer_activity(
                "external-orphan-transfer",
                "acc_tfsa",
                ACTIVITY_TYPE_TRANSFER_IN,
                Some("orphan-transfer-group"),
                true,
                ActivityStatus::Posted,
            ),
            transfer_activity(
                "pending-orphan-transfer",
                "acc_tfsa",
                ACTIVITY_TYPE_TRANSFER_IN,
                Some("pending-transfer-group"),
                false,
                ActivityStatus::Pending,
            ),
            transfer_activity(
                "paired-out",
                "acc_cash",
                ACTIVITY_TYPE_TRANSFER_OUT,
                Some("transfer-group-1"),
                false,
                ActivityStatus::Posted,
            ),
            transfer_activity(
                "paired-in",
                "acc_tfsa",
                ACTIVITY_TYPE_TRANSFER_IN,
                Some("transfer-group-1"),
                false,
                ActivityStatus::Posted,
            ),
        ];

        let groups = invalid_transfer_groups_from_activities(&activities, &account_names, None);

        assert!(groups.is_empty());
    }

    #[test]
    fn sell_with_matching_lot_disposal_is_not_reported() {
        let accounts = vec![health_account(
            "business",
            account_types::SECURITIES,
            TrackingMode::Transactions,
        )];
        let activities = vec![sell_activity("sell-aapl", "business", "aapl")];
        let disposals = HashMap::from([(
            "business".to_string(),
            HashSet::from(["sell-aapl".to_string()]),
        )]);
        let assets = HashMap::from([("aapl".to_string(), health_asset("aapl"))]);

        let issues = missing_lot_disposal_sells_from_data(
            &accounts,
            &activities,
            &disposals,
            &assets,
            Some("America/Toronto"),
        );

        assert!(issues.is_empty());
    }

    #[test]
    fn sell_without_lot_disposal_is_reported_with_local_date() {
        let accounts = vec![health_account(
            "business",
            account_types::SECURITIES,
            TrackingMode::Transactions,
        )];
        let activities = vec![sell_activity("sell-aapl", "business", "aapl")];
        let disposals = HashMap::from([("business".to_string(), HashSet::new())]);
        let assets = HashMap::from([("aapl".to_string(), health_asset("aapl"))]);

        let issues = missing_lot_disposal_sells_from_data(
            &accounts,
            &activities,
            &disposals,
            &assets,
            Some("America/Toronto"),
        );

        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].issue_type,
            crate::health::checks::ConsistencyIssueType::MissingLotDisposalForSell
        );
        assert_eq!(issues[0].asset_symbol.as_deref(), Some("AAPL"));
        assert_eq!(
            issues[0].activity_date,
            Some(chrono::NaiveDate::from_ymd_opt(2026, 6, 1).unwrap())
        );
        assert_eq!(issues[0].proceeds, Some(dec!(291.10598755)));
    }

    #[test]
    fn missing_lot_sell_proceeds_follow_core_trade_amount_rules() {
        let mut option_sell = sell_activity("sell-option", "business", "option");
        option_sell.quantity = Some(dec!(2));
        option_sell.unit_price = Some(dec!(1.5));
        option_sell.amount = Some(dec!(999));
        option_sell.fee = Some(dec!(0.25));

        let mut option_asset = health_asset("option");
        option_asset.instrument_type = Some(InstrumentType::Option);

        assert_eq!(
            health_sell_net_proceeds(&option_sell, Some(&option_asset)),
            dec!(299.75)
        );

        let mut bond_sell = option_sell.clone();
        bond_sell.id = "sell-bond".to_string();
        bond_sell.amount = Some(dec!(950));

        let mut bond_asset = health_asset("bond");
        bond_asset.instrument_type = Some(InstrumentType::Bond);

        assert_eq!(
            health_sell_net_proceeds(&bond_sell, Some(&bond_asset)),
            dec!(949.75)
        );
    }

    #[tokio::test]
    async fn test_health_service_empty_portfolio() {
        let store = Arc::new(MockDismissalStore::new());
        let service = HealthService::new(store);

        let status = service
            .run_checks_with_data(
                "USD",
                0.0,
                &[],
                &HashMap::new(),
                &[],
                &[],
                &[],
                &[],
                &None,
                &[],
                Some("UTC"),
                None,
                &[],
            )
            .await
            .unwrap();

        assert_eq!(status.total_count(), 0);
        assert_eq!(status.overall_severity, crate::health::Severity::Info);
    }

    #[tokio::test]
    async fn test_dismiss_and_restore() {
        let store = Arc::new(MockDismissalStore::new());
        let service = HealthService::new(store.clone());

        // Dismiss an issue
        service
            .dismiss_issue("test_issue", "hash123")
            .await
            .unwrap();

        let dismissed = service.get_dismissed_ids().await.unwrap();
        assert_eq!(dismissed.len(), 1);
        assert_eq!(dismissed[0], "test_issue");

        // Restore the issue
        service.restore_issue("test_issue").await.unwrap();

        let dismissed = service.get_dismissed_ids().await.unwrap();
        assert!(dismissed.is_empty());
    }

    #[tokio::test]
    async fn test_config_validation() {
        let store = Arc::new(MockDismissalStore::new());
        let service = HealthService::new(store);

        // Invalid: warning >= critical
        let bad_config = HealthConfig {
            price_stale_warning_hours: 72,
            price_stale_critical_hours: 24, // Should be > warning
            ..Default::default()
        };

        let result = service.update_config(bad_config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_health_check_with_issues() {
        let store = Arc::new(MockDismissalStore::new());
        let service = HealthService::new(store);

        let holdings = vec![AssetHoldingInfo {
            asset_id: "SEC:AAPL:XNAS".to_string(),
            symbol: "AAPL".to_string(),
            name: Some("Apple Inc.".to_string()),
            exchange_mic: None,
            market_value: 10_000.0,
            uses_market_pricing: true,
        }];

        // No quotes = stale
        let quote_times = HashMap::new();

        let status = service
            .run_checks_with_data(
                "USD",
                100_000.0,
                &holdings,
                &quote_times,
                &[],
                &[],
                &[],
                &[],
                &None,
                &[],
                Some("UTC"),
                None,
                &[],
            )
            .await
            .unwrap();

        assert_eq!(status.total_count(), 1);
        assert!(status.overall_severity >= crate::health::Severity::Error);
    }

    #[tokio::test]
    async fn test_dismissed_issues_filtered() {
        let store = Arc::new(MockDismissalStore::new());
        let service = HealthService::new(store);

        // First, run checks to get an issue
        let holdings = vec![AssetHoldingInfo {
            asset_id: "SEC:AAPL:XNAS".to_string(),
            symbol: "AAPL".to_string(),
            name: Some("Apple Inc.".to_string()),
            exchange_mic: None,
            market_value: 10_000.0,
            uses_market_pricing: true,
        }];
        let quote_times = HashMap::new();

        let status = service
            .run_checks_with_data(
                "USD",
                100_000.0,
                &holdings,
                &quote_times,
                &[],
                &[],
                &[],
                &[],
                &None,
                &[],
                Some("UTC"),
                None,
                &[],
            )
            .await
            .unwrap();

        assert_eq!(status.total_count(), 1);
        let issue = &status.issues[0];

        // Dismiss the issue
        service
            .dismiss_issue(&issue.id, &issue.data_hash)
            .await
            .unwrap();

        // Run checks again - issue should be filtered out
        let status = service
            .run_checks_with_data(
                "USD",
                100_000.0,
                &holdings,
                &quote_times,
                &[],
                &[],
                &[],
                &[],
                &None,
                &[],
                Some("UTC"),
                None,
                &[],
            )
            .await
            .unwrap();

        assert_eq!(status.total_count(), 0);
    }
}
