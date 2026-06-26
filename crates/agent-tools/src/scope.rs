//! Agent scopes — the enforced permission model for agent tool access.
//!
//! Scope names reuse the addon permission category vocabulary
//! (`accounts`, `holdings`, ...) with an action suffix, but share no
//! implementation with the addon system (which is declaration-only).
//! Only scopes that gate shipped tools are defined; add new variants when
//! the tools that need them ship.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A single granted or required permission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentScope {
    AccountsRead,
    HoldingsRead,
    PerformanceRead,
    ActivitiesRead,
    FinancialPlanningRead,
    HealthRead,
    ClassificationRead,
    ActivitiesDraft,
    ActivitiesWrite,
    ClassificationSuggest,
}

impl AgentScope {
    /// Every scope, in stable display order (read scopes first, then the
    /// draft/write/suggest scopes).
    pub const ALL: &'static [AgentScope] = &[
        AgentScope::AccountsRead,
        AgentScope::HoldingsRead,
        AgentScope::PerformanceRead,
        AgentScope::ActivitiesRead,
        AgentScope::FinancialPlanningRead,
        AgentScope::HealthRead,
        AgentScope::ClassificationRead,
        AgentScope::ActivitiesDraft,
        AgentScope::ActivitiesWrite,
        AgentScope::ClassificationSuggest,
    ];

    /// The read-only scopes — what the `read-only` preset grants. Kept
    /// separate from [`AgentScope::ALL`] so adding a write scope never
    /// silently widens read-only tokens.
    pub const READ_SCOPES: &'static [AgentScope] = &[
        AgentScope::AccountsRead,
        AgentScope::HoldingsRead,
        AgentScope::PerformanceRead,
        AgentScope::ActivitiesRead,
        AgentScope::FinancialPlanningRead,
        AgentScope::HealthRead,
        AgentScope::ClassificationRead,
    ];

    /// Canonical wire format, e.g. `"accounts:read"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentScope::AccountsRead => "accounts:read",
            AgentScope::HoldingsRead => "holdings:read",
            AgentScope::PerformanceRead => "performance:read",
            AgentScope::ActivitiesRead => "activities:read",
            AgentScope::FinancialPlanningRead => "financial-planning:read",
            AgentScope::HealthRead => "health:read",
            AgentScope::ClassificationRead => "classification:read",
            AgentScope::ActivitiesDraft => "activities:draft",
            AgentScope::ActivitiesWrite => "activities:write",
            AgentScope::ClassificationSuggest => "classification:suggest",
        }
    }

    /// Parse the canonical wire format. Unknown scopes return `None`;
    /// callers decide whether unknown means "ignore" (forward compat for
    /// tokens minted by a newer version) or "reject". This is the strict
    /// parser used for token-creation validation — it does NOT accept the
    /// retired `portfolio:read` alias (see [`AgentScope::parse_lenient`]).
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|scope| scope.as_str() == s)
    }

    /// Like [`AgentScope::parse`] but also maps the retired `portfolio:read`
    /// scope to [`AgentScope::HoldingsRead`]. Used on the auth path so tokens
    /// minted before the rename keep their holdings/value access.
    pub fn parse_lenient(s: &str) -> Option<Self> {
        match s {
            "portfolio:read" => Some(AgentScope::HoldingsRead),
            other => Self::parse(other),
        }
    }
}

impl std::fmt::Display for AgentScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AgentScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AgentScope::parse(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown agent scope: {s}")))
    }
}

/// A set of granted scopes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentScopeSet(BTreeSet<AgentScope>);

impl AgentScopeSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// The read-only preset: every defined read scope.
    pub fn read_only() -> Self {
        Self(AgentScope::READ_SCOPES.iter().copied().collect())
    }

    /// Read-only preset plus the ability to prepare (but not commit)
    /// activity drafts.
    pub fn read_activity_draft() -> Self {
        let mut set = Self::read_only();
        set.insert(AgentScope::ActivitiesDraft);
        set
    }

    /// Read-only preset plus drafting and committing activities.
    pub fn read_activity_write() -> Self {
        let mut set = Self::read_activity_draft();
        set.insert(AgentScope::ActivitiesWrite);
        set
    }

    /// Read-only + activity writes + classification suggestions.
    pub fn read_activity_write_classification_suggest() -> Self {
        let mut set = Self::read_activity_write();
        set.insert(AgentScope::ClassificationSuggest);
        set
    }

    /// Build from canonical scope strings, silently skipping unknown ones
    /// (forward compatibility with scopes minted by newer versions) and
    /// mapping the retired `portfolio:read` alias to `holdings:read`. Use
    /// this on the auth path.
    pub fn from_strs<'a>(scopes: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            scopes
                .into_iter()
                .filter_map(AgentScope::parse_lenient)
                .collect(),
        )
    }

    pub fn insert(&mut self, scope: AgentScope) {
        self.0.insert(scope);
    }

    pub fn contains(&self, scope: AgentScope) -> bool {
        self.0.contains(&scope)
    }

    /// True when every scope in `required` is granted.
    pub fn grants_all(&self, required: &[AgentScope]) -> bool {
        required.iter().all(|scope| self.0.contains(scope))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = AgentScope> + '_ {
        self.0.iter().copied()
    }

    /// Validate scope dependencies. Returns a human-readable error when a
    /// granted scope is missing a prerequisite: committing activities
    /// (`activities:write`) requires the ability to draft them
    /// (`activities:draft`).
    pub fn dependency_error(&self) -> Option<String> {
        if self.contains(AgentScope::ActivitiesWrite) && !self.contains(AgentScope::ActivitiesDraft)
        {
            return Some(
                "activities:write requires activities:draft (commit needs a draft)".to_string(),
            );
        }
        None
    }
}

impl FromIterator<AgentScope> for AgentScopeSet {
    fn from_iter<I: IntoIterator<Item = AgentScope>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_canonical_strings() {
        for scope in AgentScope::ALL {
            assert_eq!(AgentScope::parse(scope.as_str()), Some(*scope));
        }
    }

    #[test]
    fn parse_rejects_unknown_and_legacy_alias() {
        assert_eq!(AgentScope::parse("accounts:write"), None);
        assert_eq!(AgentScope::parse(""), None);
        // The strict parser (token creation) does not accept the retired alias.
        assert_eq!(AgentScope::parse("portfolio:read"), None);
    }

    #[test]
    fn parse_lenient_maps_legacy_portfolio_read() {
        assert_eq!(
            AgentScope::parse_lenient("portfolio:read"),
            Some(AgentScope::HoldingsRead)
        );
        assert_eq!(
            AgentScope::parse_lenient("holdings:read"),
            Some(AgentScope::HoldingsRead)
        );
    }

    #[test]
    fn from_strs_skips_unknown_and_applies_legacy_alias() {
        let set = AgentScopeSet::from_strs(["accounts:read", "not-a-scope", "portfolio:read"]);
        assert!(set.contains(AgentScope::AccountsRead));
        assert!(set.contains(AgentScope::HoldingsRead));
        assert!(!set.contains(AgentScope::PerformanceRead));
    }

    #[test]
    fn read_only_excludes_write_and_suggest_scopes() {
        let set = AgentScopeSet::read_only();
        assert!(set.contains(AgentScope::HoldingsRead));
        assert!(!set.contains(AgentScope::ActivitiesDraft));
        assert!(!set.contains(AgentScope::ActivitiesWrite));
        assert!(!set.contains(AgentScope::ClassificationSuggest));
    }

    #[test]
    fn presets_layer_correctly() {
        assert!(AgentScopeSet::read_activity_draft().contains(AgentScope::ActivitiesDraft));
        assert!(!AgentScopeSet::read_activity_draft().contains(AgentScope::ActivitiesWrite));

        let write = AgentScopeSet::read_activity_write();
        assert!(write.contains(AgentScope::ActivitiesDraft));
        assert!(write.contains(AgentScope::ActivitiesWrite));
        assert!(!write.contains(AgentScope::ClassificationSuggest));

        let full = AgentScopeSet::read_activity_write_classification_suggest();
        assert!(full.contains(AgentScope::ClassificationSuggest));
    }

    #[test]
    fn grants_all_requires_every_scope() {
        let set = AgentScopeSet::from_strs(["accounts:read"]);
        assert!(set.grants_all(&[AgentScope::AccountsRead]));
        assert!(!set.grants_all(&[AgentScope::AccountsRead, AgentScope::HoldingsRead]));
        assert!(set.grants_all(&[]));
    }

    #[test]
    fn dependency_error_flags_write_without_draft() {
        let mut set = AgentScopeSet::read_only();
        set.insert(AgentScope::ActivitiesWrite);
        assert!(set.dependency_error().is_some());

        set.insert(AgentScope::ActivitiesDraft);
        assert!(set.dependency_error().is_none());
    }
}
