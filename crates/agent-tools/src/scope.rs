//! Agent scopes — the enforced permission model for agent tool access.
//!
//! Scope names reuse the addon permission category vocabulary
//! (`accounts`, `portfolio`, ...) with an action suffix, but share no
//! implementation with the addon system (which is declaration-only).
//! Only scopes that gate shipped tools are defined; add new variants when
//! the tools that need them ship.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A single granted or required permission scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AgentScope {
    AccountsRead,
    PortfolioRead,
    PerformanceRead,
    ActivitiesRead,
    FinancialPlanningRead,
    HealthRead,
    ClassificationRead,
}

impl AgentScope {
    /// All scopes, in stable display order.
    pub const ALL: &'static [AgentScope] = &[
        AgentScope::AccountsRead,
        AgentScope::PortfolioRead,
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
            AgentScope::PortfolioRead => "portfolio:read",
            AgentScope::PerformanceRead => "performance:read",
            AgentScope::ActivitiesRead => "activities:read",
            AgentScope::FinancialPlanningRead => "financial-planning:read",
            AgentScope::HealthRead => "health:read",
            AgentScope::ClassificationRead => "classification:read",
        }
    }

    /// Parse the canonical wire format. Unknown scopes return `None`;
    /// callers decide whether unknown means "ignore" (forward compat for
    /// tokens minted by a newer version) or "reject".
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|scope| scope.as_str() == s)
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
        Self(AgentScope::ALL.iter().copied().collect())
    }

    /// Build from canonical scope strings, silently skipping unknown ones
    /// (forward compatibility with scopes minted by newer versions).
    pub fn from_strs<'a>(scopes: impl IntoIterator<Item = &'a str>) -> Self {
        Self(scopes.into_iter().filter_map(AgentScope::parse).collect())
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
    fn parse_rejects_unknown() {
        assert_eq!(AgentScope::parse("accounts:write"), None);
        assert_eq!(AgentScope::parse(""), None);
    }

    #[test]
    fn from_strs_skips_unknown() {
        let set = AgentScopeSet::from_strs(["accounts:read", "not-a-scope", "health:read"]);
        assert!(set.contains(AgentScope::AccountsRead));
        assert!(set.contains(AgentScope::HealthRead));
        assert!(!set.contains(AgentScope::PortfolioRead));
    }

    #[test]
    fn grants_all_requires_every_scope() {
        let set = AgentScopeSet::from_strs(["accounts:read"]);
        assert!(set.grants_all(&[AgentScope::AccountsRead]));
        assert!(!set.grants_all(&[AgentScope::AccountsRead, AgentScope::PortfolioRead]));
        assert!(set.grants_all(&[]));
    }
}
