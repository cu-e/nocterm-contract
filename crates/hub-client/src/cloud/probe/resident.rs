//! Borrow-only decoded owners: data drops before its original allocation.
use nocterm_hub_model::cloud::head::{SignedHeadQuery, SignedHeadWitness};
use std::{fmt, sync::Arc};
pub struct ResidentHeadQuery {
    value: SignedHeadQuery,
    _residency: Arc<dyn Send + Sync>,
}
impl ResidentHeadQuery {
    pub(super) fn new(value: SignedHeadQuery, residency: Arc<dyn Send + Sync>) -> Self {
        Self {
            value,
            _residency: residency,
        }
    }
    pub fn query(&self) -> &SignedHeadQuery {
        &self.value
    }
}
pub struct ResidentHeadWitness {
    value: SignedHeadWitness,
    _residency: Arc<dyn Send + Sync>,
}
impl ResidentHeadWitness {
    pub(super) fn new(value: SignedHeadWitness, residency: Arc<dyn Send + Sync>) -> Self {
        Self {
            value,
            _residency: residency,
        }
    }
    pub fn witness(&self) -> &SignedHeadWitness {
        &self.value
    }
}
impl fmt::Debug for ResidentHeadQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResidentHeadQuery").finish_non_exhaustive()
    }
}
impl fmt::Debug for ResidentHeadWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResidentHeadWitness")
            .finish_non_exhaustive()
    }
}
