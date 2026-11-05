//! A borrow-only decoded owner: data drops before its original allocation.
use nocterm_hub_model::cloud::head::SignedHeadQuery;
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
impl fmt::Debug for ResidentHeadQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResidentHeadQuery").finish_non_exhaustive()
    }
}
