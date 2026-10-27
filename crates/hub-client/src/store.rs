//! Where a device keeps its tokens between processes.

use std::any::Any;

use crate::Session;

/// Persists the tokens of one device so processes sharing it rotate them in turn.
///
/// A refresh token is single-use: a second process presenting a rotated token gets the
/// device revoked. With a store, [`crate::HubClient`] takes [`SessionStore::lock`], adopts a
/// session another process saved meanwhile, rotates and saves before releasing the lock.
pub trait SessionStore: Send + Sync + std::fmt::Debug {
    /// An exclusive lock shared by every process using this store, held until the guard
    /// drops. It may block briefly while another process refreshes.
    fn lock(&self) -> std::io::Result<Box<dyn Any + Send>>;

    /// The session last saved, if any.
    fn load(&self) -> std::io::Result<Option<Session>>;

    fn save(&self, session: &Session) -> std::io::Result<()>;
}
