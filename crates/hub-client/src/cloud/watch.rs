//! Lossy hints never advance a durable event cursor; reconnect uses bounded replay.
use super::{CloudError, CloudSelector, transport::RelayAccess};
use nocterm_hub_proto::v1;
use std::fmt;

pub struct CloudWatch {
    source: RelayAccess,
    stream: tonic::Streaming<v1::CloudHint>,
    last: u64,
    ended: bool,
}
impl CloudWatch {
    pub(super) async fn start(
        source: RelayAccess,
        selector: &CloudSelector,
        after: u64,
    ) -> Result<Self, CloudError> {
        source.require_selector(selector)?;
        let stream = source
            .service()?
            .watch(v1::CloudWatchRequest {
                selector: Some(selector.wire()?),
                after_cursor: after,
            })
            .await?
            .into_inner();
        source.check_source()?;
        Ok(Self {
            source,
            stream,
            last: after,
            ended: false,
        })
    }
    pub async fn next_hint(&mut self) -> Result<Option<u64>, CloudError> {
        if self.ended {
            return Ok(None);
        }
        self.ended = true;
        self.source.check_source()?;
        let Some(hint) = self.stream.message().await? else {
            return Ok(None);
        };
        self.source.check_source()?;
        if hint.head_cursor < self.last {
            return Err(CloudError::Protocol);
        }
        self.last = hint.head_cursor;
        self.ended = false;
        Ok(Some(self.last))
    }
}
impl fmt::Debug for CloudWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudWatch")
            .field("last_hint", &self.last)
            .finish_non_exhaustive()
    }
}
