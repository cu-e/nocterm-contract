//! Actual encoded request bodies retain their caller's working allocation.
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tonic::{
    body::Body,
    codegen::{Bytes, Service, http},
    transport::Channel,
};

#[derive(Clone)]
pub struct ResidentChannel {
    inner: Channel,
    residency: Arc<dyn Send + Sync>,
}
impl ResidentChannel {
    pub(crate) fn new(inner: Channel, residency: Arc<dyn Send + Sync>) -> Self {
        Self { inner, residency }
    }
}
impl Service<http::Request<Body>> for ResidentChannel {
    type Response = <Channel as Service<http::Request<Body>>>::Response;
    type Error = <Channel as Service<http::Request<Body>>>::Error;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let future = self
            .inner
            .call(retain_request(request, self.residency.clone()));
        let residency = self.residency.clone();
        Box::pin(async move {
            let response = future.await?;
            Ok(retain_response(response, residency))
        })
    }
}

fn retain_request(
    request: http::Request<Body>,
    residency: Arc<dyn Send + Sync>,
) -> http::Request<Body> {
    request.map(|inner| {
        Body::new(ResidentBody {
            inner,
            _residency: residency,
        })
    })
}

fn retain_response(
    response: http::Response<Body>,
    residency: Arc<dyn Send + Sync>,
) -> http::Response<Body> {
    response.map(|inner| {
        Body::new(ResidentBody {
            inner,
            _residency: residency,
        })
    })
}

// Inner must precede the allocation: its queued message/framing buffers are
// destroyed before the last proof can release, including Tower cancellation.
struct ResidentBody {
    inner: Body,
    _residency: Arc<dyn Send + Sync>,
}
impl http_body::Body for ResidentBody {
    type Data = Bytes;
    type Error = tonic::Status;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        http_body::Body::poll_frame(Pin::new(&mut self.get_mut().inner), cx)
    }
    fn size_hint(&self) -> http_body::SizeHint {
        http_body::Body::size_hint(&self.inner)
    }
    fn is_end_stream(&self) -> bool {
        http_body::Body::is_end_stream(&self.inner)
    }
}

pub(super) fn working_owner_bytes() -> usize {
    // Request and response bodies may coexist; the service's response future
    // also owns a channel future and one residency reference while pending.
    std::mem::size_of::<ResidentChannel>()
        + 2 * std::mem::size_of::<ResidentBody>()
        + std::mem::size_of::<<Channel as Service<http::Request<Body>>>::Future>()
        + std::mem::size_of::<Arc<dyn Send + Sync>>()
}

#[cfg(test)]
mod tests;

impl std::fmt::Debug for ResidentChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResidentStoreChannel")
            .finish_non_exhaustive()
    }
}
