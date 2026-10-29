//! Captured bounded Store acquisition using the sole actual resident transport.
use crate::{ClientError, cloud::CapturedSigner, signer::Credentials};
use nocterm_hub_grpc::store_service_client::StoreServiceClient;
use std::{fmt, sync::Arc};
use tonic::{
    GrpcMethod, Request, Status,
    service::{Interceptor, interceptor::InterceptedService},
    transport::Channel,
};

/// Opaque shared149 request/response-body transport. Its constructor is private
/// to the SDK; this public name makes the generated Store alias usable downstream.
pub use crate::cloud::resident_channel::ResidentChannel as ResidentStoreChannel;
/// Captured Store-only proof. No public constructor or generic signing API.
#[derive(Clone)]
pub struct ResidentStoreSigner(CapturedSigner);
/// Generated Store methods and codec, with no duplicate RPC implementation.
pub type ResidentStoreSigned = InterceptedService<ResidentStoreChannel, ResidentStoreSigner>;
pub type ResidentStoreClient = StoreServiceClient<ResidentStoreSigned>;
const MAX_STORE_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

impl Interceptor for ResidentStoreSigner {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let method = request
            .extensions()
            .get::<GrpcMethod>()
            .ok_or_else(|| Status::permission_denied("unknown Store method"))?;
        if method.service() != "nocterm.hub.v1.StoreService"
            || !matches!(
                method.method(),
                "GetAccountKeyset"
                    | "PutAccountKeyset"
                    | "CreateCollection"
                    | "ListCollections"
                    | "DeleteCollection"
                    | "GetCollectionKey"
                    | "GrantCollectionKey"
                    | "ListCollectionMembers"
                    | "PutObject"
                    | "DeleteObject"
                    | "GetObject"
                    | "ListChanges"
            )
        {
            return Err(Status::permission_denied("guarded Store unary scope"));
        }
        self.0.call_bounded(request)
    }
}
impl fmt::Debug for ResidentStoreSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResidentStoreSigner")
            .finish_non_exhaustive()
    }
}
fn limit(maximum: usize) -> Result<(), ClientError> {
    if maximum == 0 || maximum > MAX_STORE_MESSAGE_BYTES {
        return Err(Status::invalid_argument("bounded Store message limit").into());
    }
    Ok(())
}
/// SDK body/proof/fixed transport working bytes. Caller pre-validates request
/// encoded_len<=maximum before handing it to the generated encoder. Original
/// request, decoded protobuf DTO/container allocations and native crypto/results
/// are separately admitted and retain the same guard. This is not an RSS bound.
pub fn store_work_bytes(maximum: usize) -> Result<usize, ClientError> {
    limit(maximum)?;
    Ok(crate::cloud::acknowledgement_work_bytes()
        + 2 * maximum
        + std::mem::size_of::<ResidentStoreClient>())
}
pub(crate) fn create(
    channel: Channel,
    credentials: Arc<Credentials>,
    residency: Arc<dyn Send + Sync>,
    maximum: usize,
) -> Result<ResidentStoreClient, ClientError> {
    limit(maximum)?;
    let capture = credentials.capture_current_cloud()?;
    let signer = ResidentStoreSigner(CapturedSigner::new(credentials, capture.generation));
    Ok(StoreServiceClient::new(InterceptedService::new(
        ResidentStoreChannel::new(channel, residency),
        signer,
    ))
    .max_decoding_message_size(maximum)
    .max_encoding_message_size(maximum))
}
