use std::sync::Arc;

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::{
    kmip_messages::Message,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use tracing::info;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::dispatch, KMS},
    database::KMSServer,
    result::KResult,
};

/// Generate KMIP JSON TTLV and send it to the KMIP server
#[post("/kmip/2_1")]
pub(crate) async fn kmip(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<TTLV>> {
    let span = tracing::span!(tracing::Level::INFO, "kmip_2_1");
    let _enter = span.enter();

    /*Note: convert json string into ttlv object */
    let ttlv = serde_json::from_str::<TTLV>(&body)?;

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(&req_http);

    /*Note: logging statement in Rust that uses the log crate (or a similar logging framework) to log information about a KMIP request. */
    info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip. Request: {:?} {}", ttlv.tag.as_str(), user);

    /*Note: All the operations happens here and receive the response */
    let ttlv = handle_ttlv(&kms, &ttlv, &user, database_params.as_ref()).await?;

    /*Note: Ok(Json(ttlv)) in the context of this code is returning a successful HTTP response, where the body of the response contains the ttlv data serialized into JSON format. */
    Ok(Json(ttlv))
}

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation`s serialized in a single KMIP `Message`

async fn handle_ttlv(
    kms: &KMS,
    ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    if [
        "Message",
        "GenerateEnrolData",
        "ReEnrolData",
        "GetEnrolData",
    ]
    .contains(&ttlv.tag.as_str())
    {
        /*Note: Deserialize */
        let req = from_ttlv::<Message>(ttlv)?;
        /*Note: Process the request */
        let resp = kms.message(req, user, database_params).await?;
        /*Note: Serialize the response */
        Ok(to_ttlv(&resp)?)
    } else {
        /*Note: Rceive the Returning Response */
        let operation = dispatch(kms, ttlv, user, database_params).await?;
        /*Note: Serialize */
        Ok(to_ttlv(&operation)?)
    }
}
