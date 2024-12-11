use std::fs;

use cosmian_kmip::kmip::ttlv::TTLV;

use super::{
    paths::{DEVICE_UID_PATH, GET_REQ_PATH, GET_RES_PATH, KMS_PATH},
    utils::{
        extract_request_info, extract_value_by_uuid_and_field, get_current_timestamp, handle_get,
        update_two_stage_ttlv, uuid_available,
    },
};
use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    enrol_data::paths::CA_PATH,
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn handle_get_enroldata(
    kms: &KMS,
    body: &String,
    _ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    // Extract UUID
    let device_uuid = extract_request_info(body, "UUID").await?;

    if device_uuid == "" {
        kms_bail!(KmsError::InvalidRequest(format!("UUID can't be empty!")));
    }

    let uuid_excistance = uuid_available(&device_uuid, DEVICE_UID_PATH).await;
    if !uuid_excistance {
        kms_bail!(KmsError::ItemNotFound(format!("UUID can't be found!")));
    }

    let kms_uuid = "kms";
    let ca_uuid = "ca";

    // Helper function for repetitive handle_get operations
    async fn fetch_and_update(
        kms: &KMS,
        user: &str,
        database_params: Option<&ExtraDatabaseParams>,
        get_req_path: &str,
        get_res_path: &str,
        uid_path: &str,
        uuid: &str,
        key: &str,
        tag: &str,
        obj_type: &str,
    ) -> KResult<()> {
        // Directly unwrap the key value from the JSON object
        let id = extract_value_by_uuid_and_field(&uid_path, uuid, key).await?;

        // Fetch data using handle_get and update the TTLV
        let data = handle_get(
            kms,
            user,
            database_params,
            get_req_path,
            "UniqueIdentifier",
            &id,
            obj_type,
        )
        .await?;
        let _update = update_two_stage_ttlv(get_res_path, tag, &data).await;

        Ok(())
    }
    // Fetch and update the required data
    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        DEVICE_UID_PATH,
        &device_uuid,
        "DEVICE_UUID_CERT_ID",
        "DeviceUUIDCertificate",
        "cert",
    )
    .await?;

    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        DEVICE_UID_PATH,
        &device_uuid,
        "DEVICE_PRIVATE_KEY_ID",
        "DeviceCertificatePrivateKey",
        "key",
    )
    .await?;

    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        DEVICE_UID_PATH,
        &device_uuid,
        "DEVICE_CERT_ID",
        "DeviceCertificate",
        "cert",
    )
    .await?;

    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        DEVICE_UID_PATH,
        &device_uuid,
        "DEVICE_KEY_ID",
        "DeviceKey",
        "key",
    )
    .await?;

    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        KMS_PATH,
        &kms_uuid,
        "KMS_CERT_ID",
        "KMSCertificate",
        "cert",
    )
    .await?;

    fetch_and_update(
        kms,
        user,
        database_params,
        GET_REQ_PATH,
        GET_RES_PATH,
        CA_PATH,
        &ca_uuid,
        "CA_CERT_ID",
        "CACertificate",
        "cert",
    )
    .await?;

    // Add timestamp
    let timestamp = get_current_timestamp().await;
    let _unused = update_two_stage_ttlv(GET_RES_PATH, "TimeStamp", &timestamp).await;

    // Final output
    let fin_res = fs::read_to_string(GET_RES_PATH)?;
    let fin_ttlv = serde_json::from_str::<TTLV>(&fin_res)?;
    Ok(fin_ttlv)
}
