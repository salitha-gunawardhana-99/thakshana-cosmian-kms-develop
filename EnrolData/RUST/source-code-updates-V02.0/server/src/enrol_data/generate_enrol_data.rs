use std::fs;

use cosmian_kmip::kmip::ttlv::TTLV;

use super::{
    paths::{
        CA_PATH, CERTIFY_PATH, CREATE_KEY_PAIR_PATH, CREATE_PATH, DEVICE_UID_PATH,
        GEN_RESPONSE_PATH, IMPORT_CA_PATH, KMS_PATH,
    },
    utils::{
        extract_request_info, extract_value_by_uuid_and_field, get_or_create_uuid, handle_certify,
        handle_create, handle_create_key_pair, import_ca, update_two_stage_ttlv,
    },
};
use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

pub async fn handle_generate_enroldata(
    kms: &KMS,
    body: &String,
    _ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    // Helper function to update TTLV and handle repeated operations
    async fn process_operation<F>(
        gen_response_path: &str,
        object_tag: &str,
        operation: F,
    ) -> KResult<()>
    where
        F: std::future::Future<Output = KResult<String>>,
    {
        let operation_result = operation.await?;
        let _update = update_two_stage_ttlv(gen_response_path, object_tag, &operation_result).await;
        Ok(())
    }

    // Extract information from the request body
    let serial_number = extract_request_info(body, "SerialNumber").await?;
    let part_number = extract_request_info(body, "PartNumber").await?;

    if serial_number == "" || part_number == "" {
        kms_bail!(KmsError::InvalidRequest(format!(
            "Serial number or part number can't be empty!"
        )));
    }

    let device_uuid = get_or_create_uuid(
        serial_number,
        part_number,
        kms,
        user,
        database_params,
        DEVICE_UID_PATH,
        CREATE_PATH,
    )
    .await?;
    // println!("UUID: {}", &device_uuid);

    let _update = update_two_stage_ttlv(GEN_RESPONSE_PATH, "DeviceUUID", &device_uuid).await;

    let ca_id = import_ca(kms, user, database_params, IMPORT_CA_PATH, CA_PATH).await?;

    let kms_uuid = "kms";

    // Check if KMS certificate exists and valid
    let kms_cert_id: String =
        extract_value_by_uuid_and_field(&KMS_PATH, &kms_uuid, "KMS_CERT_ID").await?;
    if !kms_cert_id.is_empty() {
    } else {
        // KMS Keys operations
        process_operation(
            GEN_RESPONSE_PATH,
            "KMSKeys",
            handle_create_key_pair(
                kms,
                user,
                database_params,
                CREATE_KEY_PAIR_PATH,
                KMS_PATH,
                kms_uuid,
                "KMS_PRIVATE_KEY_ID",
                "KMS_PUBLIC_KEY_ID",
            ),
        )
        .await?;

        let pub_key_id_to_certify =
            extract_value_by_uuid_and_field(&KMS_PATH, kms_uuid, "KMS_PUBLIC_KEY_ID").await?;

        process_operation(
            GEN_RESPONSE_PATH,
            "KMSCertificate",
            handle_certify(
                kms,
                user,
                database_params,
                CERTIFY_PATH,
                KMS_PATH,
                kms_uuid,
                &ca_id,
                &pub_key_id_to_certify,
                "KMS_CERT_ID",
            ),
        )
        .await?;
    }

    // Device Key operations
    process_operation(
        GEN_RESPONSE_PATH,
        "DeviceKey",
        handle_create(
            kms,
            user,
            database_params,
            CREATE_PATH,
            DEVICE_UID_PATH,
            &device_uuid,
            "DEVICE_KEY_ID",
        ),
    )
    .await?;

    // Device Keys operations
    process_operation(
        GEN_RESPONSE_PATH,
        "DeviceKeys",
        handle_create_key_pair(
            kms,
            user,
            database_params,
            CREATE_KEY_PAIR_PATH,
            DEVICE_UID_PATH,
            &device_uuid,
            "DEVICE_PRIVATE_KEY_ID",
            "DEVICE_PUBLIC_KEY_ID",
        ),
    )
    .await?;

    let pub_key_id_to_certify =
        extract_value_by_uuid_and_field(&DEVICE_UID_PATH, &device_uuid, "DEVICE_PUBLIC_KEY_ID")
            .await?;

    process_operation(
        GEN_RESPONSE_PATH,
        "DeviceCertificate",
        handle_certify(
            kms,
            user,
            database_params,
            CERTIFY_PATH,
            DEVICE_UID_PATH,
            &device_uuid,
            &ca_id,
            &pub_key_id_to_certify,
            "DEVICE_CERT_ID",
        ),
    )
    .await?;

    // UUID Key operations
    process_operation(
        GEN_RESPONSE_PATH,
        "DeviceUUIDKeys",
        handle_create_key_pair(
            kms,
            user,
            database_params,
            CREATE_KEY_PAIR_PATH,
            DEVICE_UID_PATH,
            &device_uuid,
            "DEVICE_UUID_PRIVATE_KEY_ID",
            "DEVICE_UUID_PUBLIC_KEY_ID",
        ),
    )
    .await?;

    let pub_key_id_to_certify = extract_value_by_uuid_and_field(
        &DEVICE_UID_PATH,
        &device_uuid,
        "DEVICE_UUID_PUBLIC_KEY_ID",
    )
    .await?;

    process_operation(
        GEN_RESPONSE_PATH,
        "DeviceUUIDCertificate",
        handle_certify(
            kms,
            user,
            database_params,
            CERTIFY_PATH,
            DEVICE_UID_PATH,
            &device_uuid,
            &ca_id,
            &pub_key_id_to_certify,
            "DEVICE_UUID_CERT_ID",
        ),
    )
    .await?;

    // Final output
    let fin_res = fs::read_to_string(GEN_RESPONSE_PATH)?;
    let fin_ttlv = serde_json::from_str::<TTLV>(&fin_res)?;
    Ok(fin_ttlv)
}
