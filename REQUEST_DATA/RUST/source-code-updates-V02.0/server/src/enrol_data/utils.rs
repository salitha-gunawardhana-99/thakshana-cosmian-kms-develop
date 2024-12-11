use std::{error::Error, fs};

use chrono::Local;
use cosmian_kmip::kmip::ttlv::{serializer::to_ttlv, TTLV};
use serde::Deserialize;
use serde_json::{json, to_string, Value};

use super::paths::{DESTROY_PATH, REVOKE_PATH};
use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::dispatch, KMS},
    error::KmsError,
    kms_bail,
    result::KResult,
};

/*=================================================================================================== */

#[derive(Deserialize)]
struct RequestAttribute {
    tag: String,
    #[serde(rename = "type")]
    #[allow(unused)]
    attribute_type: String,
    value: String,
}

#[derive(Deserialize)]
struct RequestStructure {
    #[allow(unused)]
    tag: String,
    #[serde(rename = "type")]
    #[allow(unused)]
    structure_type: String,
    value: Vec<RequestAttribute>,
}

pub async fn extract_request_info(json_body: &str, search_tag: &str) -> KResult<String> {
    let parsed_json: RequestStructure = serde_json::from_str(json_body)?;
    let mut tag_value = String::new();

    // Find the attribute with the matching tag
    if let Some(attribute) = parsed_json.value.iter().find(|attr| attr.tag == search_tag) {
        tag_value = attribute.value.clone().to_string();
    }
    Ok(tag_value)
}

/*=================================================================================================== */

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

pub async fn get_or_create_uuid(
    serial_number: String,
    part_number: String,
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    device_path: &str,
    create_path: &str,
) -> KResult<String> {
    // Helper function to read the JSON file
    fn read_json_file(file_path: &str) -> Vec<Value> {
        if let Ok(mut file) = File::open(file_path) {
            let mut content = String::new();
            file.read_to_string(&mut content).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        }
    }

    // Helper function to write the JSON file
    fn write_json_file(file_path: &str, json_data: &[Value]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
            .expect("Unable to open or create JSON file");
        file.write_all(serde_json::to_string_pretty(json_data).unwrap().as_bytes())
            .expect("Unable to write to JSON file");
    }

    let mut json_data = read_json_file(device_path);

    // Check if the SERIAL_NUMBER and PART_NUMBER pair exists
    for entity in &json_data {
        if let (Some(existing_serial), Some(existing_part)) = (
            entity.get("SERIAL_NUMBER").and_then(|v| v.as_str()),
            entity.get("PART_NUMBER").and_then(|v| v.as_str()),
        ) {
            if existing_serial == serial_number && existing_part == part_number {
                return Ok(entity
                    .get("UUID")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string());
            }
        }
    }

    // If not found, add a new entry with the required structure with dynamically generated UUID
    let new_uuid = new_uuid_generation(kms, user, database_params, create_path).await?;
    let new_entity = json!({
        "SERIAL_NUMBER": serial_number,
        "PART_NUMBER": part_number,
        "UUID": &new_uuid,
        "UID": [
            {
                "DEVICE_KEY_ID": "not-created-yet",
                "DEVICE_PRIVATE_KEY_ID": "not-created-yet",
                "DEVICE_PUBLIC_KEY_ID": "not-created-yet",
                "DEVICE_CERT_ID": "not-created-yet",
                "DEVICE_UUID_PRIVATE_KEY_ID": "not-created-yet",
                "DEVICE_UUID_PUBLIC_KEY_ID": "not-created-yet",
                "DEVICE_UUID_CERT_ID": "not-created-yet"
            }
        ]
    });
    json_data.push(new_entity);
    write_json_file(device_path, &json_data);
    Ok(new_uuid.to_string())
}

/*=================================================================================================== */

pub async fn uuid_available(uuid_to_check: &str, id_path: &str) -> bool {
    // Read the JSON file
    let json_content = match fs::read_to_string(id_path) {
        Ok(content) => content,
        Err(_) => {
            eprintln!("Failed to read JSON file.");
            return false;
        }
    };

    // Parse the JSON content
    let parsed_json: Value = match serde_json::from_str(&json_content) {
        Ok(json) => json,
        Err(_) => {
            eprintln!("Failed to parse JSON content.");
            return false;
        }
    };

    // Check if UUID exists in the JSON array
    if let Value::Array(entries) = parsed_json {
        for entry in entries {
            if let Some(uuid) = entry.get("UUID") {
                if uuid == uuid_to_check {
                    return true;
                }
            }
        }
    }

    // UUID not found
    false
}

/*=================================================================================================== */

#[derive(Deserialize)]
struct ImportResponse {
    #[allow(unused)]
    tag: String,
    #[allow(unused)]
    #[serde(rename = "type")]
    data_type: String,
    value: Vec<Attribute>,
}

#[derive(Deserialize)]
struct Attribute {
    #[allow(unused)]
    tag: String,
    #[allow(unused)]
    #[serde(rename = "type")]
    data_type: String,
    value: String,
}

pub async fn extract_unique_identifier(json_body: &str) -> KResult<String> {
    let response: ImportResponse = serde_json::from_str(json_body)?;
    let mut unique_id = String::new();

    // Find the attribute with the tag "UniqueIdentifier"
    if let Some(attribute) = response
        .value
        .iter()
        .find(|attr| attr.tag == "UniqueIdentifier")
    {
        unique_id = attribute.value.clone().to_string();
    }
    Ok(unique_id)
}

/*=================================================================================================== */

pub async fn extract_value_by_uuid_and_field(
    path: &str,
    uuid: &str,
    field_name: &str,
) -> KResult<String> {
    let data_json: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    let mut result_value = String::new();

    // Find the entity with the matching UUID
    if let Some(entity) = data_json
        .as_array()
        .unwrap()
        .iter()
        .find(|entity| entity.get("UUID").and_then(|v| v.as_str()) == Some(uuid))
    {
        // If the entity is found, check the "UID" array
        if let Some(uid_array) = entity.get("UID").and_then(|v| v.as_array()) {
            // Find the specific field in the first object of the UID array
            if let Some(uid_object) = uid_array.get(0) {
                // Get the value of the requested field and store it in result_value
                if let Some(field_value) = uid_object.get(field_name).and_then(|v| v.as_str()) {
                    result_value = field_value.to_string();
                }
            }
        }
    }
    // Return the result as a String
    Ok(result_value)
}

/*=================================================================================================== */

pub async fn update_devices_uid_json(
    uid_path: &str,
    uuid: &str,
    key_id_ref: &str,
    unique_id: &str,
) -> Result<(), Box<dyn Error>> {
    use std::fs;

    use serde_json::Value;

    let json_data = fs::read_to_string(uid_path)?;
    let mut entities: Vec<Value> = serde_json::from_str(&json_data)?;

    // Find the entity with the matching UUID
    if let Some(entity) = entities
        .iter_mut()
        .find(|entity| entity.get("UUID").and_then(|v| v.as_str()) == Some(uuid))
    {
        // Ensure "UID" exists and is an array
        let uid_array = entity
            .get_mut("UID")
            .and_then(|v| v.as_array_mut())
            .ok_or("Failed to retrieve UID array")?;

        // Find the relevant object in the UID array based on key_id_ref
        if let Some(uid_object) = uid_array
            .iter_mut()
            .find(|obj| obj.get(key_id_ref).is_some())
        {
            // Update the key-value pair in the existing object
            uid_object[key_id_ref] = Value::String(unique_id.to_string());
        } else {
            // If no object exists with the key_id_ref, add a new one
            let new_uid_object = json!({
                key_id_ref: unique_id
            });
            uid_array.push(new_uid_object);
        }
    } else {
        return Err(format!("Entity with UUID '{}' not found.", uuid).into());
    }

    fs::write(uid_path, serde_json::to_string_pretty(&entities)?)?;
    Ok(())
}

/*=================================================================================================== */

pub async fn update_two_stage_ttlv(
    file_path: &str,
    tag: &str,
    new_value: &str,
) -> Result<(), String> {
    let json_content =
        fs::read_to_string(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let mut json_data: Value =
        serde_json::from_str(&json_content).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // Find and update the tag's value
    if let Some(value_array) = json_data.get_mut("value").and_then(|v| v.as_array_mut()) {
        for item in value_array.iter_mut() {
            if let Some(item_tag) = item.get("tag").and_then(|t| t.as_str()) {
                if item_tag == tag {
                    item["value"] = json!(new_value);
                    break;
                }
            }
        }
    } else {
        return Err("The JSON structure does not match the expected format.".to_string());
    }

    // Write the updated JSON back to the file
    let updated_json = serde_json::to_string_pretty(&json_data)
        .map_err(|e| format!("Failed to serialize updated JSON: {}", e))?;
    fs::write(file_path, updated_json)
        .map_err(|e| format!("Failed to write updated JSON to file: {}", e))?;

    Ok(())
}

/*=================================================================================================== */

pub async fn handle_revoke(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    ref_tag: &str,
    id: &str,
) -> KResult<()> {
    // Helper function to handle the common revoke/destroy process
    async fn process_operation(
        kms: &KMS,
        user: &str,
        database_params: Option<&ExtraDatabaseParams>,
        req_path: &str,
        ref_tag: &str,
        id: &str,
    ) -> KResult<()> {
        let _revoke = update_two_stage_ttlv(req_path, ref_tag, id).await;
        let req_content = fs::read_to_string(req_path)?;
        let ttlv_operation = serde_json::from_str::<TTLV>(&req_content)?;
        dispatch(kms, &ttlv_operation, user, database_params).await?;
        Ok(())
    }

    // Process the revoke operation
    process_operation(kms, user, database_params, REVOKE_PATH, ref_tag, id).await?;

    // Process the destroy operation
    process_operation(kms, user, database_params, DESTROY_PATH, ref_tag, id).await?;

    Ok(())
}

/*=================================================================================================== */

pub async fn force(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    uid_path: &str,
    uuid: &str,
    key_id_ref: &str,
) -> KResult<()> {
    // Revoke and destroy already available crypto materials
    let available_id = extract_value_by_uuid_and_field(&uid_path, uuid, key_id_ref).await?;
    if available_id != "" {
        let _revoke = handle_revoke(
            kms,
            user,
            database_params,
            "UniqueIdentifier",
            &available_id,
        )
        .await;
    }
    Ok(())
}

/*=================================================================================================== */

pub async fn import_ca(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    ca_import_path: &str,
    ca_path: &str,
) -> KResult<String> {
    let private_key_id =
        extract_value_by_uuid_and_field(&ca_path, "ca", "CA_PRIVATE_KEY_ID").await?;
    if !private_key_id.is_empty() {
        return Ok(private_key_id);
    }

    // Dispatch operation if "CA_PRIVATE_KEY_ID" is missing or invalid
    let import_ca_req = fs::read_to_string(ca_import_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&import_ca_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the unique identifier from the response
    let unique_id = extract_unique_identifier(&resp).await?;

    let _update = update_devices_uid_json(ca_path, "ca", "CA_PRIVATE_KEY_ID", &unique_id).await;
    Ok(unique_id)
}

/*=================================================================================================== */

pub async fn new_uuid_generation(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    create_path: &str,
) -> KResult<String> {
    let create_req = fs::read_to_string(create_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_req)?;

    // Dispatch the Create operation
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp).await?;
    Ok(unique_id)
}

/*=================================================================================================== */

pub async fn handle_create(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    create_path: &str,
    uid_path: &str,
    uuid: &str,
    key_id_ref: &str,
) -> KResult<String> {
    // Force
    let _force = force(kms, user, database_params, uid_path, uuid, key_id_ref).await?;

    let mut operation_result = "Unsuccess";

    let create_req = fs::read_to_string(create_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_req)?;

    // Try to Dispatch the Create operation
    match dispatch(kms, &ttlv_operation, user, database_params).await {
        Ok(operation) => {
            operation_result = "Success";
            let rep_ttlv = to_ttlv(&operation)?;
            let resp = to_string(&rep_ttlv)?;
            let unique_id = extract_unique_identifier(&resp).await?;
            let _update = update_devices_uid_json(uid_path, uuid, key_id_ref, &unique_id).await;
        }
        Err(error) => {
            println!("Create dispatch failed: {:?}", error);
            let _update = update_devices_uid_json(uid_path, uuid, key_id_ref, "Invalid").await;
        }
    }
    Ok(operation_result.to_string())
}

/*=================================================================================================== */

pub async fn extract_unique_identifiers(json_body: &str) -> KResult<(String, String)> {
    let response: ImportResponse = serde_json::from_str(json_body)?;

    let mut private_key_uid = String::new();
    let mut public_key_uid = String::new();

    // Iterate over the attributes to find the specific identifiers
    for attribute in response.value.iter() {
        match attribute.tag.as_str() {
            "PrivateKeyUniqueIdentifier" => {
                private_key_uid = attribute.value.clone().to_string();
            }
            "PublicKeyUniqueIdentifier" => {
                public_key_uid = attribute.value.clone().to_string();
            }
            _ => {}
        }
    }
    Ok((private_key_uid, public_key_uid))
}

/*=================================================================================================== */

pub async fn handle_create_key_pair(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    create_key_pair_path: &str,
    uid_path: &str,
    uuid: &str,
    private_key_id_ref: &str,
    public_key_id_ref: &str,
) -> KResult<String> {
    // Force
    let _force = force(
        kms,
        user,
        database_params,
        uid_path,
        uuid,
        private_key_id_ref,
    )
    .await?;

    let create_key_pair_req = fs::read_to_string(create_key_pair_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_key_pair_req)?;

    let mut operation_result = "Unsuccess";

    // Try to Dispatch the Create Key Pair operation
    match dispatch(kms, &ttlv_operation, user, database_params).await {
        Ok(operation) => {
            operation_result = "Success";
            let rep_ttlv = to_ttlv(&operation)?;
            let resp = to_string(&rep_ttlv)?;
            let (private_uid, public_uid) = extract_unique_identifiers(&resp).await?;
            let _update =
                update_devices_uid_json(uid_path, uuid, private_key_id_ref, &private_uid).await;
            let _update =
                update_devices_uid_json(uid_path, uuid, public_key_id_ref, &public_uid).await;
        }
        Err(error) => {
            println!("Create Key Pair dispatch failed: {:?}", error);
            let _update =
                update_devices_uid_json(uid_path, uuid, private_key_id_ref, "Invalid").await;
            let _update =
                update_devices_uid_json(uid_path, uuid, public_key_id_ref, "Invalid").await;
        }
    }
    Ok(operation_result.to_string())
}

/*=================================================================================================== */

pub async fn update_cerify_json(
    file_path: &str,
    unique_identifier: &str,
    linked_object_identifier: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_string = fs::read_to_string(file_path)?;
    let mut json_data: Value = serde_json::from_str(&json_string)?;

    // Traverse and update the UniqueIdentifier
    if let Some(unique_id) = json_data
        .get_mut("value")
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| {
            arr.iter_mut()
                .find(|v| v.get("tag") == Some(&Value::String("UniqueIdentifier".to_string())))
        })
    {
        if let Some(value) = unique_id.get_mut("value") {
            *value = Value::String(unique_identifier.to_string());
        }
    }

    // Traverse and update the LinkedObjectIdentifier
    if let Some(linked_object_id) = json_data
        .get_mut("value")
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| {
            arr.iter_mut()
                .find(|v| v.get("tag") == Some(&Value::String("Attributes".to_string())))
        })
        .and_then(|attrs| attrs.get_mut("value"))
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| {
            arr.iter_mut()
                .find(|v| v.get("tag") == Some(&Value::String("Link".to_string())))
        })
        .and_then(|link| link.get_mut("value"))
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| {
            arr.iter_mut()
                .find(|v| v.get("tag") == Some(&Value::String("Link".to_string())))
        })
        .and_then(|inner_link| inner_link.get_mut("value"))
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| {
            arr.iter_mut().find(|v| {
                v.get("tag") == Some(&Value::String("LinkedObjectIdentifier".to_string()))
            })
        })
    {
        if let Some(value) = linked_object_id.get_mut("value") {
            *value = Value::String(linked_object_identifier.to_string());
        }
    }
    fs::write(file_path, serde_json::to_string_pretty(&json_data)?)?;
    Ok(())
}

pub async fn handle_certify(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    certify_path: &str,
    uid_path: &str,
    uuid: &str,
    ca_id: &str,
    pub_key_id_to_certify: &str,
    cert_id_ref: &str,
) -> KResult<String> {
    // Force
    let _force = force(kms, user, database_params, uid_path, uuid, cert_id_ref).await?;

    // Identifiers
    let unique_identifier = pub_key_id_to_certify;
    let linked_object_identifier = ca_id;

    // Update the Certify JSON file
    if let Err(e) =
        update_cerify_json(certify_path, unique_identifier, linked_object_identifier).await
    {
        eprintln!("Error updating JSON file: {}", e);
    }

    let mut operation_result = "Unsuccess";

    let certify_req = fs::read_to_string(certify_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&certify_req)?;

    // Try to Dispatch the Certify operation
    match dispatch(kms, &ttlv_operation, user, database_params).await {
        Ok(operation) => {
            operation_result = "Success";
            let rep_ttlv = to_ttlv(&operation)?;
            let resp = to_string(&rep_ttlv)?;
            let unique_id = extract_unique_identifier(&resp).await?;
            let _update = update_devices_uid_json(uid_path, uuid, cert_id_ref, &unique_id).await;
        }
        Err(error) => {
            println!("Certify dispatch failed: {:?}", error);
            let _update = update_devices_uid_json(uid_path, uuid, cert_id_ref, "Invalid").await;
        }
    }
    Ok(operation_result.to_string())
}

/*=================================================================================================== */

pub async fn extract_key(json_data: &Value) -> KResult<String> {
    let mut key = String::new();
    // Traverse through the JSON structure to find the ByteString value
    if let Some(value) = json_data.get("value") {
        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(tag) = item.get("tag").and_then(|t| t.as_str()) {
                    if tag == "Object" {
                        if let Some(object_value) = item.get("value").and_then(|v| v.as_array()) {
                            for obj_item in object_value {
                                if let Some(tag) = obj_item.get("tag").and_then(|t| t.as_str()) {
                                    if tag == "KeyBlock" {
                                        if let Some(key_block_value) =
                                            obj_item.get("value").and_then(|v| v.as_array())
                                        {
                                            for key_block_item in key_block_value {
                                                if let Some(tag) = key_block_item
                                                    .get("tag")
                                                    .and_then(|t| t.as_str())
                                                {
                                                    if tag == "KeyValue" {
                                                        if let Some(key_value_value) =
                                                            key_block_item
                                                                .get("value")
                                                                .and_then(|v| v.as_array())
                                                        {
                                                            for key_value_item in key_value_value {
                                                                if let Some(tag) = key_value_item
                                                                    .get("tag")
                                                                    .and_then(|t| t.as_str())
                                                                {
                                                                    if tag == "KeyMaterial" {
                                                                        if let Some(
                                                                            key_material_value,
                                                                        ) = key_value_item
                                                                            .get("value")
                                                                            .and_then(|v| {
                                                                                v.as_array()
                                                                            })
                                                                        {
                                                                            for key_material_item in
                                                                                key_material_value
                                                                            {
                                                                                if let Some(tag) = key_material_item.get("tag").and_then(|t| t.as_str()) {
                                                                                    if tag == "ByteString" {
                                                                                        // Return the ByteString value
                                                                                        if let Some(byte_string) = key_material_item.get("value").and_then(|v| v.as_str()) {
                                                                                            key = byte_string.to_string();
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(key)
}

pub async fn extract_cert(json_data: &Value) -> KResult<String> {
    let mut cert = String::new();
    // Traverse through the JSON structure to find the CertificateValue
    if let Some(value) = json_data.get("value") {
        if let Some(arr) = value.as_array() {
            for item in arr {
                if let Some(tag) = item.get("tag").and_then(|t| t.as_str()) {
                    if tag == "Object" {
                        if let Some(object_value) = item.get("value").and_then(|v| v.as_array()) {
                            for obj_item in object_value {
                                if let Some(tag) = obj_item.get("tag").and_then(|t| t.as_str()) {
                                    if tag == "CertificateValue" {
                                        if let Some(byte_string) =
                                            obj_item.get("value").and_then(|v| v.as_str())
                                        {
                                            cert = byte_string.to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(cert)
}

/*=================================================================================================== */

pub async fn handle_get(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    get_req_path: &str,
    ref_tag: &str,
    id: &str,
    crypto_type: &str,
) -> KResult<String> {
    let _update = update_two_stage_ttlv(get_req_path, ref_tag, id).await;
    let get_req_content = fs::read_to_string(get_req_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&get_req_content)?;

    let operation_result = dispatch(kms, &ttlv_operation, user, database_params).await?;
    let result_ttlv = to_ttlv(&operation_result)?;
    let result_json_string = to_string(&result_ttlv)?;
    let result_json: Value = serde_json::from_str(&result_json_string)?;

    // Extract the required data based on the crypto_material_type
    let crypto_data = match crypto_type {
        "key" => extract_key(&result_json).await?,
        "cert" => extract_cert(&result_json).await?,
        x => kms_bail!(KmsError::ItemNotFound(format!("Item: {x}"))),
    };
    Ok(crypto_data)
}

/*=================================================================================================== */

pub async fn get_current_timestamp() -> &'static str {
    // Get the current local datetime
    let now = Local::now();

    // Return the timestamp as a string slice
    Box::leak(now.format("%Y-%m-%d %H:%M:%S").to_string().into_boxed_str())
}

/*=================================================================================================== */
