use std::{fs, sync::Arc}; // Allows sharing KMSServer across threads safely.

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::{
    kmip_messages::Message,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use serde_json::to_string;
use tracing::info;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::dispatch, KMS},
    database::KMSServer,
    result::KResult,
};

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

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
    println!("body: {}", body);
    print_type_of(&body);
    let ttlv = serde_json::from_str::<TTLV>(&body)?;
    // println!("body: {}", Json(ttlv));
    print_type_of(&ttlv);

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(&req_http);

    /*Note: logging statement in Rust that uses the log crate (or a similar logging framework) to log information about a KMIP request. */
    info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip. Request: {:?} {}", ttlv.tag.as_str(), user);

    let ttlv_out: TTLV;

    if ttlv.tag.as_str() == "GenerateEnrolData" {
        ttlv_out =
            handle_generate_enroldata(&kms, &body, &ttlv, &user, database_params.as_ref()).await?;
    } else if ttlv.tag.as_str() == "GetEnrolData" {
        ttlv_out =
            handle_get_enroldata(&kms, &body, &ttlv, &user, database_params.as_ref()).await?;
    } else {
        /*Note: All the operations happens here and receive the response */
        ttlv_out = handle_ttlv(&kms, &ttlv, &user, database_params.as_ref()).await?;
        // print_type_of(&ttlv);
    }

    // Serialize TTLV back to JSON for printing
    let serialized_ttlv = to_string(&ttlv_out)?;

    // Print the serialized TTLV JSON to the console or log
    println!("Serialized TTLV: {}", serialized_ttlv);

    /*Note: Ok(Json(ttlv)) in the context of this code is returning a successful HTTP response, where the body of the response contains the ttlv data serialized into JSON format. */
    // print_type_of(&Json(ttlv));
    // let json_out = fs::read_to_string("crate/server/src/routes/enrol_data/Response.json")?;
    Ok(Json(ttlv_out))
    // let ttlv_fin = serde_json::from_str::<TTLV>(&json_out)?;
    // Ok(Json(ttlv_fin))
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
    if ttlv.tag.as_str() == "Message" {
        let req = from_ttlv::<Message>(ttlv)?;
        let resp = kms.message(req, user, database_params).await?;
        Ok(to_ttlv(&resp)?)
    } else {
        let operation = dispatch(kms, ttlv, user, database_params).await?;
        Ok(to_ttlv(&operation)?)
    }
}

/*======================================================================================================== */

// use std::error::Error;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct RequestAttribute {
    tag: String,
    #[serde(rename = "type")]
    #[allow(unused)] // Suppress warnings for unused fields
    attribute_type: String,
    value: String,
}

#[derive(Deserialize)]
struct RequestStructure {
    #[allow(unused)] // Suppress warnings for unused fields
    tag: String,
    #[serde(rename = "type")]
    #[allow(unused)] // Suppress warnings for unused fields
    structure_type: String,
    value: Vec<RequestAttribute>,
}

fn extract_request_info(json_body: &str, search_tag: &str) -> KResult<String> {
    // Parse the JSON string into the structure
    let parsed_json: RequestStructure = serde_json::from_str(json_body)?;

    let mut tag_value = String::new();

    // Find the attribute with the matching tag
    if let Some(attribute) = parsed_json.value.iter().find(|attr| attr.tag == search_tag) {
        tag_value = attribute.value.clone().to_string();
    }
    Ok(tag_value)
}

/*======================================================================================================== */

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

fn extract_unique_identifier(json_body: &str) -> KResult<String> {
    // Parse the JSON string into the `ImportResponse` struct
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

pub async fn import_ca(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    // Read the JSON file containing the CA import request
    let import_ca_req = fs::read_to_string("crate/server/src/routes/enrol_data/CA_import.json")?;

    // Deserialize the JSON into a TTLV operation
    let ttlv_operation = serde_json::from_str::<TTLV>(&import_ca_req)?;

    // Read the existing JSON file
    let file_path = "crate/server/src/routes/enrol_data/uid.json";
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(file_path)?)?;

    // Check if "device_key_id" exists and is not empty
    if let Some(ca_private_key_id) = json_data.get("CA_PRIVATE_KEY_ID") {
        if ca_private_key_id.is_string() && !ca_private_key_id.as_str().unwrap_or("").is_empty() {
            // If it exists, use the value
            let unique_id = ca_private_key_id.as_str().unwrap_or("").to_string();
            println!("CA UIDddddddddddddddd");
            println!("CA UID: {}", unique_id);
            return Ok(unique_id);
        }
    }

    // If no valid "device_key_id" found, dispatch operation
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp)?;

    // Update the "device_key_id" field in JSON data
    json_data["CA_PRIVATE_KEY_ID"] = serde_json::Value::String(unique_id.clone());

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifier
    println!("CA UID: {}", unique_id);

    // Return the unique ID
    Ok(unique_id)
}

/*======================================================================================================== */

use serde_json::json;

fn operation_status_json(tag: &str, type_str: &str, value: &str) -> Value {
    // Create the JSON structure with the provided inputs
    json!({
        "tag": tag,
        "type": type_str,
        "value": value
    })
}

use std::io;

fn append_to_response_json(file_path: &str, new_data: Value) -> io::Result<()> {
    // Read the existing JSON data from the file
    let mut existing_data: Value = serde_json::from_str(&fs::read_to_string(file_path)?)?;

    // Ensure the "value" field is an array (which it is in the original structure)
    if let Some(value_array) = existing_data
        .get_mut("value")
        .and_then(|v| v.as_array_mut())
    {
        // Append the new data to the array
        value_array.push(new_data);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid structure in the existing JSON",
        ));
    }

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&existing_data)?)?;
    Ok(())
}

async fn handle_create(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    uid_path: &str,
    key_id_ref: &str,
) -> KResult<Value> {
    let create_req = fs::read_to_string("crate/server/src/routes/enrol_data/Create.json")?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp)?;

    // Update uid json
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(uid_path)?)?;
    json_data[key_id_ref] = serde_json::Value::String(unique_id.clone());
    fs::write(uid_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifier
    println!("{key_id_ref}: {}", unique_id);

    let operation_result = operation_status_json("Status1", "TextString", "Success1");

    // Return the unique ID
    Ok(operation_result)
}

/*======================================================================================================== */

fn extract_unique_identifiers(json_body: &str) -> KResult<(String, String)> {
    // Parse the JSON string into the `ImportResponse` struct
    let response: ImportResponse = serde_json::from_str(json_body)?;

    // Initialize variables for the private and public key unique identifiers
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

    // Ensure both identifiers were found
    // if private_key_uid.is_empty() || public_key_uid.is_empty() {
    //     return Err(KError::new("Missing one or both unique identifiers"));
    // }

    Ok((private_key_uid, public_key_uid))
}

async fn handle_create_key_pair(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    uid_path: &str,
    private_key_id_ref: &str,
    public_key_id_ref: &str,
) -> KResult<Value> {
    let create_key_pair_req =
        fs::read_to_string("crate/server/src/routes/enrol_data/CreateKeyPair.json")?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_key_pair_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifiers
    let (private_uid, public_uid) = extract_unique_identifiers(&resp)?;

    // Update uid json
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(uid_path)?)?;
    json_data[private_key_id_ref] = serde_json::Value::String(private_uid.clone());
    json_data[public_key_id_ref] = serde_json::Value::String(public_uid.clone());
    fs::write(uid_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifiers
    println!("Private Key UID: {}", private_uid);
    println!("Public Key UID: {}", public_uid);

    let operation_result = operation_status_json("Status2", "TextString", "Success2");

    // Return the unique ID
    Ok(operation_result)
}

/*======================================================================================================== */

// use serde_json::{self, Value};

fn update_cerify_json(
    file_path: &str,
    unique_identifier: &str,
    linked_object_identifier: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read the JSON file into a string
    let json_string = fs::read_to_string(file_path)?;

    // Parse the JSON string into a serde_json::Value
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

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&json_data)?)?;
    Ok(())
}

async fn handle_certify(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    uid_path: &str,
    cert_id_ref: &str,
) -> KResult<Value> {
    // should check............................................................
    let certify_path = "crate/server/src/routes/enrol_data/Certify.json";
    let unique_identifier = "b2496783-d979-4864-bd44-bd78bd1a06d4_pk";
    let linked_object_identifier = "2672398c-9035-4b70-bd4e-8eed732ff762";

    match update_cerify_json(certify_path, unique_identifier, linked_object_identifier) {
        Ok(_) => println!("JSON file updated successfully."),
        Err(e) => eprintln!("Error updating JSON file: {}", e),
    }

    let certify_req = fs::read_to_string("crate/server/src/routes/enrol_data/Certify.json")?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&certify_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp)?;

    // Update uid json
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(uid_path)?)?;
    json_data[cert_id_ref] = serde_json::Value::String(unique_id.clone());
    fs::write(uid_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifier
    println!("KMS_CERT_ID: {}", unique_id);

    let operation_result = operation_status_json("Status3", "TextString", "Success3");

    // Return the unique ID
    Ok(operation_result)
}

/*======================================================================================================== */

fn update_two_stage_ttlv(file_path: &str, tag: &str, new_value: &str) -> Result<(), String> {
    // Read the JSON file
    let json_content =
        fs::read_to_string(file_path).map_err(|e| format!("Failed to read file: {}", e))?;

    // Parse the JSON content
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

/*======================================================================================================== */

async fn handle_generate_enroldata(
    kms: &KMS,
    body: &String,
    _ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    // Extract SerialNumber
    let serial_number = extract_request_info(body, "SerialNumber")?;
    println!("SerialNumber: {}", serial_number);

    // Extract PartNumber
    let part_number = extract_request_info(body, "PartNumber")?;
    println!("PartNumber: {}", part_number);

    println!("Serial Number: {}", serial_number);
    println!("Part Number: {}", part_number);

    let _ca_uid = import_ca(kms, user, database_params).await?;

    let uid_path = "crate/server/src/routes/enrol_data/uid.json";
    let gen_response_path = "crate/server/src/routes/enrol_data/GenerateEnrolDataResponse.json";

    // Create KMS keys

    let private_key_id_ref = "KMS_PRIVATE_KEY_ID";
    let public_key_id_ref = "KMS_PUBLIC_KEY_ID";

    let new_create_key_pair_appended = handle_create_key_pair(
        kms,
        &user,
        database_params,
        &uid_path,
        &private_key_id_ref,
        &public_key_id_ref,
    )
    .await?;

    let _unused = append_to_response_json(gen_response_path, new_create_key_pair_appended);

    // Certify KMS

    let cert_id_ref = "KMS_CERT_ID";

    let new_create_appended =
        handle_certify(kms, &user, database_params, &uid_path, &cert_id_ref).await?;

    let _unused = append_to_response_json(gen_response_path, new_create_appended);

    // Create device key

    let key_id_ref = "DEVICE_KEY_ID";

    let new_create_appended =
        handle_create(kms, &user, database_params, &uid_path, &key_id_ref).await?;

    let _unused = append_to_response_json(gen_response_path, new_create_appended);

    // Create device keys

    let private_key_id_ref = "DEVICE_PRIVATE_KEY_ID";
    let public_key_id_ref = "DEVICE_PUBLIC_KEY_ID";

    let new_create_key_pair_appended = handle_create_key_pair(
        kms,
        &user,
        database_params,
        &uid_path,
        &private_key_id_ref,
        &public_key_id_ref,
    )
    .await?;

    let _unused = append_to_response_json(gen_response_path, new_create_key_pair_appended);

    // Certify device

    let cert_id_ref = "DEVICE_CERT_ID";

    let new_create_appended =
        handle_certify(kms, &user, database_params, &uid_path, &cert_id_ref).await?;

    let _unused = append_to_response_json(gen_response_path, new_create_appended);

    // Create UUID keys

    let private_key_id_ref = "DEVICE_UUID_PRIVATE_KEY_ID";
    let public_key_id_ref = "DEVICE_UUID_PUBLIC_KEY_ID";

    let new_create_key_pair_appended = handle_create_key_pair(
        kms,
        &user,
        database_params,
        &uid_path,
        &private_key_id_ref,
        &public_key_id_ref,
    )
    .await?;

    let _unused = append_to_response_json(gen_response_path, new_create_key_pair_appended);

    // Certify UUID

    let cert_id_ref = "DEVICE_UUID_CERT_ID";

    let new_create_appended =
        handle_certify(kms, &user, database_params, &uid_path, &cert_id_ref).await?;

    let _unused = append_to_response_json(gen_response_path, new_create_appended);

    // Final output

    let fin_res = fs::read_to_string(gen_response_path)?;
    let fin_ttlv = serde_json::from_str::<TTLV>(&fin_res)?;
    Ok(fin_ttlv)
}

/*======================================================================================================== */

fn extract_key(json_data: &Value) -> KResult<String> {
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

fn extract_cert(json_data: &Value) -> KResult<String> {
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

async fn handle_get(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
    get_req_path: &str,
    ref_tag: &str,
    id: &str,
    crypto_type: &str,
) -> KResult<String> {
    // Change get request
    let _unused = update_two_stage_ttlv(get_req_path, ref_tag, &id);

    let get_req = fs::read_to_string(get_req_path)?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&get_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;
    let json_value: Value = serde_json::from_str(&resp)?;

    let mut crypto_data = String::new();

    if crypto_type == "key" {
        crypto_data = extract_key(&json_value)?;
    } else if crypto_type == "cert" {
        crypto_data = extract_cert(&json_value)?;
    }

    println!("key: {}", crypto_data);

    Ok(crypto_data)
}

use chrono::Local;

fn get_current_timestamp() -> &'static str {
    // Get the current local datetime
    let now = Local::now();

    // Return the timestamp as a string slice
    Box::leak(now.format("%Y-%m-%d %H:%M:%S").to_string().into_boxed_str())
}

async fn handle_get_enroldata(
    kms: &KMS,
    body: &String,
    _ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    // Extract uuid
    let uuid = extract_request_info(body, "UUID")?;
    println!("UUID: {}", uuid);

    // Get key value
    // let uid_path = "crate/server/src/routes/enrol_data/uid.json";
    let get_req_path = "crate/server/src/routes/enrol_data/Get.json";
    let get_response_path = "crate/server/src/routes/enrol_data/GetEnrolDataResponse.json";
    let uid_path = "crate/server/src/routes/enrol_data/uid.json";
    let mut _json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(uid_path)?)?;

    // 01

    let id: &str = _json_data["DEVICE_UUID_CERT_ID"].as_str().unwrap();
    let cert = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "cert",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "DeviceUUIDCertificate", &cert);

    // 02

    let id = _json_data["DEVICE_PRIVATE_KEY_ID"].as_str().unwrap();
    println!("---------------id : {}", id);
    let key = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "key",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "DeviceCertificatePrivateKey", &key);

    // 03

    let id = _json_data["DEVICE_CERT_ID"].as_str().unwrap();
    let cert = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "cert",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "DeviceCertificate", &cert);

    // 04

    let id = _json_data["DEVICE_KEY_ID"].as_str().unwrap();
    let key = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "key",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "DeviceKey", &key);

    // 05

    let id = _json_data["KMS_CERT_ID"].as_str().unwrap();
    let cert = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "cert",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "KMSCertificate", &cert);

    // 06

    let id = _json_data["CA_CERT_ID"].as_str().unwrap();
    let cert = handle_get(
        kms,
        &user,
        database_params,
        &get_req_path,
        "UniqueIdentifier",
        id,
        "cert",
    )
    .await?;
    let _unused = update_two_stage_ttlv(get_response_path, "CACertificate", &cert);

    // 07

    let timestamp = get_current_timestamp();
    let _unused = update_two_stage_ttlv(get_response_path, "TimeStamp", &timestamp);

    // Final output

    let fin_res = fs::read_to_string(get_response_path)?;
    let fin_ttlv = serde_json::from_str::<TTLV>(&fin_res)?;
    Ok(fin_ttlv)
}

/*======================================================================================================== */
