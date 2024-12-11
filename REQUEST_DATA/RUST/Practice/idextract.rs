use serde::Deserialize;
use std::error::Error;

#[derive(Deserialize)]
struct ImportResponse {
    tag: String,
    #[serde(rename = "type")]
    data_type: String,
    value: Vec<Attribute>,
}

#[derive(Deserialize)]
struct Attribute {
    tag: String,
    #[serde(rename = "type")]
    data_type: String,
    value: String,
}

fn extract_unique_identifier(json_body: &str) -> Result<String, Box<dyn Error>> {
    // Parse the JSON string into the `ImportResponse` struct
    let response: ImportResponse = serde_json::from_str(json_body)?;

    // Find the attribute with the tag "UniqueIdentifier"
    if let Some(attribute) = response
        .value
        .iter()
        .find(|attr| attr.tag == "UniqueIdentifier")
    {
        return Ok(attribute.value.clone());
    }

    Err("UniqueIdentifier not found".into())
}

fn main() {
    let json_body = r#"
    {
      "tag": "ImportResponse",
      "type": "Structure",
      "value": [
        {
          "tag": "UniqueIdentifier",
          "type": "TextString",
          "value": "c8da37bf-9752-42fd-b6ed-cbea359671c3"
        }
      ]
    }
    "#;

    match extract_unique_identifier(json_body) {
        Ok(unique_identifier) => println!("Unique Identifier: {}", unique_identifier),
        Err(e) => println!("Error: {}", e),
    }
}
