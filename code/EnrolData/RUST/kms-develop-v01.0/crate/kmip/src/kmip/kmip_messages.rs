use std::fmt::{self, Display, Formatter};

/// The messages in the protocol consist of a message header,
/// one or more batch items (which contain OPTIONAL message payloads),
/// and OPTIONAL message extensions. The message headers contain fields whose
/// presence is determined by the protocol features used (e.g., asynchronous responses).
/// The field contents are also determined by whether the message is a request or a response.
/// The message payload is determined by the specific operation being
/// requested or to which is being replied.
///
/// The message headers are structures that contain some of the following objects.
///
/// Messages contain the following objects and fields.
/// All fields SHALL appear in the order specified.
///
/// If the client is capable of accepting asynchronous responses,
/// then it MAY set the Asynchronous
///
/// Indicator in the header of a batched request.
/// The batched responses MAY contain a mixture of synchronous and
/// asynchronous responses only if the Asynchronous Indicator is present in the header.
use chrono::Utc;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::{self, SerializeStruct},
    Deserialize, Serialize,
};

use super::{
    kmip_operations::{Direction, ErrorReason, Operation},
    kmip_types::{
        AsynchronousIndicator, AttestationType, BatchErrorContinuationOption, Credential,
        MessageExtension, Nonce, OperationEnumeration, ProtocolVersion, ResultStatusEnumeration,
    },
};

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    /// Header of the request
    pub header: MessageHeader,
    /// Batch items of the request
    pub items: Vec<MessageBatchItem>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut temp_str = format!("Message header: {:?}, ", self.header);
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                temp_str.push_str(", ");
            }
            temp_str = format!("{temp_str} {item}");
        }
        write!(f, "{temp_str}")
    }
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let header_batch_count = usize::try_from(self.header.batch_count)
            .map_err(|err| ser::Error::custom(format!("failed to convert batch count: {err:?}")))?;
        // check batch item count
        if header_batch_count != self.items.len() {
            return Err(ser::Error::custom(format!(
                "mismatch number of batch items between header (`{}`) and items list (`{}`)",
                self.header.batch_count,
                self.items.len()
            )))
        }
        // check version of protocol version defined in the header is
        // equal or greater than the protocol version of each item's payload.
        for item in &self.items {
            if self.header.protocol_version > item.request_payload.protocol_version() {
                return Err(ser::Error::custom(format!(
                    "item's protocol version is greater (`{}`) than header's protocol version \
                     (`{}`)",
                    self.header.protocol_version,
                    item.request_payload.protocol_version()
                )))
            }
        }
        let mut st = serializer.serialize_struct("Message", 2)?;
        st.serialize_field("Header", &self.header)?;
        st.serialize_field("Items", &self.items)?;
        st.end()
    }
}

/// Header of the request
///
/// Contains fields whose presence is determined by the protocol features used.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MessageHeader {
    pub protocol_version: ProtocolVersion,
    /// This is an OPTIONAL field contained in a request message,
    /// and is used to indicate the maximum size of a response, in bytes,
    /// that the requester SHALL be able to handle.
    ///
    /// It SHOULD only be sent in requests that possibly return large replies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_response_size: Option<u32>,
    /// The Client Correlation Value is a string that MAY be added to messages by clients
    /// to provide additional information to the server. It need not be unique.
    /// The server SHOULD log this information.
    ///
    /// For client to server operations, the Client Correlation Value is provided in the request.
    /// For server to client operations, the Client Correlation Value is provided in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    /// The Server Correlation Value SHOULD be provided by the server and
    /// SHOULD be globally unique, and SHOULD be logged by the server with each request.
    ///
    /// For client to server operations, the Server Correlation Value is provided in the response.
    /// For server to client operations, the Server Correlation Value is provided in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asynchronous_indicator: Option<AsynchronousIndicator>,
    /// Indicates whether the client is able to create
    /// an Attestation Credential Object.
    ///
    /// If not present, the value `false` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_capable_indicator: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    /// Used to authenticate the requester
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Credential>>,
    /// If omitted, then `Stop` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_error_continuation_option: Option<BatchErrorContinuationOption>,
    /// If omitted, then `true` is assumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_order_option: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>, // epoch millis
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

/// Batch item for a message request
///
/// `request_payload` depends on the request
#[derive(PartialEq, Eq)]
pub struct MessageBatchItem {
    /// Type of the KMIP operation
    pub operation: OperationEnumeration,
    /// Indicates that the Data output of the operation should not
    /// be returned to the client
    pub ephemeral: Option<bool>,
    /// This is an OPTIONAL field contained in a request,
    /// and is used for correlation between requests and responses.
    ///
    /// If a request has a Unique Batch Item ID, then responses to
    /// that request SHALL have the same Unique Batch Item ID.
    pub unique_batch_item_id: Option<u32>,
    /// The KMIP request, which depends on the KMIP Operation
    pub request_payload: Operation,
    pub message_extension: Option<Vec<MessageExtension>>,
}

impl fmt::Display for MessageBatchItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MessageBatchItem {{ operation: {:?}, ephemeral: {:?}, unique_batch_item_id: {:?}, \
             request_payload: {}, message_extension: {:?} }}",
            self.operation,
            self.ephemeral,
            self.unique_batch_item_id,
            self.request_payload,
            self.message_extension
        )
    }
}
impl MessageBatchItem {
    #[must_use]
    pub const fn new(request: Operation) -> Self {
        Self {
            operation: request.operation_enum(),
            ephemeral: None,
            unique_batch_item_id: None,
            request_payload: request,
            message_extension: None,
        }
    }
}

impl Serialize for MessageBatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.operation != self.request_payload.operation_enum() {
            return Err(ser::Error::custom(format!(
                "operation enum (`{}`) doesn't correspond to request payload (`{}`)",
                self.operation,
                self.request_payload.operation_enum()
            )))
        }
        if self.request_payload.direction() != Direction::Request {
            return Err(ser::Error::custom(format!(
                "request payload operation is not a request type operation (`{:?}`)",
                self.request_payload.direction()
            )))
        }

        let mut st = serializer.serialize_struct("MessageBatchItem", 5)?;
        st.serialize_field("Operation", &self.operation)?;
        if let Some(ephemeral) = &self.ephemeral {
            st.serialize_field("Ephemeral", ephemeral)?;
        }
        if let Some(unique_batch_item_id) = &self.unique_batch_item_id {
            st.serialize_field("UniqueBatchItemId", unique_batch_item_id)?;
        }
        st.serialize_field("RequestPayload", &self.request_payload)?;
        if let Some(message_extension) = &self.message_extension {
            st.serialize_field("MessageExtension", &message_extension)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for MessageBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            Ephemeral,
            UniqueBatchItemId,
            RequestPayload,
            MessageExtension,
        }

        struct MessageBatchItemVisitor;

        impl<'de> Visitor<'de> for MessageBatchItemVisitor {
            type Value = MessageBatchItem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MessageBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut ephemeral: Option<bool> = None;
                let mut unique_batch_item_id: Option<u32> = None;
                let mut request_payload: Option<Operation> = None;
                let mut message_extension: Option<Vec<MessageExtension>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("operation"))
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::Ephemeral => {
                            if ephemeral.is_some() {
                                return Err(de::Error::duplicate_field("ephemeral"))
                            }
                            ephemeral = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemId => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("unique_batch_item_id"))
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("message_extension"))
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::RequestPayload => {
                            if request_payload.is_some() {
                                return Err(de::Error::duplicate_field("request_payload"))
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `request_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            request_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::Encrypt(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::Create(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPair(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::Certify(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::Locate(map.next_value()?)
                                }
                                OperationEnumeration::Get => Operation::Get(map.next_value()?),
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributes(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::Revoke(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::Destroy(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::Decrypt(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::Import(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::Export(map.next_value()?)
                                }
                                _ => return Err(de::Error::missing_field("valid enum operation")),
                            });
                        }
                    }
                }
                let operation = operation.ok_or_else(|| de::Error::missing_field("operation"))?;
                tracing::trace!("MessageBatchItem operation: {operation:?}");

                let request_payload =
                    request_payload.ok_or_else(|| de::Error::missing_field("request_payload"))?;
                tracing::trace!("MessageBatchItem request payload: {request_payload}");

                if operation != request_payload.operation_enum() {
                    return Err(de::Error::custom(format!(
                        "operation enum (`{}`) doesn't correspond to request payload (`{}`)",
                        operation,
                        request_payload.operation_enum()
                    )))
                }

                Ok(MessageBatchItem {
                    operation,
                    ephemeral,
                    unique_batch_item_id,
                    request_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "operation",
            "ephemeral",
            "unique_batch_item_id",
            "request_payload",
            "message_extension",
        ];
        deserializer.deserialize_struct("MessageBatchItem", FIELDS, MessageBatchItemVisitor)
    }
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MessageResponse {
    /// Message type
    // pub message_type: &'static str,
    /// Header of the response
    pub header: MessageResponseHeader,
    /// Batch items of the response
    pub items: Vec<MessageResponseBatchItem>,
}

impl Serialize for MessageResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let header_batch_count = usize::try_from(self.header.batch_count)
            .map_err(|err| ser::Error::custom(format!("failed to convert batch count: {err:?}")))?;

        // check batch item count
        if header_batch_count != self.items.len() {
            return Err(ser::Error::custom(format!(
                "mismatch number of batch items between header (`{}`) and items list (`{}`)",
                self.header.batch_count,
                self.items.len()
            )))
        }
        // check version of protocol version defined in the header is
        // equal or greater than the protocol version of each item's payload.
        for item in &self.items {
            if let Some(response_payload) = &item.response_payload {
                if self.header.protocol_version > response_payload.protocol_version() {
                    return Err(ser::Error::custom(format!(
                        "item's protocol version is greater (`{}`) than header's protocol version \
                         (`{}`)",
                        self.header.protocol_version,
                        response_payload.protocol_version()
                    )))
                }
            }
        }
        let mut st = serializer.serialize_struct("Message", 2)?;
        // let mut st = serializer.serialize_struct(&self.message_type, 2)?;
        st.serialize_field("Header", &self.header)?;
        st.serialize_field("Items", &self.items)?;
        st.end()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MessageResponseHeader {
    pub protocol_version: ProtocolVersion,
    pub timestamp: u64, // epoch millis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    /// Mandatory only if Hashed Password credential was used
    ///
    /// Hash(Timestamp || S1 || Hash(S2)), where S1, S2 and
    /// the Hash algorithm are defined in the Hashed Password credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_hashed_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_type: Option<Vec<AttestationType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_correlation_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_correlation_value: Option<String>,
    /// This field contains the number of Batch Items in a message and is REQUIRED.
    ///
    /// If only a single operation is being requested, then the batch count SHALL be set to 1.
    /// The Message Payload, which follows the Message Header, contains one or more batch items.
    pub batch_count: u32,
}

/// Default implementation for a message response header
///
/// The timestamp is automatically set to now (UTC time)
impl Default for MessageResponseHeader {
    #[allow(clippy::cast_sign_loss, clippy::as_conversions)]
    fn default() -> Self {
        Self {
            timestamp: Utc::now().timestamp() as u64,
            protocol_version: ProtocolVersion::default(),
            nonce: None,
            server_hashed_password: None,
            attestation_type: None,
            client_correlation_value: None,
            server_correlation_value: None,
            batch_count: 0,
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct MessageResponseBatchItem {
    /// Required if present in request Batch Item
    pub operation: Option<OperationEnumeration>,
    /// Required if present in request Batch Item
    pub unique_batch_item_id: Option<u32>,
    /// Indicates the success or failure of a request
    pub result_status: ResultStatusEnumeration,
    /// Indicates a reason for failure or a modifier for a
    /// partially successful operation and SHALL be present in
    /// responses that return a Result Status of Failure.
    ///
    /// Required if `result_status` is `Failure`
    pub result_reason: Option<ErrorReason>,
    /// Contains a more descriptive error message,
    /// which MAY be provided to an end user or used for logging/auditing purposes.
    ///
    /// Required if `result_status` is NOT `Pending` or `Success`
    pub result_message: Option<String>,
    /// Returned in the immediate response to an operation that is pending and
    /// that requires asynchronous polling. Note: the server decides which
    /// operations are performed synchronously or asynchronously.
    ///
    /// A server-generated correlation value SHALL be specified in any subsequent
    /// Poll or Cancel operations that pertain to the original operation.
    ///
    /// Required if `result_status` is `Pending`
    pub asynchronous_correlation_value: Option<Vec<u8>>,
    /// The KMIP response, which depends on the KMIP Operation
    ///
    /// Mandatory if a success, `None` in case of failure.
    ///
    /// Content depends on Operation.
    pub response_payload: Option<Operation>,
    pub message_extension: Option<MessageExtension>,
}

impl MessageResponseBatchItem {
    #[must_use]
    pub const fn new(result_status: ResultStatusEnumeration) -> Self {
        Self {
            result_status,
            operation: None,
            unique_batch_item_id: None,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            response_payload: None,
            message_extension: None,
        }
    }

    #[must_use]
    pub const fn new_with_response(
        result_status: ResultStatusEnumeration,
        response: Operation,
    ) -> Self {
        Self {
            result_status,
            operation: Some(response.operation_enum()),
            response_payload: Some(response),
            unique_batch_item_id: None,
            result_reason: None,
            result_message: None,
            asynchronous_correlation_value: None,
            message_extension: None,
        }
    }
}

impl Serialize for MessageResponseBatchItem {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.result_status {
            ResultStatusEnumeration::OperationFailed if self.result_reason.is_none() => {
                return Err(ser::Error::custom(
                    "missing `ResultReason` with failed status (`ResultStatus` is set to \
                     `OperationFailed`)",
                ))
            }
            ResultStatusEnumeration::OperationFailed | ResultStatusEnumeration::OperationUndone
                if self.result_message.is_none() =>
            {
                return Err(ser::Error::custom(
                    "missing `ResultMessage` with unsuccessful status (`ResultStatus` is set to \
                     either `OperationFailed` or `OperationUndone`)",
                ))
            }
            ResultStatusEnumeration::OperationPending
                if self.asynchronous_correlation_value.is_none() =>
            {
                return Err(ser::Error::custom(
                    "missing `AsynchronousCorrelationValue` with pending status (`ResultStatus` \
                     is set to `OperationPending`)",
                ))
            }
            _ => (),
        }

        let mut st = serializer.serialize_struct("MessageResponseBatchItem", 5)?;
        if let Some(operation) = self.operation {
            if let Some(response_payload) = &self.response_payload {
                if operation != response_payload.operation_enum() {
                    return Err(ser::Error::custom(format!(
                        "operation enum (`{}`) doesn't correspond to response payload (`{}`)",
                        operation,
                        response_payload.operation_enum()
                    )))
                }

                if response_payload.direction() != Direction::Response {
                    return Err(ser::Error::custom(format!(
                        "response payload operation is not a response type operation (`{:?}`)",
                        response_payload.direction()
                    )))
                }
            }

            st.serialize_field("Operation", &self.operation)?;
        }
        if let Some(unique_batch_item_id) = &self.unique_batch_item_id {
            st.serialize_field("UniqueBatchItemId", unique_batch_item_id)?;
        }
        st.serialize_field("ResultStatus", &self.result_status)?;
        if let Some(result_reason) = &self.result_reason {
            st.serialize_field("ResultReason", result_reason)?;
        }
        if let Some(result_message) = &self.result_message {
            st.serialize_field("ResultMessage", result_message)?;
        }
        if let Some(acv) = &self.asynchronous_correlation_value {
            st.serialize_field("AsynchronousCorrelationValue", &acv)?;
        }
        if let Some(response_payload) = &self.response_payload {
            st.serialize_field("ResponsePayload", &response_payload)?;
        }
        if let Some(message_extension) = &self.message_extension {
            st.serialize_field("MessageExtension", &message_extension)?;
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for MessageResponseBatchItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Operation,
            UniqueBatchItemId,
            ResultStatus,
            ResultReason,
            ResultMessage,
            AsynchronousCorrelationValue,
            ResponsePayload,
            MessageExtension,
        }

        struct MessageResponseBatchItemVisitor;

        impl<'de> Visitor<'de> for MessageResponseBatchItemVisitor {
            type Value = MessageResponseBatchItem;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct MessageResponseBatchItem")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut operation: Option<OperationEnumeration> = None;
                let mut unique_batch_item_id: Option<u32> = None;
                let mut result_status: Option<ResultStatusEnumeration> = None;
                let mut result_reason: Option<ErrorReason> = None;
                let mut result_message: Option<String> = None;
                let mut asynchronous_correlation_value: Option<Vec<u8>> = None;
                let mut response_payload: Option<Operation> = None;
                let mut message_extension: Option<MessageExtension> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Operation => {
                            if operation.is_some() {
                                return Err(de::Error::duplicate_field("operation"))
                            }
                            operation = Some(map.next_value()?);
                        }
                        Field::UniqueBatchItemId => {
                            if unique_batch_item_id.is_some() {
                                return Err(de::Error::duplicate_field("unique_batch_item_id"))
                            }
                            unique_batch_item_id = Some(map.next_value()?);
                        }
                        Field::MessageExtension => {
                            if message_extension.is_some() {
                                return Err(de::Error::duplicate_field("message_extension"))
                            }
                            message_extension = Some(map.next_value()?);
                        }
                        Field::ResultStatus => {
                            if result_status.is_some() {
                                return Err(de::Error::duplicate_field("result_status"))
                            }
                            result_status = Some(map.next_value()?);
                        }
                        Field::ResultReason => {
                            if result_reason.is_some() {
                                return Err(de::Error::duplicate_field("result_reason"))
                            }
                            result_reason = Some(map.next_value()?);
                        }
                        Field::ResultMessage => {
                            if result_message.is_some() {
                                return Err(de::Error::duplicate_field("result_message"))
                            }
                            result_message = Some(map.next_value()?);
                        }
                        Field::AsynchronousCorrelationValue => {
                            if asynchronous_correlation_value.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "asynchronous_correlation_value",
                                ))
                            }
                            asynchronous_correlation_value = Some(map.next_value()?);
                        }
                        Field::ResponsePayload => {
                            if response_payload.is_some() {
                                return Err(de::Error::duplicate_field("response_payload"))
                            }
                            // we must have parsed the `operation` field before
                            // TODO: handle the case where the keys are not in right order
                            let Some(operation) = operation else {
                                return Err(de::Error::missing_field("operation"))
                            };
                            // recover by hand the proper type of `response_payload`
                            // the default derived deserializer does not have enough
                            // information to properly recover which type has been
                            // serialized, we need to do the job by hand,
                            // using the `operation` enum.
                            response_payload = Some(match operation {
                                OperationEnumeration::Encrypt => {
                                    Operation::EncryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Create => {
                                    Operation::CreateResponse(map.next_value()?)
                                }
                                OperationEnumeration::CreateKeyPair => {
                                    Operation::CreateKeyPairResponse(map.next_value()?)
                                }
                                OperationEnumeration::Certify => {
                                    Operation::CertifyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Locate => {
                                    Operation::LocateResponse(map.next_value()?)
                                }
                                OperationEnumeration::Get => {
                                    Operation::GetResponse(map.next_value()?)
                                }
                                OperationEnumeration::GetAttributes => {
                                    Operation::GetAttributesResponse(map.next_value()?)
                                }
                                OperationEnumeration::Revoke => {
                                    Operation::RevokeResponse(map.next_value()?)
                                }
                                OperationEnumeration::Destroy => {
                                    Operation::DestroyResponse(map.next_value()?)
                                }
                                OperationEnumeration::Decrypt => {
                                    Operation::DecryptResponse(map.next_value()?)
                                }
                                OperationEnumeration::Import => {
                                    Operation::ImportResponse(map.next_value()?)
                                }
                                OperationEnumeration::Export => {
                                    Operation::ExportResponse(map.next_value()?)
                                }
                                _ => {
                                    return Err(de::Error::missing_field(
                                        "valid enum operation (unsupported operation ?)",
                                    ))
                                }
                            });
                        }
                    }
                }

                tracing::trace!("MessageResponseBatchItem operation: {operation:?}");
                if let Some(response_payload) = &response_payload {
                    tracing::trace!(
                        "MessageResponseBatchItem response payload: {response_payload}"
                    );
                }

                let result_status =
                    result_status.ok_or_else(|| de::Error::missing_field("result_status"))?;

                match result_status {
                    ResultStatusEnumeration::OperationFailed if result_reason.is_none() => {
                        // missing `ResultReason` with failed status
                        return Err(de::Error::missing_field("result_reason"))
                    }
                    ResultStatusEnumeration::OperationFailed
                    | ResultStatusEnumeration::OperationUndone
                        if result_message.is_none() =>
                    {
                        // missing `ResultMessage` with unsuccessful status
                        return Err(de::Error::missing_field("result_message"))
                    }
                    ResultStatusEnumeration::OperationPending
                        if asynchronous_correlation_value.is_none() =>
                    {
                        // missing `ResultMessage` with unsuccessful status
                        return Err(de::Error::missing_field("asynchronous_correlation_value"))
                    }
                    _ => (),
                }

                Ok(MessageResponseBatchItem {
                    operation,
                    unique_batch_item_id,
                    result_status,
                    result_reason,
                    result_message,
                    asynchronous_correlation_value,
                    response_payload,
                    message_extension,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "operation",
            "unique_batch_item_id",
            "result_status",
            "result_reason",
            "result_message",
            "asynchronous_correlation_value",
            "response_payload",
            "message_extension",
        ];
        deserializer.deserialize_struct(
            "MessageResponseBatchItem",
            FIELDS,
            MessageResponseBatchItemVisitor,
        )
    }
}
