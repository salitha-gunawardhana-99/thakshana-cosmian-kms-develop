/*
Note: Use Case: This pattern is useful for enhancing error handling in Rust applications, particularly when you want to:

Provide richer error information (e.g., attach reasons or contexts to errors).
Streamline error mapping (reduce boilerplate for error conversion).
Improve debugging and observability by including detailed error messages.
*/

use cosmian_kmip::kmip::kmip_operations::ErrorReason;

use crate::error::KmsError;

pub type KResult<R> = Result<R, KmsError>;

/// A helper trait for `KResult` that provides additional methods for error handling.
pub trait KResultHelper<T> {
    /// Sets the reason for the error.
    ///
    /// # Errors
    ///
    /// Returns a `KResult` with the specified `ErrorReason` if the original result is an error.
    fn reason(self, reason: ErrorReason) -> KResult<T>;

    /// Sets the context for the error.
    ///
    /// # Errors
    ///
    /// Returns a `KResult` with the specified context if the original result is an error.
    fn context(self, context: &str) -> KResult<T>;

    /// Sets the context for the error using a closure.
    ///
    /// # Errors
    ///
    /// Returns a `KResult` with the context returned by the closure if the original result is an error.
    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String;
}

impl<T, E> KResultHelper<T> for std::result::Result<T, E>
where
    E: std::error::Error,
{
    fn reason(self, reason: ErrorReason) -> KResult<T> {
        self.map_err(|e| KmsError::ServerError(e.to_string()).reason(reason))
    }

    fn context(self, context: &str) -> KResult<T> {
        self.map_err(|e| KmsError::ServerError(format!("{context}: {e}")))
    }

    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String,
    {
        self.map_err(|e| KmsError::ServerError(format!("{}: {e}", op())))
    }
}

impl<T> KResultHelper<T> for Option<T> {
    fn context(self, context: &str) -> KResult<T> {
        self.ok_or_else(|| KmsError::ServerError(context.to_owned()))
    }

    fn with_context<O>(self, op: O) -> KResult<T>
    where
        O: FnOnce() -> String,
    {
        self.ok_or_else(|| KmsError::ServerError(op()))
    }

    fn reason(self, reason: ErrorReason) -> KResult<T> {
        self.ok_or_else(|| KmsError::ServerError(reason.to_string()))
    }
}
