use connectrpc::ConnectError;

pub mod crypto;
pub mod mining;
pub mod validator;
pub mod wallet;

pub(crate) fn invalid_field_value<Message: buffa::MessageName, Error>(
    field_name: &str,
    value: &str,
    source: Error,
) -> ConnectError
where
    Error: std::error::Error + Send + Sync + 'static,
{
    crate::proto::Error::invalid_field_value::<Message, _>(field_name, value, source).into()
}

pub(crate) fn missing_field<Message: buffa::MessageName>(field_name: &str) -> ConnectError {
    crate::proto::Error::missing_field::<Message>(field_name).into()
}

pub(crate) fn internal_err<E: std::fmt::Display>(err: E) -> ConnectError {
    ConnectError::internal(err.to_string())
}
