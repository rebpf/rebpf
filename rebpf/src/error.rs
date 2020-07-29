use thiserror::Error;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("libbpf-related error: {0} ({1:?})")]
    Libbpf(String, LibbpfError),
    #[error("Generic programming error: {0:?}")]
    Generic(GenericError),
    #[error("Invalid BPF program name")]
    InvalidProgName,
    #[error("Invalid BPF map name")]
    InvalidMapName,
    #[error("Custom error: {0}")]
    Custom(String),
}

#[derive(Debug)]
pub enum GenericError {
    CStringConversion(std::ffi::NulError),
    CCharConversion(std::str::Utf8Error),
    InvalidPath,
    InvalidInterfaceName(String),
    OutOfIndex,
}

#[derive(Debug)]
pub enum LibbpfError {
    LibbpfSys(std::os::raw::c_int),
    InvalidFd,
    InvalidTitle,
}
