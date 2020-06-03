pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Libbpf(String, LibbpfError),
    Generic(GenericError),
    InvalidProgName,
    InvalidMapName,
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
