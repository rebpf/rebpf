pub enum Error {
    CStringConversion(std::ffi::NulError),
    InvalidInterfaceName,
    InvalidPath,
    BpfProgLoad(std::os::raw::c_int),
    BpfSetLinkXdpFd(std::os::raw::c_int),
    BpfObjGetInfoByFd(std::os::raw::c_int),
}
