// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

#[derive(Debug)]
pub enum Error {
    CStringConversion(std::ffi::NulError),
    CCharConversion(std::str::Utf8Error),
    InvalidInterfaceName,
    InvalidPath,
    InvalidProgSec,
    InvalidMapName,
    InvalidBpfProgram,
    InvalidInfoSize,
    InvalidBpfMap,
    BpfProgLoad(std::os::raw::c_int),
    BpfSetLinkXdpFd(std::os::raw::c_int),
    BpfObjGetInfoByFd(std::os::raw::c_int),
    BpfMapUpdateElem(std::os::raw::c_int),
    CustomError(String)
}
