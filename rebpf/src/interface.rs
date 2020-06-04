use crate::{
    error::{Error, GenericError},
    utils,
};
use libc;
use std::ffi::CString;

pub struct Interface {
    pub(crate) ifindex: u32,
}

impl Interface {
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }
}

fn if_nametoindex(dev: &str) -> Result<u32, Error> {
    let dev_cstring: CString = utils::str_to_cstring(dev)?;
    let ifindex = unsafe { libc::if_nametoindex(dev_cstring.as_ptr()) };
    if ifindex == 0 {
        utils::map_generic_error(GenericError::InvalidInterfaceName(dev.to_owned()))
    } else {
        Ok(ifindex)
    }
}

pub fn get_interface(interface_name: &str) -> Result<Interface, Error> {
    let ifindex = if_nametoindex(interface_name)?;
    Ok(Interface { ifindex })
}
