// This code is released under the
// GNU Lesser General Public License (LGPL), version 3
// https://www.gnu.org/licenses/lgpl-3.0.html
// (c) Lorenzo Vannucci

use crate::error::Error;
use std::ffi::CString; 
use libc;

pub struct Interface {
    pub(crate) ifindex: u32
}

impl Interface {
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }
}

fn if_nametoindex(dev: &str) -> Result<u32, Error> {
    let dev_cstring: CString = crate::str_to_cstring(dev)?;
    let ifindex = unsafe { libc::if_nametoindex(dev_cstring.as_ptr()) };
    if ifindex == 0 {
        Err(Error::InvalidInterfaceName)
    } else {
        Ok(ifindex)
    }
}

pub fn get_interface(interface_name: &str) -> Result<Interface, Error> {
    let ifindex = if_nametoindex(interface_name)?;
    Ok(Interface {
        ifindex
    })
}  
