//! This module contains BPF high-level maps api that can
//! be executed on userspace side.

use crate::error::{Error, Result};
use crate::libbpf;
use crate::libbpf::{BpfMapDef, BpfMapFd, BpfMapInfo, BpfMapType, BpfObject, BpfUpdateElemFlags};
use crate::map_layout::*;
use duplicate::duplicate;
use duplicate::duplicate_inline;
use maybe_uninit::MaybeUninit;

/// This trait is implemented by all the map wrapper types, as
/// as convenient way to communicate their underlying types to the
/// Rust type system.
pub trait Map {
    type Key;
    type Value;
    type Layout: MapLayout<Self::Value>;

    fn fd(&self) -> &BpfMapFd<Self::Key, Self::Value, Self::Layout>;
}

pub trait Update: Map {
    /// Update a value inside the map.
    ///
    /// This operation is considered as atomic.
    fn update<'a>(
        &'a mut self,
        key: &Self::Key,
        value: &<<Self as Map>::Layout as MapLayout<Self::Value>>::Buffer,
        flags: BpfUpdateElemFlags,
    ) -> Result<()> {
        libbpf::bpf_map_update_elem(&self.fd(), key, value, flags)
    }
}
pub trait Lookup: Map {
    /// Lookup the map content associated with the given key.
    ///
    /// Note that the return value is a mere copy of said content.
    fn lookup(
        &self,
        key: &Self::Key,
    ) -> Option<<<Self as Map>::Layout as MapLayout<Self::Value>>::Buffer> {
        let mut buffer = Self::Layout::allocate_write();
        libbpf::bpf_map_lookup_elem(&self.fd(), key, &mut buffer)
            .map(|_| unsafe { Self::Layout::transmute(buffer) })
    }
}

macro_rules! map_impl {
    ($type_const:expr) => {
        pub fn from_obj(bpf_obj: &BpfObject, map_name: &str) -> Result<Self> {
            let fd = extract_map_fd(bpf_obj, map_name)?;
            Ok(Self { fd })
        }
        pub fn extract_info(&self) -> Result<BpfMapInfo> {
            extract_checked_info(&self.fd, $type_const)
        }
    };
}

fn extract_map_fd<K, V, L: MapLayout<V>>(
    bpf_obj: &BpfObject,
    map_name: &str,
) -> Result<BpfMapFd<K, V, L>> {
    let bpf_map = libbpf::bpf_object__find_map_by_name(bpf_obj, map_name)?;
    libbpf::bpf_map__fd(&bpf_map)
}

fn extract_checked_info<K, V, L: MapLayout<V>>(
    map_fd: &BpfMapFd<K, V, L>,
    map_type: BpfMapType,
) -> Result<BpfMapInfo> {
    let info = libbpf::bpf_obj_get_info_by_fd(map_fd)?;
    if info.matches_map_def::<K, V>(&BpfMapDef::new(map_type, 0)) {
        Ok(info)
    } else {
        Err(Error::Custom(
            "The wrapper type doesn't match the map object".to_owned(),
        ))
    }
}
/*
#[duplicate(
    [
        map_type    [ CpuMap ]
        key         [ u32 ]
        value       [ u32 ]
        map_layout  [ ScalarLayout ]
    ]
)]
pub struct map_type {
    fd: BpfMapFd<key, value, map_layout>,
}
*/
//  [Array<T>]  [u32]  [T]  [ScalarLayout]


// #[duplicate(
//   map_type            key      value    map_layout;     
//   [ CpuMap ]          [ u32 ]  [ u32 ]  [ ScalarLayout ];
//   [ Array<T> ]        [ u32 ]  [ T ]    [ ScalarLayout ];
//   [ PerCpuArray<T> ]  [ u32 ]  [ T ]    [ PerCpuLayout ];
// )]
// pub struct map_type {
//     fd: super::BpfMapFd<key, value, super::map_layout>,
// }

duplicate_inline!{
[
  map_type            generics  key      value    layout            type_const;     
  [ CpuMap ]          [ ]       [ u32 ]  [ u32 ]  [ ScalarLayout ]  [ ];
  [ Array ]           [ T ]     [ u32 ]  [ T ]    [ ScalarLayout ]  [ ];
  [ PerCpuArray ]     [ T ]     [ u32 ]  [ T ]    [ PerCpuLayout ]  [ ];
]
    pub struct map_type<generics> {
        fd: BpfMapFd<key, value, layout>,
    }
    impl<generics> Map for map_type<generics> {
        type Key = key;
        type Value = value;
        type Layout = layout;
        fn fd(&self) -> &BpfMapFd<key, value, layout> {&self.fd}
    }
    impl<generics> map_type<generics> {
       pub fn from_obj(bpf_obj: &BpfObject, map_name: &str) -> Result<Self> {
            let fd = extract_map_fd(bpf_obj, map_name)?;
            Ok(Self { fd })
        }
        pub fn extract_info(&self) -> Result<BpfMapInfo> {
            extract_checked_info(&self.fd, $type_const)
        }
    }
}




macro_rules! map_def {
    ($(#[$outer:meta])*
    struct $map_type:ident < $key:ty, $value:ty, $layout:ty > : $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type<$key, $value> {
            fd: BpfMapFd<$key, $value, $layout>,
        }
        impl<$key, $value> $map_type<$key, $value> { map_impl! {$map_type<$key, $value>: $type_const} }
        impl<$Key, $value> Map for $map_type<$key, $value> {
            type Key = $key;
            type Value = $value;
            type Layout = $layout;
            fn fd(&self) -> &BpfMapFd<$key, $value, $layout> {&self.fd}
        }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident < $value:ident, $layout:ty > : $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type <$value> {
            fd: BpfMapFd<u32, $value, $layout>,
        }
        impl<$value> $map_type<$value> { map_impl!($type_const); }
        impl<$value> Map for $map_type<$value> {
            type Key = u32;
            type Value = $value;
            type Layout = $layout;
            fn fd(&self) -> &BpfMapFd<u32, $value, $layout> {&self.fd}
        }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident < $layout:ty > : $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type {
            fd: BpfMapFd<u32, u32, $layout>,
        }
        impl $map_type { map_impl!($type_const); }
        impl Map for $map_type {
            type Key = u32;
            type Value = u32;
            type Layout = $layout;
            fn fd(&self) -> &BpfMapFd<u32, u32, $layout> {&self.fd}
        }
    };
}

macro_rules! impl_update_gen {
    () => {
        fn update(
            &mut self,
            key: &Self::Key,
            value: &Self::Value,
            flags: BpfUpdateElemFlags,
        ) -> Result<()> {
            libbpf::bpf_map_update_elem(&self.fd, key, value, flags)
        }
    };
}

//map_def!(struct CpuMap <ScalarLayout> : BpfMapType::CPUMAP);
//impl Update for CpuMap {}
//impl Lookup for CpuMap {}

//map_def!(struct Array<T, ScalarLayout>: BpfMapType::ARRAY);
//impl<T> Update for Array<T> {}
//impl<T> Lookup for Array<T> {}

// map_def!(struct PerCpuArray<T, PerCpuLayout>: BpfMapType::PERCPU_ARRAY);
// impl<T> Update for PerCpuArray<T> {}
// impl<T> Lookup for PerCpuArray<T> {}
