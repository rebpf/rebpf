use crate::error::{Error, Result};
use crate::libbpf;
use crate::libbpf::{BpfMapDef, BpfMapFd, BpfMapInfo, BpfMapType, BpfObject, BpfUpdateElemFlags};
use crate::maps::*;

pub trait Lookup<Value = <Self as Map>::Value>: Map {
    /// Lookup the map content associated with the given key.
    ///
    /// Note that the return value is a mere copy of said content.
    fn lookup(&self, key: &Self::Key) -> Option<Value>;

    /// Lookup the map content associated with the given key and if key
    /// is found copy content into value and return Some(()).
    fn lookup_ref(&self, key: &Self::Key, value: &mut Value) -> Option<()>;
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

fn extract_map_fd<K, V>(bpf_obj: &BpfObject, map_name: &str) -> Result<BpfMapFd<K, V>> {
    let bpf_map = libbpf::bpf_object__find_map_by_name(bpf_obj, map_name)?;
    libbpf::bpf_map__fd(&bpf_map)
}

fn extract_checked_info<K, V>(map_fd: &BpfMapFd<K, V>, map_type: BpfMapType) -> Result<BpfMapInfo> {
    let info = libbpf::bpf_obj_get_info_by_fd(map_fd)?;
    if info.matches_map_def::<K, V>(&BpfMapDef::new(map_type, 0)) {
        Ok(info)
    } else {
        // Err(Error::Custom(
        //     format!("id:{}, value_size:{}, type:{:?}, key_size:{}",
        //             info.id(), info.value_size(), info.type_(), info.key_size())
        // ))
        Err(Error::Custom(
            "The wrapper type doesn't match the map object".to_owned(),
        ))
    }
}

macro_rules! map_def {
    ($(#[$outer:meta])*
    struct $map_type:ident < $key:ty, $value:ty >: $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type<$key, $value> {
            fd: BpfMapFd<$key, $value>,
        }
        impl<$key, $value> $map_type<$key, $value> { map_impl! {$map_type<$key, $value>: $type_const} }
        impl<$key, $value> Map for $map_type<$key, $value> { type Key = $key; type Value = $value; }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident < $value:ident >: $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type <$value> {
            fd: BpfMapFd<u32, $value>,
        }
        impl<$value> $map_type<$value> { map_impl!($type_const); }
        impl<$value> Map for $map_type<$value> { type Key = u32; type Value = $value; }
    };
    ($(#[$outer:meta])*
    struct $map_type:ident : $type_const:expr) => {
        #[repr(transparent)]
        $(#[$outer])*
        pub struct $map_type {
            fd: BpfMapFd<u32, u32>,
        }
        impl $map_type { map_impl!($type_const); }
        impl Map for $map_type { type Key = u32; type Value = u32; }
    };
}

macro_rules! impl_update {
    ($map_type:ident < $($gen:ident),* > ) => {
        impl<$($gen,)*> Update for $map_type<$($gen,)*> { impl_update_gen!(); }
    };
    ($map_type:ident) => {
        impl Update for $map_type { impl_update_gen!(); }
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

macro_rules! impl_lookup {
    ($map_type:ident < $value:ident > ) => {
        impl<$value: Default> Lookup for $map_type<$value> {
            impl_lookup_gen!();
        }
    };
    ($map_type:ident) => {
        impl Lookup for $map_type {
            impl_lookup_gen!();
        }
    };
}

macro_rules! impl_lookup_gen {
    () => {
        fn lookup(&self, key: &Self::Key) -> Option<Self::Value> {
            let mut value: Self::Value = Default::default();
            libbpf::bpf_map_lookup_elem(&self.fd, key, &mut value).map(move |_| value)
        }

        fn lookup_ref(&self, key: &Self::Key, value: &mut Self::Value) -> Option<()> {
            libbpf::bpf_map_lookup_elem(&self.fd, key, value)
        }
    };
}

map_def!(struct CpuMap: BpfMapType::CPUMAP);
impl_update!(CpuMap);
impl_lookup!(CpuMap);

map_def!(struct Array<T>: BpfMapType::ARRAY);
impl_update!(Array<T>);
impl_lookup!(Array<T>);

pub struct PerCpuArray<T> {
    fd: BpfMapFd<u32, T>,
    num_cpus: usize,
}

impl<T> Map for PerCpuArray<T> {
    type Key = u32;
    type Value = T;
}

impl<T> PerCpuArray<T> {
    pub fn from_obj(bpf_obj: &BpfObject, map_name: &str) -> Result<Self> {
        let fd = extract_map_fd(bpf_obj, map_name)?;
        let num_cpus = libbpf::libbpf_num_possible_cpus()? as usize;
        Ok(Self { fd, num_cpus })
    }
    pub fn extract_info(&self) -> Result<BpfMapInfo> {
        extract_checked_info(&self.fd, BpfMapType::PERCPU_ARRAY)
    }
}

impl<T> Lookup<Vec<T>> for PerCpuArray<T> {
    fn lookup(&self, key: &Self::Key) -> Option<Vec<T>> {
        let mut values: Vec<T> = Vec::with_capacity(self.num_cpus);
        for _i in 0..self.num_cpus {
            values.push(unsafe { std::mem::zeroed() });
        }
        libbpf::unsafe_bpf_map_lookup_elem(&self.fd, key, values.as_mut_ptr()).map(move |_| values)
    }

    fn lookup_ref(&self, key: &Self::Key, value: &mut Vec<T>) -> Option<()> {
        if value.len() < self.num_cpus {
            return None;
        }
        libbpf::unsafe_bpf_map_lookup_elem(&self.fd, key, value.as_mut_ptr())
    }
}
