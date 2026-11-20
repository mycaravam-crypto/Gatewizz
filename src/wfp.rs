//! Windows Filtering Platform filters for the connection firewall (#59). Windows only; changing filters needs an
//! elevated (administrator) process.
//!
//! All of Gatewizz's filters belong to one persistent provider and sit in one persistent sublayer, so they survive a
//! crash or reboot and `remove` can take every one of them away. [`apply`] replaces the whole set inside one WFP
//! transaction: either the new rules are in force, or the old ones still are.
//!
//! Filters are at the ALE connect layers (IPv4 and IPv6), so they decide connection attempts, never read traffic.
//! Block filters clear the action right: a permit in another sublayer (Windows Firewall, other software) cannot
//! override them. Permits stay soft: they only end the evaluation of Gatewizz's own sublayer.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::firewall::Filter;

/// Where a set of filters lives. Tests use their own keys so they never touch an installed rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub provider: u128,
    pub sublayer: u128,
}

/// Gatewizz's provider and sublayer. Fixed: `remove` must find what an older version installed.
pub const KEYS: Keys = Keys {
    provider: 0x5a1f_7c3e_2b9d_4e61_a0c4_6d8e_93f1_0b27,
    sublayer: 0x8e43_d2a6_1f7b_4c95_b3e8_07a1_5c6d_f924,
};

/// A connection attempt WFP dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// The program's path as WFP reports it: a device path (`\device\harddiskvolume3\...\app.exe`), lower case.
    pub app: String,
    pub remote: std::net::IpAddr,
    pub port: u16,
    /// IP protocol number: 6 TCP, 17 UDP.
    pub protocol: u8,
    /// The runtime id of the filter that dropped it.
    pub filter_id: u64,
}

impl Dropped {
    /// The program's file name, for display and for matching rules.
    pub fn program(&self) -> &str {
        crate::firewall::file_name(&self.app)
    }
}

/// An active drop-event subscription; dropping it unsubscribes.
pub struct Subscription {
    /// Held only for its `Drop`, which unsubscribes.
    #[cfg(windows)]
    _inner: sys::Subscription,
}

/// What [`apply`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// WFP filters added (a filter without an address goes to both the IPv4 and the IPv6 layer).
    pub filters: usize,
    /// Program paths that could not be turned into a WFP app ID (missing files); their filters were skipped.
    pub skipped: Vec<String>,
}

#[cfg(windows)]
pub fn apply(keys: Keys, filters: &[Filter]) -> Result<Applied, String> {
    sys::apply(keys, filters)
}

/// Removes every filter, the sublayer and the provider. Returns how many filters were removed.
#[cfg(windows)]
pub fn remove(keys: Keys) -> Result<usize, String> {
    sys::remove(keys)
}

/// How many filters are installed, or `None` when the sublayer is not installed at all.
#[cfg(windows)]
pub fn installed(keys: Keys) -> Result<Option<usize>, String> {
    sys::installed(keys)
}

/// The runtime ids of the installed filters. A drop event names the filter that dropped the connection by this id,
/// which tells Gatewizz's drops from everyone else's. Ids change on every apply.
#[cfg(windows)]
pub fn filter_ids(keys: Keys) -> Result<std::collections::HashSet<u64>, String> {
    sys::filter_ids(keys)
}

/// Delivers every connection WFP drops to `tx` until the returned subscription is dropped. Turns on WFP's net event
/// collection, which Windows keeps in memory only (no disk log). The receiver keeps the drops whose
/// `filter_id` is one of [`filter_ids`].
#[cfg(windows)]
pub fn subscribe_drops(tx: std::sync::mpsc::Sender<Dropped>) -> Result<Subscription, String> {
    sys::subscribe_drops(tx)
}

/// The full paths a program file name stands for: matches on `PATH` and running processes with that name. WFP needs
/// full paths; a program that is neither on `PATH` nor running is not found.
#[cfg(windows)]
pub fn program_paths(name: &str) -> Vec<String> {
    let mut paths: Vec<String> = std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|dir| dir.join(name))
                .filter(|p| p.is_absolute() && p.is_file())
                .map(|p| p.to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    paths.extend(sys::running_images(name));
    let mut seen = std::collections::HashSet::new();
    paths.retain(|p| seen.insert(p.to_ascii_lowercase()));
    paths
}

#[cfg(not(windows))]
pub fn apply(_keys: Keys, _filters: &[Filter]) -> Result<Applied, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn remove(_keys: Keys) -> Result<usize, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn installed(_keys: Keys) -> Result<Option<usize>, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn filter_ids(_keys: Keys) -> Result<std::collections::HashSet<u64>, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn subscribe_drops(_tx: std::sync::mpsc::Sender<Dropped>) -> Result<Subscription, String> {
    Err(UNSUPPORTED.into())
}

#[cfg(not(windows))]
pub fn program_paths(_name: &str) -> Vec<String> {
    Vec::new()
}

#[cfg(not(windows))]
const UNSUPPORTED: &str = "[firewall] the connection firewall runs only on Windows";

#[cfg(windows)]
mod sys {
    use super::{Applied, Keys};
    use crate::firewall::{Filter, Protocol, RuleAction};
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::IpAddr;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE,
        FWP_FILTER_ENUM_OVERLAPPING, FWP_IP_VERSION_V4, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16,
        FWP_UINT32, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK,
        FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWPM_CONDITION_IP_REMOTE_PORT, FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_FILTER_CONDITION0,
        FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT_FLAG_APP_ID_SET,
        FWPM_NET_EVENT_FLAG_IP_VERSION_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
        FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_SUBSCRIPTION0,
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWPM_NET_EVENT1, FWPM_PROVIDER_FLAG_PERSISTENT,
        FWPM_PROVIDER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0,
        FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
        FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FwpmNetEventSubscribe0, FwpmNetEventUnsubscribe0,
        FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
        FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows_sys::core::GUID;

    const LAYERS: [GUID; 2] = [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ];

    /// Above the default sublayer, so Gatewizz's decisions are evaluated early; a hard block wins anyway.
    const SUBLAYER_WEIGHT: u16 = 0x8000;

    /// windows-sys GUIDs have no `PartialEq`.
    fn same(a: &GUID, b: &GUID) -> bool {
        (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    fn hresult(rc: u32) -> i32 {
        rc as i32
    }

    fn check(rc: u32, what: &str) -> Result<(), String> {
        match rc {
            0 => Ok(()),
            // ERROR_ACCESS_DENIED, or E_ACCESSDENIED as an HRESULT.
            5 | 0x8007_0005 => Err(format!(
                "[firewall] cannot {what}: access denied. Run `gatewizz firewall ...` from an elevated \
                 (Run as administrator) prompt"
            )),
            rc => Err(format!("[firewall] cannot {what}: error 0x{rc:08X}")),
        }
    }

    struct Engine(HANDLE);

    impl Engine {
        fn open() -> Result<Self, String> {
            let mut h: HANDLE = null_mut();
            let rc = unsafe {
                FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT as u32, null(), null(), &mut h)
            };
            check(rc, "open the Windows Filtering Platform")?;
            Ok(Self(h))
        }

        /// Runs `f` inside one transaction: committed if it returns Ok, aborted otherwise.
        fn transaction<T>(&self, f: impl FnOnce(&Self) -> Result<T, String>) -> Result<T, String> {
            check(
                unsafe { FwpmTransactionBegin0(self.0, 0) },
                "begin a WFP transaction",
            )?;
            match f(self) {
                Ok(value) => {
                    check(
                        unsafe { FwpmTransactionCommit0(self.0) },
                        "commit the WFP transaction",
                    )?;
                    Ok(value)
                }
                Err(err) => {
                    unsafe { FwpmTransactionAbort0(self.0) };
                    Err(err)
                }
            }
        }

        fn ensure_provider_and_sublayer(&self, keys: Keys) -> Result<(), String> {
            let (name, description) =
                (wide("Gatewizz"), wide("Gatewizz connection firewall (#59)"));
            let mut provider_key = GUID::from_u128(keys.provider);
            let provider = FWPM_PROVIDER0 {
                providerKey: provider_key,
                displayData: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr().cast_mut(),
                    description: description.as_ptr().cast_mut(),
                },
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                ..Default::default()
            };
            let rc = unsafe { FwpmProviderAdd0(self.0, &provider, null_mut()) };
            if hresult(rc) != FWP_E_ALREADY_EXISTS {
                check(rc, "add the Gatewizz WFP provider")?;
            }
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: GUID::from_u128(keys.sublayer),
                displayData: provider.displayData,
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey: &mut provider_key,
                weight: SUBLAYER_WEIGHT,
                ..Default::default()
            };
            let rc = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, null_mut()) };
            if hresult(rc) != FWP_E_ALREADY_EXISTS {
                check(rc, "add the Gatewizz WFP sublayer")?;
            }
            Ok(())
        }

        /// Keys of every filter of this provider in this sublayer, on both connect layers.
        fn filter_keys(&self, keys: Keys) -> Result<Vec<GUID>, String> {
            Ok(self
                .filters(keys)?
                .into_iter()
                .map(|(key, _)| key)
                .collect())
        }

        /// (key, runtime id) of every filter of this provider in this sublayer, on both connect layers.
        fn filters(&self, keys: Keys) -> Result<Vec<(GUID, u64)>, String> {
            let mut out = Vec::new();
            let mut provider = GUID::from_u128(keys.provider);
            let sublayer = GUID::from_u128(keys.sublayer);
            for layer in LAYERS {
                let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                    providerKey: &mut provider,
                    layerKey: layer,
                    enumType: FWP_FILTER_ENUM_OVERLAPPING,
                    actionMask: 0xFFFF_FFFF,
                    ..Default::default()
                };
                let mut handle: HANDLE = null_mut();
                check(
                    unsafe { FwpmFilterCreateEnumHandle0(self.0, &template, &mut handle) },
                    "list the Gatewizz WFP filters",
                )?;
                let listed: Result<(), String> = (|| {
                    loop {
                        let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
                        let mut n = 0u32;
                        check(
                            unsafe { FwpmFilterEnum0(self.0, handle, 64, &mut entries, &mut n) },
                            "list the Gatewizz WFP filters",
                        )?;
                        for i in 0..n as usize {
                            let filter = unsafe { &**entries.add(i) };
                            if same(&filter.subLayerKey, &sublayer) {
                                out.push((filter.filterKey, filter.filterId));
                            }
                        }
                        if !entries.is_null() {
                            unsafe {
                                FwpmFreeMemory0(
                                    (&mut entries as *mut *mut *mut FWPM_FILTER0).cast(),
                                )
                            };
                        }
                        if n < 64 {
                            return Ok(());
                        }
                    }
                })();
                unsafe { FwpmFilterDestroyEnumHandle0(self.0, handle) };
                listed?;
            }
            Ok(out)
        }

        fn delete_filters(&self, keys: Keys) -> Result<usize, String> {
            let found = self.filter_keys(keys)?;
            for key in &found {
                let rc = unsafe { FwpmFilterDeleteByKey0(self.0, key) };
                if hresult(rc) != FWP_E_FILTER_NOT_FOUND {
                    check(rc, "delete a Gatewizz WFP filter")?;
                }
            }
            Ok(found.len())
        }

        fn add_filter(
            &self,
            keys: Keys,
            layer: GUID,
            f: &Filter,
            app: Option<&mut FWP_BYTE_BLOB>,
        ) -> Result<(), String> {
            let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
            let mut condition = |field: GUID, value: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0| {
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: field,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: value,
                });
            };
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
                FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0,
            };
            if let Some(blob) = app {
                condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                    },
                );
            }
            // Kept alive until FwpmFilterAdd0 returns: the conditions point at them.
            let mut v4 = FWP_V4_ADDR_AND_MASK::default();
            let mut v6 = FWP_V6_ADDR_AND_MASK::default();
            if let Some(net) = f.remote {
                match net.addr {
                    IpAddr::V4(addr) => {
                        v4.addr = u32::from(addr);
                        v4.mask = if net.len == 0 {
                            0
                        } else {
                            u32::MAX << (32 - u32::from(net.len))
                        };
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_CONDITION_VALUE0 {
                                r#type: FWP_V4_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: &mut v4,
                                },
                            },
                        );
                    }
                    IpAddr::V6(addr) => {
                        v6.addr = addr.octets();
                        v6.prefixLength = net.len;
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_CONDITION_VALUE0 {
                                r#type: FWP_V6_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v6AddrMask: &mut v6,
                                },
                            },
                        );
                    }
                }
            }
            if let Some(port) = f.port {
                condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                    },
                );
            }
            let protocol = match f.protocol {
                Protocol::Any => None,
                Protocol::Tcp => Some(6u8),
                Protocol::Udp => Some(17u8),
            };
            if let Some(p) = protocol {
                condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: p },
                    },
                );
            }
            let name = wide(&format!("Gatewizz: {}", f.rule));
            let mut provider = GUID::from_u128(keys.provider);
            let mut weight = f.weight;
            let block = f.action == RuleAction::Block;
            use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
                FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_DISPLAY_DATA0,
            };
            let filter = FWPM_FILTER0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr().cast_mut(),
                    description: null_mut(),
                },
                flags: FWPM_FILTER_FLAG_PERSISTENT
                    | if block {
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
                    } else {
                        0
                    },
                providerKey: &mut provider,
                layerKey: layer,
                subLayerKey: GUID::from_u128(keys.sublayer),
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_VALUE0_0 {
                        uint64: &mut weight,
                    },
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: conditions.as_mut_ptr(),
                action: FWPM_ACTION0 {
                    r#type: if block {
                        FWP_ACTION_BLOCK
                    } else {
                        FWP_ACTION_PERMIT
                    },
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut id = 0u64;
            check(
                unsafe { FwpmFilterAdd0(self.0, &filter, null_mut(), &mut id) },
                &format!("add the WFP filter for rule {:?}", f.rule),
            )
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.0) };
        }
    }

    /// A WFP app ID for an executable path, freed on drop.
    struct AppId(*mut FWP_BYTE_BLOB);

    impl AppId {
        fn of(path: &str) -> Option<Self> {
            let mut blob: *mut FWP_BYTE_BLOB = null_mut();
            let rc = unsafe { FwpmGetAppIdFromFileName0(wide(path).as_ptr(), &mut blob) };
            (rc == 0 && !blob.is_null()).then_some(Self(blob))
        }
    }

    impl Drop for AppId {
        fn drop(&mut self) {
            unsafe {
                FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast::<*mut c_void>())
            };
        }
    }

    pub fn apply(keys: Keys, filters: &[Filter]) -> Result<Applied, String> {
        let engine = Engine::open()?;
        let mut apps: HashMap<String, Option<AppId>> = HashMap::new();
        let mut applied = Applied::default();
        engine.transaction(|e| {
            e.ensure_provider_and_sublayer(keys)?;
            e.delete_filters(keys)?;
            for f in filters {
                let app = match &f.program {
                    None => None,
                    Some(path) => {
                        let id = apps
                            .entry(path.to_ascii_lowercase())
                            .or_insert_with(|| AppId::of(path));
                        match id {
                            Some(id) => Some(id.0),
                            None => {
                                // Skipping an allow narrows access; skipping a block widens it. Either way say so.
                                if !applied.skipped.contains(path) {
                                    applied.skipped.push(path.clone());
                                }
                                continue;
                            }
                        }
                    }
                };
                let layers: &[GUID] = match f.remote.map(|n| n.addr) {
                    None => &LAYERS,
                    Some(IpAddr::V4(_)) => &LAYERS[..1],
                    Some(IpAddr::V6(_)) => &LAYERS[1..],
                };
                for layer in layers {
                    e.add_filter(keys, *layer, f, app.map(|p| unsafe { &mut *p }))?;
                    applied.filters += 1;
                }
            }
            Ok(())
        })?;
        Ok(applied)
    }

    pub fn remove(keys: Keys) -> Result<usize, String> {
        let engine = Engine::open()?;
        engine.transaction(|e| {
            let removed = e.delete_filters(keys)?;
            let rc = unsafe { FwpmSubLayerDeleteByKey0(e.0, &GUID::from_u128(keys.sublayer)) };
            if hresult(rc) != FWP_E_SUBLAYER_NOT_FOUND {
                check(rc, "delete the Gatewizz WFP sublayer")?;
            }
            let rc = unsafe { FwpmProviderDeleteByKey0(e.0, &GUID::from_u128(keys.provider)) };
            if hresult(rc) != FWP_E_PROVIDER_NOT_FOUND {
                check(rc, "delete the Gatewizz WFP provider")?;
            }
            Ok(removed)
        })
    }

    pub fn filter_ids(keys: Keys) -> Result<std::collections::HashSet<u64>, String> {
        let engine = Engine::open()?;
        Ok(engine
            .filters(keys)?
            .into_iter()
            .map(|(_, id)| id)
            .collect())
    }

    /// Keeps the engine session and the callback's sender alive for as long as the subscription runs.
    pub struct Subscription {
        engine: Engine,
        handle: HANDLE,
        sender: *mut std::sync::Mutex<std::sync::mpsc::Sender<super::Dropped>>,
    }

    // The raw sender pointer is only dereferenced by the callback, behind its mutex, and freed after unsubscribing.
    unsafe impl Send for Subscription {}

    impl Drop for Subscription {
        fn drop(&mut self) {
            // Unsubscribe waits for running callbacks, so the sender is unused once it returns.
            unsafe { FwpmNetEventUnsubscribe0(self.engine.0, self.handle) };
            drop(unsafe { Box::from_raw(self.sender) });
        }
    }

    unsafe extern "system" fn on_event(context: *mut c_void, event: *const FWPM_NET_EVENT1) {
        let (Some(event), false) = (unsafe { event.as_ref() }, context.is_null()) else {
            return;
        };
        if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
            return;
        }
        let drop_info = unsafe { event.Anonymous.classifyDrop };
        let Some(drop_info) = (unsafe { drop_info.as_ref() }) else {
            return;
        };
        let h = &event.header;
        let needed = FWPM_NET_EVENT_FLAG_APP_ID_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET
            | FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET
            | FWPM_NET_EVENT_FLAG_IP_VERSION_SET;
        if h.flags & needed != needed || h.appId.data.is_null() {
            return;
        }
        let remote = if h.ipVersion == FWP_IP_VERSION_V4 {
            IpAddr::from(std::net::Ipv4Addr::from(unsafe {
                h.Anonymous2.remoteAddrV4
            }))
        } else {
            IpAddr::from(unsafe { h.Anonymous2.remoteAddrV6.byteArray16 })
        };
        // The app id is a NUL-terminated UTF-16 device path.
        let words = unsafe {
            std::slice::from_raw_parts(h.appId.data.cast::<u16>(), h.appId.size as usize / 2)
        };
        let end = words.iter().position(|&w| w == 0).unwrap_or(words.len());
        let dropped = super::Dropped {
            app: String::from_utf16_lossy(&words[..end]).to_lowercase(),
            remote,
            port: h.remotePort,
            protocol: h.ipProtocol,
            filter_id: drop_info.filterId,
        };
        let sender = unsafe {
            &*context.cast::<std::sync::Mutex<std::sync::mpsc::Sender<super::Dropped>>>()
        };
        if let Ok(tx) = sender.lock() {
            let _ = tx.send(dropped);
        }
    }

    pub fn subscribe_drops(
        tx: std::sync::mpsc::Sender<super::Dropped>,
    ) -> Result<super::Subscription, String> {
        let engine = Engine::open()?;
        let value = FWP_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_VALUE0_0 { uint32: 1 },
        };
        check(
            unsafe { FwpmEngineSetOption0(engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &value) },
            "turn on WFP net event collection",
        )?;
        let sender = Box::into_raw(Box::new(std::sync::Mutex::new(tx)));
        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0::default();
        let mut handle: HANDLE = null_mut();
        let rc = unsafe {
            FwpmNetEventSubscribe0(
                engine.0,
                &subscription,
                Some(on_event),
                sender.cast_const().cast(),
                &mut handle,
            )
        };
        if let Err(err) = check(rc, "subscribe to WFP drop events") {
            drop(unsafe { Box::from_raw(sender) });
            return Err(err);
        }
        Ok(super::Subscription {
            _inner: Subscription {
                engine,
                handle,
                sender,
            },
        })
    }

    pub fn installed(keys: Keys) -> Result<Option<usize>, String> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWPM_SUBLAYER0 as Sublayer, FwpmSubLayerGetByKey0,
        };
        let engine = Engine::open()?;
        let mut found: *mut Sublayer = null_mut();
        let rc =
            unsafe { FwpmSubLayerGetByKey0(engine.0, &GUID::from_u128(keys.sublayer), &mut found) };
        if hresult(rc) == FWP_E_SUBLAYER_NOT_FOUND {
            return Ok(None);
        }
        check(rc, "read the Gatewizz WFP sublayer")?;
        unsafe { FwpmFreeMemory0((&mut found as *mut *mut Sublayer).cast()) };
        Ok(Some(engine.filter_keys(keys)?.len()))
    }

    /// Full image paths of running processes whose file name is `name`.
    pub fn running_images(name: &str) -> Vec<String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
        while more {
            let len = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            if String::from_utf16_lossy(&entry.szExeFile[..len]).eq_ignore_ascii_case(name)
                && let Some(path) = image(entry.th32ProcessID)
            {
                out.push(path);
            }
            more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
        }
        unsafe { CloseHandle(snapshot) };
        out
    }

    fn image(pid: u32) -> Option<String> {
        let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        unsafe { CloseHandle(h) };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::firewall::{DefaultAction, Rule, plan};
    use std::net::{IpAddr, ToSocketAddrs};
    use std::time::SystemTime;

    /// Separate keys, so the test never touches an installed rule set.
    const TEST_KEYS: Keys = Keys {
        provider: 0x0f3b_9a52_6c1e_4d87_9e20_b4a7_c31d_5e68,
        sublayer: 0x7d64_e1b9_3a2c_4f05_8b6e_d9c0_2a71_4f33,
    };

    /// Removes the test filters even when an assertion fails.
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = remove(TEST_KEYS);
        }
    }

    fn powershell() -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
    }

    /// Exit code of a child PowerShell that opens a TCP connection to `ip:80`: 0 connected, 3 refused or blocked.
    fn child_connects(ip: IpAddr) -> i32 {
        let script = format!(
            "$c = New-Object Net.Sockets.TcpClient; try {{ $c.Connect('{ip}', 80); exit 0 }} catch {{ exit 3 }}"
        );
        std::process::Command::new(powershell())
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .unwrap()
            .code()
            .unwrap_or(-1)
    }

    /// The acceptance test from #59: a block filter for one program and address stops that program's connection;
    /// removing the filters lets it through again and leaves nothing behind. Needs an elevated process, which
    /// GitHub's Windows runners are. Elsewhere (a developer's normal prompt) it says so and does nothing, but in CI
    /// a missing elevation is a failure.
    #[test]
    fn blocks_a_child_process_connection_and_removes_cleanly() {
        if let Err(err) = installed(TEST_KEYS) {
            assert!(
                std::env::var_os("CI").is_none(),
                "WFP unavailable in CI: {err}"
            );
            eprintln!("skipped, needs an elevated prompt: {err}");
            return;
        }
        let ip = ("example.com", 80)
            .to_socket_addrs()
            .unwrap()
            .map(|a| a.ip())
            .find(IpAddr::is_ipv4)
            .expect("example.com has an IPv4 address");
        assert_eq!(
            child_connects(ip),
            0,
            "baseline: the child must reach {ip}:80"
        );

        let _cleanup = Cleanup;
        let rules: Vec<Rule> = toml::from_str::<std::collections::HashMap<String, Vec<Rule>>>(&format!(
            "connection_rules = [{{ id = \"test-block\", process = [{:?}], ip = [\"{ip}\"], port = [80], protocol = \"tcp\", action = \"block\" }}]",
            powershell()
        ))
        .unwrap()
        .remove("connection_rules")
        .unwrap();
        let own = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let filters = plan(
            &rules,
            DefaultAction::Allow,
            &[own],
            SystemTime::now(),
            |_| Vec::new(),
            |_| Vec::new(),
        );
        let applied = apply(TEST_KEYS, &filters).unwrap();
        assert!(applied.skipped.is_empty(), "{:?}", applied.skipped);
        // The self allow goes to both layers; the block only to IPv4.
        assert_eq!(applied.filters, 3);
        assert_eq!(installed(TEST_KEYS).unwrap(), Some(3));
        // Watch for the drop the blocked connect causes.
        let (tx, rx) = std::sync::mpsc::channel();
        let subscription = subscribe_drops(tx).unwrap();
        assert_eq!(
            child_connects(ip),
            3,
            "the block filter must stop the child"
        );
        // The drop event names the child's program, the address and port, and one of the test's own filters.
        let ours = filter_ids(TEST_KEYS).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut seen = Vec::new();
        let found = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left) {
                Ok(d) if d.remote == ip && d.port == 80 && ours.contains(&d.filter_id) => {
                    break Some(d);
                }
                Ok(other) => seen.push(other),
                Err(_) => break None,
            }
        };
        drop(subscription);
        let found = found.unwrap_or_else(|| {
            panic!("no drop event by our filter for {ip}:80 within 15 s; other drops: {seen:?}")
        });
        assert_eq!(found.program(), "powershell.exe", "{found:?}");
        assert_eq!(found.protocol, 6);

        // Applying again replaces, never duplicates.
        assert_eq!(apply(TEST_KEYS, &filters).unwrap().filters, 3);
        assert_eq!(installed(TEST_KEYS).unwrap(), Some(3));

        assert_eq!(remove(TEST_KEYS).unwrap(), 3);
        assert_eq!(
            installed(TEST_KEYS).unwrap(),
            None,
            "nothing may be left behind"
        );
        assert_eq!(remove(TEST_KEYS).unwrap(), 0, "remove is idempotent");
        assert_eq!(
            child_connects(ip),
            0,
            "without the filter the child connects again"
        );
    }

    #[test]
    fn finds_running_programs_by_file_name() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().into_owned();
        let paths = program_paths(&name);
        assert!(
            paths
                .iter()
                .any(|p| p.eq_ignore_ascii_case(&me.to_string_lossy())),
            "{name} -> {paths:?}"
        );
    }
}
