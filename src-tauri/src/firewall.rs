//! Kill switch, built on the Windows Filtering Platform (as Windscribe, Mullvad and
//! WireGuard do). While on, every connection is blocked except:
//! - loopback (local proxy ports),
//! - xray and sing-box themselves (they reach the server and route bypassed traffic), but only
//!   when running with administrator rights as Phi2ray starts them: a copy launched by an
//!   ordinary program doesn't get through,
//! - traffic leaving through the VPN adapter (identified by its private address),
//! - DHCP and IPv6 link-local, so the network adapter keeps working,
//! - the local network, when "Bypass local network" is on.
//!
//! Fail-closed: the filters are not tied to Phi2ray's process, so if it crashes they keep
//! blocking instead of letting traffic out. They are never persistent either: restarting
//! Windows always clears them, so the user can't be locked out for good. On the next start
//! Phi2ray finds them (`recover`) and shows the "blocked" state with reconnect and unblock.
//!
//! Every filter has a fixed, known key, which is how leftovers are found and removed.
//! There are two slots: a new rule set goes into the free slot and is in place before the
//! old slot is removed, so replacing rules never leaves a gap.

use std::path::PathBuf;

pub struct Rules {
    /// Programs allowed to use the real network.
    pub apps: Vec<PathBuf>,
    pub allow_lan: bool,
}

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, OsStr};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::sync::Mutex;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    use super::Rules;

    /// The slot holding the current rules, if the kill switch is on.
    static ACTIVE: Mutex<Option<u8>> = Mutex::new(None);

    /// Fixed keys, the same in every version, so leftovers from any earlier run are found.
    const SUBLAYER_BASE: u128 = 0x7f3c_9a2e_51d4_4b8e_9a61_0c2f_7e4d_0000;
    const FILTER_BASE: u128 = 0x7f3c_9a2e_51d4_4b8e_9a62_0000_0000_0000;
    /// Far more than a rule set uses (about 60), so the keys never run out.
    const MAX_FILTERS: u16 = 1024;

    const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
    const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;

    const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
    const IPPROTO_UDP: u8 = 17;

    // Must match the VPN adapter addresses in tun.rs.
    const TUN_V4: (Ipv4Addr, u8) = (Ipv4Addr::new(172, 19, 0, 0), 30);
    const TUN_V6: (Ipv6Addr, u8) = (Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 0), 126);

    const LAN_V4: [(Ipv4Addr, u8); 6] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(255, 255, 255, 255), 32),
    ];
    const LAN_V6: [(Ipv6Addr, u8); 1] = [(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)];
    /// Link-local and multicast: neighbour discovery and router advertisements.
    const LINK_V6: [(Ipv6Addr, u8); 2] = [
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    ];

    pub fn is_active() -> bool {
        ACTIVE.lock().unwrap().is_some()
    }

    /// Turns the kill switch on, or replaces its rules. The new filters are in place
    /// before the old ones are removed, so there is no unprotected gap.
    pub fn enable(rules: &Rules) -> Result<(), String> {
        let mut active = ACTIVE.lock().unwrap();
        let slot = if *active == Some(0) { 1 } else { 0 };
        let engine = Engine::open()?;
        // Clear whatever an earlier run may have left in the free slot, then fill it.
        engine.transaction(|e| unsafe { remove_slot(e, slot) })?;
        engine.transaction(|e| unsafe { add_filters(e, slot, rules) })?;
        *active = Some(slot);
        // Only now remove the previous rules (or leftovers in the other slot). If that fails
        // they only block more, never less, and the next enable or disable clears them.
        let _ = engine.transaction(|e| unsafe { remove_slot(e, 1 - slot) });
        Ok(())
    }

    /// Removes every rule. If that fails the kill switch stays on, which is the safe side.
    pub fn disable() {
        let mut active = ACTIVE.lock().unwrap();
        let Ok(engine) = Engine::open() else { return };
        let removed = engine.transaction(|e| unsafe {
            remove_slot(e, 0)?;
            remove_slot(e, 1)
        });
        if removed.is_ok() {
            *active = None;
        }
    }

    /// Finds rules left behind by a run that ended without removing them (a crash, or the
    /// process being killed). They stay in place and the kill switch counts as on.
    pub fn recover() -> bool {
        let Ok(engine) = Engine::open() else { return false };
        let found = [1u8, 0].into_iter().find(|&slot| unsafe {
            let mut sublayer: *mut FWPM_SUBLAYER0 = null_mut();
            let exists = FwpmSubLayerGetByKey0(engine.0, &sublayer_key(slot), &mut sublayer) == 0;
            if !sublayer.is_null() {
                FwpmFreeMemory0(&mut sublayer as *mut _ as *mut *mut c_void);
            }
            exists
        });
        *ACTIVE.lock().unwrap() = found;
        found.is_some()
    }

    fn sublayer_key(slot: u8) -> GUID {
        GUID::from_u128(SUBLAYER_BASE | slot as u128)
    }

    fn filter_key(slot: u8, index: u16) -> GUID {
        GUID::from_u128(FILTER_BASE | (slot as u128) << 16 | index as u128)
    }

    /// An open firewall engine, closed when dropped. The session is not dynamic, so closing
    /// it (or the process dying) leaves the filters in place.
    struct Engine(HANDLE);

    impl Engine {
        fn open() -> Result<Self, String> {
            let mut name = wide("Phi2ray kill switch");
            let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            session.displayData.name = name.as_mut_ptr();
            let mut engine: HANDLE = null_mut();
            let code = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), &session, &mut engine) };
            check(code, "open the Windows firewall engine")?;
            Ok(Self(engine))
        }

        /// Runs `work` atomically: all of its changes apply, or none do.
        fn transaction(&self, work: impl FnOnce(HANDLE) -> Result<(), String>) -> Result<(), String> {
            check(unsafe { FwpmTransactionBegin0(self.0, 0) }, "start a firewall transaction")?;
            match work(self.0) {
                Ok(()) => check(unsafe { FwpmTransactionCommit0(self.0) }, "commit the firewall rules"),
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.0) };
                    Err(e)
                }
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.0) };
        }
    }

    /// Deletes a slot's filters and sublayer. A slot's filters are always added in one
    /// transaction with keys numbered from 0, so the first missing key ends the list.
    unsafe fn remove_slot(engine: HANDLE, slot: u8) -> Result<(), String> {
        for index in 0..MAX_FILTERS {
            match FwpmFilterDeleteByKey0(engine, &filter_key(slot, index)) {
                0 => {}
                FWP_E_FILTER_NOT_FOUND => break,
                code => check(code, "remove a firewall rule")?,
            }
        }
        match FwpmSubLayerDeleteByKey0(engine, &sublayer_key(slot)) {
            0 | FWP_E_SUBLAYER_NOT_FOUND => Ok(()),
            code => check(code, "remove the firewall sublayer"),
        }
    }

    unsafe fn add_filters(engine: HANDLE, slot: u8, rules: &Rules) -> Result<(), String> {
        let sublayer_key = sublayer_key(slot);
        let mut name = wide("Phi2ray");
        let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
        sublayer.subLayerKey = sublayer_key;
        sublayer.displayData.name = name.as_mut_ptr();
        sublayer.weight = 0xFFFF;
        check(FwpmSubLayerAdd0(engine, &sublayer, null_mut()), "add the firewall sublayer")?;

        let mut app_ids = Vec::new();
        for app in &rules.apps {
            let path = wide(app.as_os_str());
            let mut blob: *mut FWP_BYTE_BLOB = null_mut();
            check(FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob), "identify a core program")?;
            app_ids.push(blob);
        }
        let result = match ElevatedOnly::new() {
            Ok(mut elevated) => add_layer_filters(engine, slot, rules, &app_ids, &mut elevated.blob),
            Err(e) => Err(e),
        };
        for mut blob in app_ids {
            FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut c_void);
        }
        result
    }

    /// A security descriptor matching processes whose token has Administrators enabled (or that
    /// run as SYSTEM). Elevated processes, like the cores Phi2ray starts, match it; a program
    /// started normally doesn't, since its token holds Administrators for denying only. The same
    /// kind of user condition wireguard-windows puts on its own service.
    struct ElevatedOnly {
        sd: *mut c_void,
        blob: FWP_BYTE_BLOB,
    }

    impl ElevatedOnly {
        fn new() -> Result<Self, String> {
            // CC = FWP_ACTRL_MATCH_FILTER, the right WFP checks for user conditions.
            let sddl = wide("O:BAD:(A;;CCRC;;;BA)(A;;CCRC;;;SY)");
            let mut sd = null_mut();
            let mut size = 0u32;
            let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, &mut size) };
            if ok == 0 || sd.is_null() {
                return Err("Kill switch: couldn't build the administrator-only rule.".into());
            }
            Ok(Self { sd, blob: FWP_BYTE_BLOB { size, data: sd as *mut u8 } })
        }
    }

    impl Drop for ElevatedOnly {
        fn drop(&mut self) {
            unsafe { LocalFree(self.sd as _) };
        }
    }

    unsafe fn add_layer_filters(
        engine: HANDLE,
        slot: u8,
        rules: &Rules,
        app_ids: &[*mut FWP_BYTE_BLOB],
        elevated: &mut FWP_BYTE_BLOB,
    ) -> Result<(), String> {
        let mut next = 0;
        let layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
        ];
        for (layer, v6) in layers {
            let mut f = FilterAdder { engine, layer, slot, next: &mut next };

            f.add(15, FWP_ACTION_PERMIT, &mut [flags_condition(FWP_CONDITION_FLAG_IS_LOOPBACK)])?;
            for &app in app_ids {
                f.add(14, FWP_ACTION_PERMIT, &mut [
                    blob_condition(FWPM_CONDITION_ALE_APP_ID, app),
                    sd_condition(FWPM_CONDITION_ALE_USER_ID, elevated),
                ])?;
            }

            // Traffic from the VPN adapter's own address goes into the tunnel.
            let mut tun_v4 = v4_mask(TUN_V4);
            let mut tun_v6 = v6_mask(TUN_V6);
            let tun = if v6 { v6_condition(FWPM_CONDITION_IP_LOCAL_ADDRESS, &mut tun_v6) } else { v4_condition(FWPM_CONDITION_IP_LOCAL_ADDRESS, &mut tun_v4) };
            f.add(13, FWP_ACTION_PERMIT, &mut [tun])?;

            // DHCP keeps the real adapter's address alive. Both ports must match (client to
            // server), so a program can't slip out just by sending from the DHCP port.
            let (client_port, server_port) = if v6 { (546, 547) } else { (68, 67) };
            f.add(12, FWP_ACTION_PERMIT, &mut [
                u8_condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
                u16_condition(FWPM_CONDITION_IP_LOCAL_PORT, client_port),
                u16_condition(FWPM_CONDITION_IP_REMOTE_PORT, server_port),
            ])?;

            if v6 {
                for net in LINK_V6 {
                    let mut mask = v6_mask(net);
                    f.add(12, FWP_ACTION_PERMIT, &mut [v6_condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut mask)])?;
                }
            }
            if rules.allow_lan {
                if v6 {
                    for net in LAN_V6 {
                        let mut mask = v6_mask(net);
                        f.add(12, FWP_ACTION_PERMIT, &mut [v6_condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut mask)])?;
                    }
                } else {
                    for net in LAN_V4 {
                        let mut mask = v4_mask(net);
                        f.add(12, FWP_ACTION_PERMIT, &mut [v4_condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut mask)])?;
                    }
                }
            }

            f.add(0, FWP_ACTION_BLOCK, &mut [])?;
        }
        Ok(())
    }

    struct FilterAdder<'a> {
        engine: HANDLE,
        layer: GUID,
        slot: u8,
        /// Index of the next filter key in this slot.
        next: &'a mut u16,
    }

    impl FilterAdder<'_> {
        /// Adds one filter. Higher weights win inside our sublayer; the block-all filter has weight 0.
        unsafe fn add(&mut self, weight: u8, action: FWP_ACTION_TYPE, conditions: &mut [FWPM_FILTER_CONDITION0]) -> Result<(), String> {
            let mut name = wide("Phi2ray kill switch");
            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
            filter.displayData.name = name.as_mut_ptr();
            if *self.next >= MAX_FILTERS {
                return Err("Kill switch: too many firewall rules.".into());
            }
            filter.filterKey = filter_key(self.slot, *self.next);
            *self.next += 1;
            filter.layerKey = self.layer;
            filter.subLayerKey = sublayer_key(self.slot);
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = weight;
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = if conditions.is_empty() { null_mut() } else { conditions.as_mut_ptr() };
            filter.action.r#type = action;
            check(FwpmFilterAdd0(self.engine, &filter, null_mut(), null_mut()), "add a firewall rule")
        }
    }

    fn condition(field: GUID, match_type: FWP_MATCH_TYPE, kind: FWP_DATA_TYPE) -> FWPM_FILTER_CONDITION0 {
        let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        c.fieldKey = field;
        c.matchType = match_type;
        c.conditionValue.r#type = kind;
        c
    }

    fn flags_condition(flags: u32) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32);
        c.conditionValue.Anonymous.uint32 = flags;
        c
    }

    fn u8_condition(field: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_UINT8);
        c.conditionValue.Anonymous.uint8 = value;
        c
    }

    fn u16_condition(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_UINT16);
        c.conditionValue.Anonymous.uint16 = value;
        c
    }

    fn blob_condition(field: GUID, blob: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_BYTE_BLOB_TYPE);
        c.conditionValue.Anonymous.byteBlob = blob;
        c
    }

    /// `sd` must outlive the FwpmFilterAdd0 call that uses the condition.
    fn sd_condition(field: GUID, sd: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE);
        c.conditionValue.Anonymous.sd = sd;
        c
    }

    /// `mask` must outlive the FwpmFilterAdd0 call that uses the condition.
    fn v4_condition(field: GUID, mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_V4_ADDR_MASK);
        c.conditionValue.Anonymous.v4AddrMask = mask;
        c
    }

    fn v6_condition(field: GUID, mask: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
        let mut c = condition(field, FWP_MATCH_EQUAL, FWP_V6_ADDR_MASK);
        c.conditionValue.Anonymous.v6AddrMask = mask;
        c
    }

    fn v4_mask((addr, prefix): (Ipv4Addr, u8)) -> FWP_V4_ADDR_AND_MASK {
        // WFP takes IPv4 addresses in host byte order.
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
        FWP_V4_ADDR_AND_MASK { addr: u32::from(addr), mask }
    }

    fn v6_mask((addr, prefix): (Ipv6Addr, u8)) -> FWP_V6_ADDR_AND_MASK {
        FWP_V6_ADDR_AND_MASK { addr: addr.octets(), prefixLength: prefix }
    }

    fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain(Some(0)).collect()
    }

    fn check(code: u32, what: &str) -> Result<(), String> {
        if code == 0 {
            Ok(())
        } else {
            Err(format!("Kill switch: couldn't {what} (error 0x{code:08X})."))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn masks() {
            let m = v4_mask((Ipv4Addr::new(172, 16, 0, 0), 12));
            assert_eq!((m.addr, m.mask), (0xAC10_0000, 0xFFF0_0000));
            assert_eq!(v4_mask((Ipv4Addr::new(255, 255, 255, 255), 32)).mask, u32::MAX);
            assert_eq!(v6_mask(TUN_V6).prefixLength, 126);
        }

        #[test]
        fn administrator_only_descriptor_builds() {
            let elevated = ElevatedOnly::new().unwrap();
            assert!(elevated.blob.size >= 20 && !elevated.blob.data.is_null());
        }

        #[test]
        fn keys_are_distinct_per_slot_and_index() {
            let k = |g: GUID| (g.data1, g.data2, g.data3, g.data4);
            assert_ne!(k(filter_key(0, 1)), k(filter_key(1, 1)));
            assert_ne!(k(filter_key(0, 1)), k(filter_key(0, 2)));
            assert_ne!(k(sublayer_key(0)), k(sublayer_key(1)));
            assert_eq!(k(filter_key(1, 5)), k(GUID::from_u128(FILTER_BASE | 0x1_0005)));
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Rules;

    pub fn is_active() -> bool {
        false
    }

    pub fn enable(_rules: &Rules) -> Result<(), String> {
        Err("The kill switch is only available on Windows for now.".into())
    }

    pub fn disable() {}

    pub fn recover() -> bool {
        false
    }
}

pub use imp::{disable, enable, is_active, recover};
