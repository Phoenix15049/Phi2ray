//! Kill switch, built on the Windows Filtering Platform (as Windscribe, Mullvad and
//! WireGuard do). While on, every connection is blocked except:
//! - loopback (local proxy ports),
//! - xray and sing-box themselves (they reach the server and route bypassed traffic),
//! - traffic leaving through the VPN adapter (identified by its private address),
//! - DHCP and IPv6 link-local, so the network adapter keeps working,
//! - the local network, when "Bypass local network" is on.
//!
//! The filters live in a *dynamic* WFP session: Windows deletes them as soon as the
//! session closes, including when Phi2ray crashes, so the user can never be locked out.

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

    use rand::Rng;
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    use super::Rules;

    /// The open engine handle (as usize: raw handles are not Send). Closing it removes the filters.
    static ENGINE: Mutex<Option<usize>> = Mutex::new(None);

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
        ENGINE.lock().unwrap().is_some()
    }

    /// Turns the kill switch on, or replaces its rules. The new filters are in place
    /// before the old ones are removed, so there is no unprotected gap.
    pub fn enable(rules: &Rules) -> Result<(), String> {
        let engine = open_engine()?;
        if let Err(e) = unsafe { install(engine, rules) } {
            unsafe { FwpmEngineClose0(engine) };
            return Err(e);
        }
        if let Some(old) = ENGINE.lock().unwrap().replace(engine as usize) {
            unsafe { FwpmEngineClose0(old as HANDLE) };
        }
        Ok(())
    }

    pub fn disable() {
        if let Some(engine) = ENGINE.lock().unwrap().take() {
            unsafe { FwpmEngineClose0(engine as HANDLE) };
        }
    }

    fn open_engine() -> Result<HANDLE, String> {
        let mut name = wide("Phi2ray kill switch");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = name.as_mut_ptr();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = null_mut();
        let code = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), &session, &mut engine) };
        check(code, "open the Windows firewall engine")?;
        Ok(engine)
    }

    unsafe fn install(engine: HANDLE, rules: &Rules) -> Result<(), String> {
        check(FwpmTransactionBegin0(engine, 0), "start a firewall transaction")?;
        match add_filters(engine, rules) {
            Ok(()) => check(FwpmTransactionCommit0(engine), "commit the firewall rules"),
            Err(e) => {
                FwpmTransactionAbort0(engine);
                Err(e)
            }
        }
    }

    unsafe fn add_filters(engine: HANDLE, rules: &Rules) -> Result<(), String> {
        // A fresh sublayer per session, so a new rule set can be installed before the old one is removed.
        let sublayer_key = GUID::from_u128(rand::thread_rng().gen());
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
        let result = add_layer_filters(engine, sublayer_key, rules, &app_ids);
        for mut blob in app_ids {
            FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut c_void);
        }
        result
    }

    unsafe fn add_layer_filters(
        engine: HANDLE,
        sublayer: GUID,
        rules: &Rules,
        app_ids: &[*mut FWP_BYTE_BLOB],
    ) -> Result<(), String> {
        let layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
            (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true),
        ];
        for (layer, v6) in layers {
            let mut f = FilterAdder { engine, layer, sublayer };

            f.add(15, FWP_ACTION_PERMIT, &mut [flags_condition(FWP_CONDITION_FLAG_IS_LOOPBACK)])?;
            for &app in app_ids {
                f.add(14, FWP_ACTION_PERMIT, &mut [blob_condition(FWPM_CONDITION_ALE_APP_ID, app)])?;
            }

            // Traffic from the VPN adapter's own address goes into the tunnel.
            let mut tun_v4 = v4_mask(TUN_V4);
            let mut tun_v6 = v6_mask(TUN_V6);
            let tun = if v6 { v6_condition(FWPM_CONDITION_IP_LOCAL_ADDRESS, &mut tun_v6) } else { v4_condition(FWPM_CONDITION_IP_LOCAL_ADDRESS, &mut tun_v4) };
            f.add(13, FWP_ACTION_PERMIT, &mut [tun])?;

            // DHCP keeps the real adapter's address alive.
            let dhcp_port = if v6 { 546 } else { 68 };
            f.add(12, FWP_ACTION_PERMIT, &mut [
                u8_condition(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP),
                u16_condition(FWPM_CONDITION_IP_LOCAL_PORT, dhcp_port),
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

    struct FilterAdder {
        engine: HANDLE,
        layer: GUID,
        sublayer: GUID,
    }

    impl FilterAdder {
        /// Adds one filter. Higher weights win inside our sublayer; the block-all filter has weight 0.
        unsafe fn add(&mut self, weight: u8, action: FWP_ACTION_TYPE, conditions: &mut [FWPM_FILTER_CONDITION0]) -> Result<(), String> {
            let mut name = wide("Phi2ray kill switch");
            let mut filter: FWPM_FILTER0 = std::mem::zeroed();
            filter.displayData.name = name.as_mut_ptr();
            filter.layerKey = self.layer;
            filter.subLayerKey = self.sublayer;
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
}

pub use imp::{disable, enable, is_active};
