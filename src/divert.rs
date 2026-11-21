//! WinDivert 2.2 (#60): the packet driver that lets the firewall service hold a new connection while the user
//! decides. Windows only; the pure parts are tested on every OS.
//!
//! WinDivert is not linked: `WinDivert.dll` is loaded by full path, and only after it and `WinDivert64.sys` match the
//! SHA-256 of the pinned release (2.2.2-A). A changed, missing or quarantined file means no holding, never a load of
//! something else. WinDivert is LGPL v3 / GPL v2 and ships unmodified, with its licence, next to Gatewizz.
#![cfg_attr(not(windows), allow(dead_code))]

/// The WinDivert files Gatewizz loads, with the SHA-256 of the x64 builds in `WinDivert-2.2.2-A.zip` (whose own
/// SHA-256 is `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`).
pub const FILES: [(&str, &str); 2] = [
    (
        "WinDivert.dll",
        "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    ),
    (
        "WinDivert64.sys",
        "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
    ),
];

/// Lower-case hex, as `FILES` writes digests.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The filter for holding: the SYN of every new outbound TCP connection, never loopback, never packets another
/// driver injected (they were decided already). Narrower filters are for tests.
pub const HOLD_FILTER: &str = "outbound and !loopback and !impostor and tcp.Syn and !tcp.Ack";

/// `WINDIVERT_MTU_MAX`: the largest packet WinDivert hands out, an IPv6 header (40 bytes) and the largest payload
/// its 16-bit length field allows.
pub const MTU_MAX: usize = 40 + u16::MAX as usize;

/// `WINDIVERT_ADDRESS` (80 bytes): where a packet came from and how to send it on.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    /// Bit fields, lowest first: Layer (8), Event (8), Sniffed, Outbound, Loopback, Impostor, IPv6, IPChecksum,
    /// TCPChecksum, UDPChecksum.
    bits: u32,
    reserved: u32,
    /// The layer's data; for the network layer, the interface and sub-interface index.
    data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

const OUTBOUND: u32 = 1 << 17;
#[cfg(test)]
const LOOPBACK: u32 = 1 << 18;
const IMPOSTOR: u32 = 1 << 19;
#[cfg(test)]
const IPV6: u32 = 1 << 20;
const CHECKSUMS: u32 = (1 << 21) | (1 << 22) | (1 << 23);

impl Address {
    #[cfg(test)]
    pub fn outbound(&self) -> bool {
        self.bits & OUTBOUND != 0
    }

    #[cfg(test)]
    pub fn loopback(&self) -> bool {
        self.bits & LOOPBACK != 0
    }

    #[cfg(test)]
    pub fn ipv6(&self) -> bool {
        self.bits & IPV6 != 0
    }

    /// The address for a RST back to the app that sent the packet this address came with: same interface, inbound,
    /// not an impostor, checksums valid (`hold::rst_for` computes them).
    pub fn reply(&self) -> Self {
        Self {
            bits: (self.bits & !(OUTBOUND | IMPOSTOR)) | CHECKSUMS,
            ..*self
        }
    }
}

#[cfg(windows)]
pub use sys::{Divert, verify};

#[cfg(windows)]
mod sys {
    use super::{Address, FILES, hex};
    use std::ffi::c_void;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        FreeLibrary, GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
    };

    /// What `GetProcAddress` returns.
    type Proc = unsafe extern "system" fn() -> isize;
    type Open = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
    type Recv = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
    type Send = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
    type Shutdown = unsafe extern "C" fn(HANDLE, i32) -> i32;
    type Close = unsafe extern "C" fn(HANDLE) -> i32;

    const LAYER_NETWORK: i32 = 0;
    const SHUTDOWN_BOTH: i32 = 3;

    /// An open WinDivert handle on the network layer. Packets that match its filter are taken off the wire and
    /// handed to [`Divert::recv`]; [`Divert::send`] puts packets back.
    pub struct Divert {
        module: HMODULE,
        handle: HANDLE,
        recv: Recv,
        send: Send,
        shutdown: Shutdown,
        close: Close,
    }

    // The handle is a kernel object handle; WinDivert allows Recv, Send and Shutdown from different threads.
    unsafe impl std::marker::Send for Divert {}
    unsafe impl Sync for Divert {}

    fn sha256(bytes: &[u8]) -> Result<[u8; 32], String> {
        let mut out = [0u8; 32];
        let status = unsafe {
            BCryptHash(
                BCRYPT_SHA256_ALG_HANDLE,
                std::ptr::null(),
                0,
                bytes.as_ptr(),
                bytes.len() as u32,
                out.as_mut_ptr(),
                out.len() as u32,
            )
        };
        if status != 0 {
            return Err(format!("[firewall] SHA-256 failed: status {status:#x}"));
        }
        Ok(out)
    }

    /// Checks both WinDivert files in `dir` against the pinned digests.
    pub fn verify(dir: &Path) -> Result<(), String> {
        for (name, expected) in FILES {
            let path = dir.join(name);
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("[firewall] cannot read {}: {e}", path.display()))?;
            let actual = hex(&sha256(&bytes)?);
            if actual != expected {
                return Err(format!(
                    "[firewall] {} is not the pinned WinDivert 2.2.2-A build (SHA-256 {actual}); it is not loaded",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    impl Divert {
        /// Verifies and loads WinDivert from `dir`, which installs and starts its driver if needed (administrator
        /// rights), and opens a network-layer handle for `filter` at `priority`.
        pub fn open(dir: &Path, filter: &str, priority: i16) -> Result<Self, String> {
            verify(dir)?;
            let dll: Vec<u16> = dir.join(FILES[0].0).as_os_str().encode_wide_nul();
            let module = unsafe {
                LoadLibraryExW(
                    dll.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_WITH_ALTERED_SEARCH_PATH,
                )
            };
            if module.is_null() {
                return Err(format!(
                    "[firewall] cannot load WinDivert.dll: error {}",
                    unsafe { GetLastError() }
                ));
            }
            let symbol =
                |name: &std::ffi::CStr| unsafe { GetProcAddress(module, name.as_ptr().cast()) };
            let found = (
                symbol(c"WinDivertOpen"),
                symbol(c"WinDivertRecv"),
                symbol(c"WinDivertSend"),
                symbol(c"WinDivertShutdown"),
                symbol(c"WinDivertClose"),
            );
            let (Some(open), Some(recv), Some(send), Some(shutdown), Some(close)) = found else {
                unsafe { FreeLibrary(module) };
                return Err("[firewall] WinDivert.dll lacks an expected function".into());
            };
            // SAFETY: the addresses come from the verified WinDivert 2.2 DLL, whose exports have these signatures
            // (windivert.h).
            let (open, recv, send, shutdown, close) = unsafe {
                (
                    std::mem::transmute::<Proc, Open>(open),
                    std::mem::transmute::<Proc, Recv>(recv),
                    std::mem::transmute::<Proc, Send>(send),
                    std::mem::transmute::<Proc, Shutdown>(shutdown),
                    std::mem::transmute::<Proc, Close>(close),
                )
            };
            let filter = std::ffi::CString::new(filter)
                .map_err(|_| "[firewall] a WinDivert filter cannot contain NUL".to_string())?;
            let handle = unsafe { open(filter.as_ptr().cast(), LAYER_NETWORK, priority, 0) };
            if handle == INVALID_HANDLE_VALUE {
                let error = unsafe { GetLastError() };
                unsafe { FreeLibrary(module) };
                return Err(format!(
                    "[firewall] cannot open WinDivert: error {error}{}",
                    match error {
                        5 => " (needs administrator rights)",
                        577 | 1275 =>
                            " (Windows refused the driver; see its signature and Defender)",
                        87 => " (bad filter)",
                        _ => "",
                    }
                ));
            }
            Ok(Self {
                module,
                handle,
                recv,
                send,
                shutdown,
                close,
            })
        }

        /// Waits for the next packet matching the filter; `None` after [`Divert::stop`].
        pub fn recv(&self, buf: &mut [u8]) -> Option<(usize, Address)> {
            let mut len = 0u32;
            let mut address = Address::default();
            let ok = unsafe {
                (self.recv)(
                    self.handle,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut len,
                    &mut address,
                )
            };
            (ok != 0).then_some((len as usize, address))
        }

        /// Sends a packet: a held one back on its way, or a RST to the app.
        pub fn send(&self, packet: &[u8], address: &Address) -> Result<(), String> {
            let ok = unsafe {
                (self.send)(
                    self.handle,
                    packet.as_ptr().cast(),
                    packet.len() as u32,
                    std::ptr::null_mut(),
                    address,
                )
            };
            if ok == 0 {
                return Err(format!(
                    "[firewall] WinDivert could not send a packet: error {}",
                    unsafe { GetLastError() }
                ));
            }
            Ok(())
        }

        /// Ends a [`Divert::recv`] waiting on another thread. Packets not yet received are dropped, so held
        /// connections must be answered before.
        pub fn stop(&self) {
            unsafe { (self.shutdown)(self.handle, SHUTDOWN_BOTH) };
        }
    }

    impl Drop for Divert {
        fn drop(&mut self) {
            unsafe {
                (self.close)(self.handle);
                FreeLibrary(self.module);
            }
        }
    }

    trait WideNul {
        fn encode_wide_nul(&self) -> Vec<u16>;
    }

    impl WideNul for std::ffi::OsStr {
        fn encode_wide_nul(&self) -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            self.encode_wide().chain([0]).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_has_windiverts_layout() {
        assert_eq!(size_of::<Address>(), 80);
        let captured = Address {
            bits: OUTBOUND | IMPOSTOR | IPV6,
            ..Default::default()
        };
        assert!(captured.outbound() && captured.ipv6() && !captured.loopback());
        let reply = captured.reply();
        assert!(!reply.outbound(), "a RST to the app is inbound");
        assert_eq!(reply.bits & IMPOSTOR, 0);
        assert_eq!(reply.bits & CHECKSUMS, CHECKSUMS);
        assert!(reply.ipv6(), "the family is kept");
        assert_eq!(hex(&[0x00, 0xab, 0x10]), "00ab10");
        assert!(FILES.iter().all(|(_, digest)| digest.len() == 64));
    }

    /// The pinned digests refuse anything else: a missing file, and a file with other bytes.
    #[cfg(windows)]
    #[test]
    fn only_the_pinned_windivert_files_pass() {
        let dir = std::env::temp_dir().join(format!("gatewizz-divert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = verify(&dir).unwrap_err();
        assert!(
            missing.contains("cannot read") && missing.contains("WinDivert.dll"),
            "{missing}"
        );
        for (name, _) in FILES {
            std::fs::write(dir.join(name), b"not the driver").unwrap();
        }
        let wrong = verify(&dir).unwrap_err();
        assert!(
            wrong.contains("is not the pinned WinDivert 2.2.2-A build"),
            "{wrong}"
        );
        // Divert::open checks first, so a wrong file is never loaded.
        let refused = Divert::open(&dir, HOLD_FILTER, 0).err().unwrap();
        assert!(refused.contains("not the pinned"), "{refused}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The elevated Windows CI test from #60: a connection is held, then released or refused. Needs the WinDivert
    /// files in `GATEWIZZ_WINDIVERT_DIR` (the CI job downloads and verifies the pinned release) and administrator
    /// rights, which GitHub's Windows runners have.
    #[cfg(windows)]
    #[test]
    fn a_held_connect_completes_after_release_and_is_refused_after_a_reset() {
        use crate::hold;
        use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
        use std::time::{Duration, Instant};

        let Some(dir) = std::env::var_os("GATEWIZZ_WINDIVERT_DIR") else {
            assert!(
                std::env::var_os("CI").is_none(),
                "CI must set GATEWIZZ_WINDIVERT_DIR"
            );
            eprintln!("skipped: set GATEWIZZ_WINDIVERT_DIR to the WinDivert 2.2.2-A x64 directory");
            return;
        };
        let ip: IpAddr = ("example.com", 80)
            .to_socket_addrs()
            .unwrap()
            .map(|a| a.ip())
            .find(IpAddr::is_ipv4)
            .expect("example.com has an IPv4 address");
        let filter = format!(
            "{} and ip.DstAddr == {ip} and tcp.DstPort == 80",
            HOLD_FILTER
        );
        let divert = Divert::open(std::path::Path::new(&dir), &filter, 0).unwrap();
        let target = SocketAddr::new(ip, 80);
        let connect = move || {
            let start = Instant::now();
            let result = TcpStream::connect_timeout(&target, Duration::from_secs(20));
            (result.map(|_| ()).map_err(|e| e.kind()), start.elapsed())
        };
        let mut buf = vec![0u8; MTU_MAX];

        // Released: the connect waits while held, then completes without the app retrying.
        let app = std::thread::spawn(connect);
        let (len, address) = divert.recv(&mut buf).expect("the SYN is diverted");
        let syn = hold::parse_syn(&buf[..len]).expect("a SYN");
        assert_eq!(syn.remote, target);
        assert!(address.outbound() && !address.loopback());
        std::thread::sleep(Duration::from_secs(2));
        divert.send(&buf[..len], &address).unwrap();
        let (result, waited) = app.join().unwrap();
        assert_eq!(result, Ok(()), "the released connection completes");
        assert!(waited >= Duration::from_secs(2), "it was held: {waited:?}");

        let first = syn.key();

        // Refused: a RST answers the held SYN, and the connect fails with "refused", not a timeout. Windows answers a
        // RST on a connection attempt by trying again a few times before it reports "refused", so every SYN of the
        // second connection gets its RST until the program gives up. Retransmissions of the first connection, which
        // may still be queued, are skipped.
        let app = std::thread::spawn(connect);
        std::thread::scope(|s| {
            s.spawn(|| {
                let mut buf = vec![0u8; MTU_MAX];
                while let Some((len, address)) = divert.recv(&mut buf) {
                    let Some(syn) = hold::parse_syn(&buf[..len]) else {
                        continue;
                    };
                    if syn.key() != first {
                        divert.send(&hold::rst_for(&syn), &address.reply()).unwrap();
                    }
                }
            });
            let (result, waited) = app.join().unwrap();
            // Ends the receiving thread.
            divert.stop();
            assert_eq!(result, Err(std::io::ErrorKind::ConnectionRefused));
            assert!(
                waited < Duration::from_secs(10),
                "refused, not timed out: {waited:?}"
            );
        });
    }
}
