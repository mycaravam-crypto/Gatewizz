//! The named pipe between the firewall service and the tray app (#59). Windows only.
//!
//! The service is the server. The pipe's access list admits SYSTEM (the service itself), administrators (who
//! control the service anyway) and interactively logged-on users (the tray app); everyone else, network clients
//! included, is refused. One client at a time: the tray app of the signed-in user.
//!
//! What crosses the pipe is metadata only (see `prompt.rs`), and the service validates every decision against the
//! notices it sent, so access to the pipe never means access to arbitrary rules.
// ponytail: any interactive user may connect, not only the console user; on a shared terminal server, another
// signed-in user could answer prompts. Narrowing to the active console session's SID needs WTS calls.
#![cfg_attr(not(windows), allow(dead_code))]

/// The pipe's name.
pub const NAME: &str = r"\\.\pipe\gatewizz-fw";

/// The pipe's access list in SDDL: protected DACL; SYSTEM full control; administrators and interactive users
/// read and write.
pub const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)";

/// Turns a WFP device path (`\device\harddiskvolume3\tools\curl.exe`) into a DOS path (`C:\tools\curl.exe`), given
/// the drives and the device each one maps to. `None` when no drive maps to the path's device.
pub fn device_to_dos(device_path: &str, drives: &[(String, String)]) -> Option<String> {
    let lower = device_path.to_ascii_lowercase();
    drives.iter().find_map(|(drive, device)| {
        let device = device.to_ascii_lowercase();
        let rest = lower.strip_prefix(&device)?;
        // `\device\harddiskvolume1` must not match `\device\harddiskvolume10\...`.
        rest.starts_with('\\')
            .then(|| format!("{drive}{}", &device_path[device.len()..]))
    })
}

#[cfg(windows)]
pub use sys::{Server, drives, serve};

#[cfg(windows)]
mod sys {
    use crate::prompt::{self, Message};
    use std::fs::File;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::Sender;
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
        QueryDosDeviceW,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Every drive letter with the device it maps to (`("C:", "\Device\HarddiskVolume3")`).
    pub fn drives() -> Vec<(String, String)> {
        let mut out = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", letter as char);
            let mut buf = vec![0u16; 1024];
            let n = unsafe {
                QueryDosDeviceW(wide(&drive).as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
            };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
                out.push((drive, String::from_utf16_lossy(&buf[..end])));
            }
        }
        out
    }

    /// The pipe's security descriptor, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn new(sddl: &str) -> Result<Self, String> {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(sddl).as_ptr(),
                    1,
                    &mut sd,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(format!(
                    "[firewall] bad pipe security descriptor: error {}",
                    unsafe { GetLastError() }
                ));
            }
            Ok(Self(sd))
        }
    }

    // A LocalAlloc'd descriptor: plain memory, usable from the server thread that now owns it.
    unsafe impl Send for Descriptor {}

    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    /// The running pipe server: [`Server::send`] delivers to the connected client, if any.
    pub struct Server {
        name: String,
        client: Arc<Mutex<Option<File>>>,
        /// The live pipe instance (as usize, 0 for none), so `stop` can disconnect a connected client.
        current: Arc<Mutex<usize>>,
        stopping: Arc<AtomicBool>,
        thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl Server {
        /// Sends a message to the connected tray app. Without one it is dropped: the notice expires unanswered and
        /// the connection stays blocked (fail closed).
        pub fn send(&self, message: &Message) -> bool {
            let mut client = self.client.lock().unwrap_or_else(|e| e.into_inner());
            match client.as_mut() {
                Some(file) => file.write_all(prompt::encode(message).as_bytes()).is_ok(),
                None => false,
            }
        }

        pub fn connected(&self) -> bool {
            self.client
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        }

        /// Stops accepting and returns once the server thread is done.
        pub fn stop(&self) {
            self.stopping.store(true, Ordering::SeqCst);
            // Wake a ConnectNamedPipe that waits for a client by being that client.
            let h = unsafe {
                CreateFileW(
                    wide(&self.name).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(h) };
            }
            // Disconnecting the instance ends the server thread's blocked read on a connected client.
            let current = *self.current.lock().unwrap_or_else(|e| e.into_inner());
            if current != 0 {
                unsafe { DisconnectNamedPipe(current as HANDLE) };
            }
            let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(thread) = thread {
                let _ = thread.join();
            }
        }
    }

    /// Serves `name` with the access list `sddl`: one client at a time, its decisions to `decisions`.
    pub fn serve(
        name: &str,
        sddl: &str,
        decisions: Sender<prompt::Decision>,
    ) -> Result<Server, String> {
        let descriptor = Descriptor::new(sddl)?;
        let client: Arc<Mutex<Option<File>>> = Arc::default();
        let current: Arc<Mutex<usize>> = Arc::default();
        let stopping = Arc::new(AtomicBool::new(false));
        // Handles cross into the server thread as integers: HANDLE is a raw pointer.
        let first = create(name, &descriptor, true)? as usize;
        let (thread_client, thread_stopping, thread_name) =
            (client.clone(), stopping.clone(), name.to_string());
        let thread_current = current.clone();
        let thread = std::thread::Builder::new()
            .name("pipe".into())
            .spawn(move || {
                let mut handle = first as HANDLE;
                let set_current = |h: HANDLE| {
                    *thread_current.lock().unwrap_or_else(|e| e.into_inner()) = h as usize;
                };
                set_current(handle);
                while !thread_stopping.load(Ordering::SeqCst) {
                    let connected = unsafe { ConnectNamedPipe(handle, null_mut()) } != 0
                        || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
                    if connected && !thread_stopping.load(Ordering::SeqCst) {
                        serve_client(handle, &thread_client, &decisions);
                    }
                    {
                        // Under the lock, so `stop` never disconnects a handle that is being closed.
                        let mut cur = thread_current.lock().unwrap_or_else(|e| e.into_inner());
                        unsafe { DisconnectNamedPipe(handle) };
                        unsafe { CloseHandle(handle) };
                        *cur = 0;
                    }
                    if thread_stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    match create(&thread_name, &descriptor, false) {
                        Ok(next) => {
                            handle = next;
                            set_current(handle);
                        }
                        Err(_) => return,
                    }
                }
                let mut cur = thread_current.lock().unwrap_or_else(|e| e.into_inner());
                unsafe { CloseHandle(handle) };
                *cur = 0;
            })
            .map_err(|e| format!("[firewall] cannot start the pipe server: {e}"))?;
        Ok(Server {
            name: name.to_string(),
            client,
            current,
            stopping,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn create(name: &str, descriptor: &Descriptor, first: bool) -> Result<HANDLE, String> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let h = unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &attributes,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // FIRST_PIPE_INSTANCE fails if someone else already created the name: never serve on a squatted pipe.
            return Err(format!(
                "[firewall] cannot create the pipe {name}: error {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(h)
    }

    /// Reads decisions from one connected client until it disconnects. Bad lines are answered, never acted on.
    fn serve_client(
        handle: HANDLE,
        client: &Mutex<Option<File>>,
        decisions: &Sender<prompt::Decision>,
    ) {
        // Two Files over one handle: the reader owns nothing (forgotten below), the writer lives in `client`.
        let reader_file = unsafe { File::from_raw_handle(handle as _) };
        let writer = match reader_file.try_clone() {
            Ok(w) => w,
            Err(_) => {
                std::mem::forget(reader_file);
                return;
            }
        };
        *client.lock().unwrap_or_else(|e| e.into_inner()) = Some(writer);
        let mut reader = BufReader::new(reader_file);
        let mut line = String::new();
        loop {
            line.clear();
            // Bounded: a client that never sends a newline cannot make the service buffer without limit.
            match (&mut reader)
                .take(prompt::MAX_LINE as u64 + 1)
                .read_line(&mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let reply = match prompt::decode(&line) {
                Ok(Message::Decision(d)) => {
                    let _ = decisions.send(d);
                    None
                }
                Ok(_) => Some("only decisions are accepted".to_string()),
                Err(err) => Some(err),
            };
            if let Some(message) = reply {
                let mut c = client.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(w) = c.as_mut() {
                    let _ = w.write_all(
                        prompt::encode(&Message::Result {
                            id: 0,
                            ok: false,
                            message,
                        })
                        .as_bytes(),
                    );
                }
            }
            if line.len() > prompt::MAX_LINE {
                break;
            }
        }
        *client.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // The handle is closed by the server loop, not by this File.
        std::mem::forget(reader.into_inner());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drives() -> Vec<(String, String)> {
        vec![
            ("C:".into(), r"\Device\HarddiskVolume3".into()),
            ("D:".into(), r"\Device\HarddiskVolume1".into()),
        ]
    }

    #[test]
    fn device_paths_become_dos_paths() {
        assert_eq!(
            device_to_dos(r"\device\harddiskvolume3\tools\curl.exe", &drives()).as_deref(),
            Some(r"C:\tools\curl.exe")
        );
        // Volume 1 must not claim volume 10 or 3's paths.
        assert_eq!(
            device_to_dos(r"\device\harddiskvolume10\x.exe", &drives()),
            None
        );
        assert_eq!(
            device_to_dos(r"\device\harddiskvolume1\x.exe", &drives()).as_deref(),
            Some(r"D:\x.exe")
        );
        assert_eq!(
            device_to_dos(r"\device\mup\server\share\x.exe", &drives()),
            None
        );
    }

    #[test]
    fn the_access_list_admits_only_system_admins_and_interactive_users() {
        assert!(SDDL.starts_with("D:P"), "protected: no inherited entries");
        let aces: Vec<&str> = SDDL
            .trim_start_matches("D:P")
            .split(')')
            .filter(|a| !a.is_empty())
            .collect();
        assert_eq!(aces, ["(A;;GA;;;SY", "(A;;GRGW;;;BA", "(A;;GRGW;;;IU"]);
    }

    /// The pipe ACL test from #59: a client whose token lacks the admitted groups is refused, while the
    /// (administrator, elevated) test process itself gets in and can exchange a line.
    #[cfg(windows)]
    #[test]
    fn a_client_without_the_admitted_groups_is_refused() {
        use std::io::{BufRead, BufReader, Write};
        use std::ptr::{null, null_mut};
        use windows_sys::Win32::Foundation::{
            CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
        };
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, CreateWellKnownSid, ImpersonateLoggedOnUser, RevertToSelf,
            SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
            TOKEN_IMPERSONATE, TOKEN_QUERY, WinBuiltinAdministratorsSid, WinInteractiveSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
        let name = format!(r"\\.\pipe\gatewizz-fw-test-{}", std::process::id());
        let (tx, rx) = std::sync::mpsc::channel();
        let server = serve(&name, SDDL, tx).unwrap();

        // A token with administrators and interactive users made deny-only.
        let mut token: HANDLE = null_mut();
        let access = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY;
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) },
            0
        );
        let mut sids = [[0u8; SECURITY_MAX_SID_SIZE as usize]; 2];
        let mut disable = Vec::new();
        for (buf, kind) in sids
            .iter_mut()
            .zip([WinBuiltinAdministratorsSid, WinInteractiveSid])
        {
            let mut size = buf.len() as u32;
            assert_ne!(
                unsafe { CreateWellKnownSid(kind, null_mut(), buf.as_mut_ptr().cast(), &mut size) },
                0
            );
            disable.push(SID_AND_ATTRIBUTES {
                Sid: buf.as_mut_ptr().cast(),
                Attributes: 0,
            });
        }
        let mut restricted: HANDLE = null_mut();
        let ok = unsafe {
            CreateRestrictedToken(
                token,
                0,
                2,
                disable.as_ptr(),
                0,
                null(),
                0,
                null(),
                &mut restricted,
            )
        };
        assert_ne!(ok, 0, "CreateRestrictedToken failed: {}", unsafe {
            GetLastError()
        });

        let restricted_token = restricted as usize;
        let refused = std::thread::scope(|s| {
            s.spawn(|| {
                assert_ne!(
                    unsafe { ImpersonateLoggedOnUser(restricted_token as HANDLE) },
                    0
                );
                let h = unsafe {
                    CreateFileW(
                        wide(&name).as_ptr(),
                        GENERIC_READ | GENERIC_WRITE,
                        0,
                        null(),
                        OPEN_EXISTING,
                        0,
                        null_mut(),
                    )
                };
                let error = unsafe { GetLastError() };
                unsafe { RevertToSelf() };
                if !h.is_null() && h != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                    unsafe { CloseHandle(h) };
                    return None;
                }
                Some(error)
            })
            .join()
            .unwrap()
        });
        unsafe { CloseHandle(restricted) };
        unsafe { CloseHandle(token) };
        assert_eq!(
            refused,
            Some(5),
            "the restricted client must get ERROR_ACCESS_DENIED"
        );

        // The process's own token (elevated administrator) connects and its decision reaches the service.
        let mut client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        let decision = crate::prompt::Decision {
            id: 7,
            action: crate::firewall::RuleAction::Allow,
            lasting: crate::prompt::Lasting::Once,
            any_host: false,
            any_port: false,
        };
        client
            .write_all(
                crate::prompt::encode(&crate::prompt::Message::Decision(decision.clone()))
                    .as_bytes(),
            )
            .unwrap();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            decision
        );
        // A notice sent by the service reaches the client.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !server.connected() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(server.send(&crate::prompt::Message::Result {
            id: 7,
            ok: true,
            message: "ok".into()
        }));
        let mut line = String::new();
        BufReader::new(&client).read_line(&mut line).unwrap();
        assert!(line.contains("\"result\""), "{line}");
        drop(client);
        server.stop();
    }
}
