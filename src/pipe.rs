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
pub use sys::{Client, Event, Server, connect, drives, serve};

#[cfg(windows)]
mod sys {
    use crate::prompt::{self, Message};
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{Read, Write};
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
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeServerProcessId,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
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
        /// The connected client's outbox, `None` while no client is connected. Only the server thread touches the
        /// pipe: synchronous I/O on one pipe is serialized, so a write from another thread would wait behind the
        /// server thread's read forever.
        client: Arc<Mutex<Option<VecDeque<String>>>>,
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
                Some(outbox) if outbox.len() < OUTBOX_MAX => {
                    outbox.push_back(prompt::encode(message));
                    true
                }
                // A client that stops reading cannot make the service queue without limit.
                _ => false,
            }
        }

        pub fn connected(&self) -> bool {
            self.client
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        }

        /// Stops accepting and returns once the server thread is done. Safe to call more than once.
        pub fn stop(&self) {
            if self.stopping.swap(true, Ordering::SeqCst) {
                return;
            }
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
            // Disconnecting the instance ends the server thread's blocked read on a connected client. Done under the
            // lock: the server thread takes it to close the handle, so this never touches a closed (or reused) one.
            {
                let current = self.current.lock().unwrap_or_else(|e| e.into_inner());
                if *current != 0 {
                    unsafe { DisconnectNamedPipe(*current as HANDLE) };
                }
            }
            let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(thread) = thread {
                let _ = thread.join();
            }
        }
    }

    /// The server thread never outlives its `Server`, also when unwinding drops it without a `stop`.
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// Serves `name` with the access list `sddl`: one client at a time, its decisions to `decisions`.
    pub fn serve(
        name: &str,
        sddl: &str,
        decisions: Sender<prompt::Decision>,
    ) -> Result<Server, String> {
        let descriptor = Descriptor::new(sddl)?;
        let client: Arc<Mutex<Option<VecDeque<String>>>> = Arc::default();
        let current: Arc<Mutex<usize>> = Arc::default();
        let stopping = Arc::new(AtomicBool::new(false));
        // Handles cross into the server thread as integers: HANDLE is a raw pointer.
        let first = create(name, &descriptor)? as usize;
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
                        serve_client(handle, &thread_client, &decisions, &thread_stopping);
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
                    // FIRST_PIPE_INSTANCE again: ours is closed now, so if the name exists, someone squatted it.
                    match create(&thread_name, &descriptor) {
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

    /// Always with FILE_FLAG_FIRST_PIPE_INSTANCE: there is only ever one instance, ours, so an existing pipe of the
    /// same name belongs to someone else and must not be served.
    fn create(name: &str, descriptor: &Descriptor) -> Result<HANDLE, String> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let h = unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
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

    /// Messages queued for a client before more are refused.
    const OUTBOX_MAX: usize = 256;

    /// How long the client loop waits when there is nothing to read or write.
    const POLL: std::time::Duration = std::time::Duration::from_millis(20);

    /// Serves one connected client until it disconnects or the server stops. Decisions go to `decisions`; bad
    /// lines are answered, never acted on.
    fn serve_client(
        handle: HANDLE,
        client: &Mutex<Option<VecDeque<String>>>,
        decisions: &Sender<prompt::Decision>,
        stopping: &AtomicBool,
    ) {
        pump(handle, client, stopping, |line| {
            let refusal = match line {
                Ok(Message::Decision(d)) => {
                    let _ = decisions.send(d);
                    return None;
                }
                Ok(_) => "only decisions are accepted".to_string(),
                Err(err) => err,
            };
            Some(Message::Result {
                id: 0,
                ok: false,
                message: refusal,
            })
        });
    }

    /// Runs one pipe connection, either end, until the other end goes away or `stopping` is set. This thread does
    /// all of the pipe's I/O: it writes what was queued in `outbox`, then reads only what `PeekNamedPipe` says is
    /// there, so no read ever blocks a write (synchronous I/O on one pipe is serialized). Each line read goes to
    /// `on_line`, whose answer, if any, is queued. `outbox` is `Some` while the connection runs.
    fn pump(
        handle: HANDLE,
        outbox: &Mutex<Option<VecDeque<String>>>,
        stopping: &AtomicBool,
        mut on_line: impl FnMut(Result<Message, String>) -> Option<Message>,
    ) {
        // The caller owns `handle` and closes it; ManuallyDrop makes sure this File never does, also when
        // unwinding. I/O goes through `&File`.
        let file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(handle as _) });
        let mut io = &*file;
        *outbox.lock().unwrap_or_else(|e| e.into_inner()) = Some(VecDeque::new());
        let mut pending: Vec<u8> = Vec::new();
        let queue = |message: Option<Message>| {
            if let (Some(message), Some(q)) = (
                message,
                outbox.lock().unwrap_or_else(|e| e.into_inner()).as_mut(),
            ) {
                q.push_back(prompt::encode(&message));
            }
        };
        'run: while !stopping.load(Ordering::SeqCst) {
            let outgoing: Vec<String> = outbox
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
                .map(|q| q.drain(..).collect())
                .unwrap_or_default();
            for line in &outgoing {
                if io.write_all(line.as_bytes()).is_err() {
                    break 'run;
                }
            }
            let mut available = 0u32;
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            if ok == 0 {
                // The other end went away.
                break;
            }
            if available == 0 {
                if outgoing.is_empty() {
                    std::thread::sleep(POLL);
                }
                continue;
            }
            let mut chunk = vec![0u8; (available as usize).min(prompt::MAX_LINE + 1)];
            match io.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => pending.extend_from_slice(&chunk[..n]),
            }
            while let Some(end) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                queue(on_line(prompt::decode(&String::from_utf8_lossy(&line))));
            }
            // Bounded: a peer that never sends a newline cannot make this end buffer without limit.
            if pending.len() > prompt::MAX_LINE {
                queue(on_line(Err(format!(
                    "message longer than {} bytes",
                    prompt::MAX_LINE
                ))));
                break;
            }
        }
        // A last answer (the refusal of an overlong line) still goes out before the connection closes.
        let last: Vec<String> = outbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .map(|q| q.into_iter().collect())
            .unwrap_or_default();
        for line in &last {
            if io.write_all(line.as_bytes()).is_err() {
                break;
            }
        }
    }

    /// What the tray app's [`Client`] reports.
    #[derive(Debug, PartialEq)]
    pub enum Event {
        /// Connected to the service: notices may follow.
        Connected,
        /// The service went away (stopped, restarted or removed). Notices it sent can no longer be answered, since
        /// a restarted service starts its ids again.
        Disconnected,
        /// A notice or the result of a decision.
        Message(Message),
    }

    /// How long the client waits before trying the pipe again, when the service is not running.
    const RETRY: std::time::Duration = std::time::Duration::from_secs(2);

    /// The tray app's end of the pipe: it keeps connecting to the service while it runs, and reports what arrives.
    pub struct Client {
        /// Queued lines for the service, `None` while not connected. Only the client thread touches the pipe.
        outbox: Arc<Mutex<Option<VecDeque<String>>>>,
        stopping: Arc<AtomicBool>,
        thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl Client {
        /// Queues a message for the service. `false` when not connected (or the queue is full): the decision is
        /// lost, and the connection stays blocked.
        pub fn send(&self, message: &Message) -> bool {
            let mut outbox = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
            match outbox.as_mut() {
                Some(q) if q.len() < OUTBOX_MAX => {
                    q.push_back(prompt::encode(message));
                    true
                }
                _ => false,
            }
        }

        /// Stops connecting and returns once the client thread is done. Safe to call more than once.
        pub fn stop(&self) {
            self.stopping.store(true, Ordering::SeqCst);
            let thread = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(thread) = thread {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// Connects to the pipe `name` whenever it exists, and keeps doing so after each disconnect, until stopped.
    /// `trusted` gets the pipe server's process id and decides whether to talk to it: anyone may create a pipe
    /// of that name while the service is not running, and such a squatter must not be shown as the firewall.
    /// Every event goes to `events`, followed by a call to `wake`.
    pub fn connect(
        name: &str,
        trusted: impl Fn(u32) -> bool + Send + 'static,
        events: Sender<Event>,
        wake: impl Fn() + Send + 'static,
    ) -> Result<Client, String> {
        let outbox: Arc<Mutex<Option<VecDeque<String>>>> = Arc::default();
        let stopping = Arc::new(AtomicBool::new(false));
        let (thread_outbox, thread_stopping, name) =
            (outbox.clone(), stopping.clone(), name.to_string());
        let thread = std::thread::Builder::new()
            .name("prompt-pipe".into())
            .spawn(move || {
                let report = |event: Event| {
                    let _ = events.send(event);
                    wake();
                };
                while !thread_stopping.load(Ordering::SeqCst) {
                    let handle = unsafe {
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
                    if handle == INVALID_HANDLE_VALUE {
                        wait(&thread_stopping, RETRY);
                        continue;
                    }
                    let mut server = 0u32;
                    let known = unsafe { GetNamedPipeServerProcessId(handle, &mut server) } != 0;
                    if !known || !trusted(server) {
                        unsafe { CloseHandle(handle) };
                        wait(&thread_stopping, RETRY);
                        continue;
                    }
                    report(Event::Connected);
                    pump(handle, &thread_outbox, &thread_stopping, |line| {
                        if let Ok(message @ (Message::Notice(_) | Message::Result { .. })) = line {
                            report(Event::Message(message));
                        }
                        // Anything else from the service is ignored: the tray app never answers it.
                        None
                    });
                    unsafe { CloseHandle(handle) };
                    report(Event::Disconnected);
                    wait(&thread_stopping, RETRY);
                }
            })
            .map_err(|e| format!("[ui] cannot start the firewall prompt client: {e}"))?;
        Ok(Client {
            outbox,
            stopping,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Sleeps up to `total`, in short steps so a stop is noticed quickly.
    fn wait(stopping: &AtomicBool, total: std::time::Duration) {
        let deadline = std::time::Instant::now() + total;
        while !stopping.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(POLL * 5);
        }
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

    /// The tray app's client: it talks only to a trusted server, gets notices, sends decisions, and notices when
    /// the server goes away.
    #[cfg(windows)]
    #[test]
    fn the_client_talks_only_to_a_trusted_server() {
        use std::time::Duration;
        let name = format!(r"\\.\pipe\gatewizz-fw-client-{}", std::process::id());
        let (decisions_tx, decisions) = std::sync::mpsc::channel();
        let server = serve(&name, SDDL, decisions_tx).unwrap();

        // A server it does not trust is never reported, and it leaves the pipe free for the next client.
        let (tx, untrusted_events) = std::sync::mpsc::channel();
        let untrusted = connect(&name, |_| false, tx, || {}).unwrap();
        assert!(
            untrusted_events
                .recv_timeout(Duration::from_secs(1))
                .is_err()
        );
        untrusted.stop();

        let me = std::process::id();
        let (tx, events) = std::sync::mpsc::channel();
        let client = connect(&name, move |pid| pid == me, tx, || {}).unwrap();
        // The untrusted client's connection may still be closing; the server takes the next one after it.
        assert_eq!(
            events.recv_timeout(Duration::from_secs(10)).unwrap(),
            Event::Connected
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !server.connected() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let notice = crate::prompt::Notice {
            id: 3,
            program: "curl.exe".into(),
            path: r"C:\tools\curl.exe".into(),
            remote: "192.0.2.2".parse().unwrap(),
            port: 9,
            protocol: crate::firewall::Protocol::Tcp,
            count: 1,
        };
        assert!(server.send(&crate::prompt::Message::Notice(notice.clone())));
        assert_eq!(
            events.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Message(crate::prompt::Message::Notice(notice))
        );
        let decision = crate::prompt::Decision {
            id: 3,
            action: crate::firewall::RuleAction::Allow,
            lasting: crate::prompt::Lasting::Once,
            any_host: false,
            any_port: true,
        };
        assert!(client.send(&crate::prompt::Message::Decision(decision.clone())));
        assert_eq!(
            decisions.recv_timeout(Duration::from_secs(5)).unwrap(),
            decision
        );
        server.stop();
        assert_eq!(
            events.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Disconnected
        );
        assert!(
            !client.send(&crate::prompt::Message::Decision(decision)),
            "nothing to send to"
        );
        client.stop();
    }
}
