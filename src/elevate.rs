//! UAC self-elevation for the `firewall` commands (#59): run from a normal prompt, they start an elevated copy of
//! gatewizz through the UAC consent prompt and print what it reports. Windows only; the pure parts are tested on every
//! OS.
//!
//! The elevated copy cannot write to the caller's console, so its output comes back over a named pipe the caller
//! creates (`--elevated-output <pipe>`). The caller accepts only the elevated process it started on that pipe
//! (checked by process id), so no other program can put text in its place. Nothing is written to disk.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

/// The hidden trailing argument that tells the elevated copy where its output goes.
pub const OUTPUT_FLAG: &str = "--elevated-output";

/// Splits `--elevated-output <pipe>` off the end of the arguments: (the command's own arguments, the pipe).
pub fn split_output(args: &[String]) -> (&[String], Option<&str>) {
    match args {
        [rest @ .., flag, pipe] if flag == OUTPUT_FLAG && pipe.starts_with(r"\\.\pipe\") => {
            (rest, Some(pipe.as_str()))
        }
        _ => (args, None),
    }
}

/// The arguments for the elevated copy: the same command, with a `--config` path made absolute (the elevated process
/// may not start in the same directory), then the output pipe.
pub fn elevated_args(args: &[String], cwd: &Path, pipe: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(args.len() + 2);
    let mut config_next = false;
    for arg in args {
        if config_next {
            let path = Path::new(arg);
            out.push(if path.is_absolute() {
                arg.clone()
            } else {
                cwd.join(path).to_string_lossy().into_owned()
            });
        } else {
            out.push(arg.clone());
        }
        config_next = arg == "--config";
    }
    out.push(OUTPUT_FLAG.into());
    out.push(pipe.into());
    out
}

/// One Windows command line from arguments, quoted the way `CommandLineToArgvW` and the Rust runtime split it:
/// backslashes are literal except before a quote, where they are doubled.
pub fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
                return arg.clone();
            }
            let mut quoted = String::from('"');
            let mut backslashes = 0;
            for c in arg.chars() {
                match c {
                    '\\' => backslashes += 1,
                    '"' => {
                        quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                        quoted.push('"');
                        backslashes = 0;
                    }
                    _ => {
                        quoted.extend(std::iter::repeat_n('\\', backslashes));
                        quoted.push(c);
                        backslashes = 0;
                    }
                }
            }
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
            quoted.push('"');
            quoted
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(windows)]
pub use sys::{is_elevated, relaunch, report};

#[cfg(windows)]
mod sys {
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, GetProcessId, INFINITE, OpenProcessToken,
        WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// Whether this process runs with an elevated (full administrator) token.
    pub fn is_elevated() -> bool {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
        };
        unsafe { CloseHandle(token) };
        ok != 0 && elevation.TokenIsElevated != 0
    }

    /// In the elevated copy: sends the command's outcome to the caller's pipe. The exit code carries success.
    pub fn report(pipe: &str, outcome: &Result<String, String>) -> bool {
        let text = match outcome {
            Ok(text) | Err(text) => text,
        };
        std::fs::OpenOptions::new()
            .write(true)
            .open(pipe)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .is_ok()
    }

    /// Runs this executable again with `args`, elevated through the UAC prompt, and returns what it reported: its
    /// output on success, its error otherwise.
    pub fn relaunch(args: &[String]) -> Result<String, String> {
        let me = std::env::current_exe()
            .map_err(|e| format!("[firewall] cannot locate gatewizz.exe: {e}"))?;
        let cwd = std::env::current_dir()
            .map_err(|e| format!("[firewall] cannot read the current directory: {e}"))?;
        let mut nonce = [0u8; 8];
        getrandom(&mut nonce);
        let pipe_name = format!(
            r"\\.\pipe\gatewizz-elevated-{}-{}",
            std::process::id(),
            nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        // FIRST_PIPE_INSTANCE: if the name exists already, someone else made it, and it is not used.
        let pipe = unsafe {
            CreateNamedPipeW(
                wide(&pipe_name).as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                64 * 1024,
                0,
                null(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(format!(
                "[firewall] cannot create the pipe for the elevated output: error {}",
                unsafe { GetLastError() }
            ));
        }
        let pipe_raw = pipe as usize;
        let args = super::elevated_args(args, &cwd, &pipe_name);
        let (file, parameters, directory, verb) = (
            wide(&me.to_string_lossy()),
            wide(&super::command_line(&args)),
            wide(&cwd.to_string_lossy()),
            wide("runas"),
        );
        let mut info = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: verb.as_ptr(),
            lpFile: file.as_ptr(),
            lpParameters: parameters.as_ptr(),
            lpDirectory: directory.as_ptr(),
            nShow: SW_HIDE,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut info) } == 0 || info.hProcess.is_null() {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(pipe) };
            return Err(if error == ERROR_CANCELLED {
                "[firewall] administrator rights were declined; the firewall was not changed".into()
            } else {
                format!("[firewall] cannot start gatewizz elevated: error {error}")
            });
        }
        let child = unsafe { GetProcessId(info.hProcess) };
        // Reads what the elevated copy writes, but only from that process: anyone else is ignored.
        let reader = std::thread::spawn(move || {
            let pipe = pipe_raw as HANDLE;
            let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) } != 0
                || unsafe { GetLastError() }
                    == windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED;
            let mut client = 0u32;
            let ours = connected
                && unsafe { GetNamedPipeClientProcessId(pipe, &mut client) } != 0
                && client == child;
            let mut text = String::new();
            if ours {
                let mut file = std::mem::ManuallyDrop::new(unsafe {
                    std::fs::File::from_raw_handle(pipe as _)
                });
                let mut bytes = Vec::new();
                let _ = file.read_to_end(&mut bytes);
                text = String::from_utf8_lossy(&bytes).into_owned();
            }
            unsafe { CloseHandle(pipe) };
            ours.then_some(text)
        });
        unsafe { WaitForSingleObject(info.hProcess, INFINITE) };
        let mut code = 1u32;
        unsafe { GetExitCodeProcess(info.hProcess, &mut code) };
        unsafe { CloseHandle(info.hProcess) };
        // An elevated copy that never connected leaves the reader waiting: connecting ourselves wakes it, and the
        // process id check then discards that connection.
        if !reader.is_finished() {
            let h = unsafe {
                CreateFileW(
                    wide(&pipe_name).as_ptr(),
                    GENERIC_WRITE,
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
        }
        let text = reader.join().ok().flatten().unwrap_or_default();
        let text = text.trim_end().to_string();
        if code == 0 {
            Ok(text)
        } else if text.is_empty() {
            Err(format!(
                "[firewall] the elevated gatewizz failed with exit code {code}"
            ))
        } else {
            Err(text)
        }
    }

    /// Fills `buf` from the system's random number generator; on failure the pipe name stays unique through the
    /// process id and FIRST_PIPE_INSTANCE.
    fn getrandom(buf: &mut [u8]) {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        unsafe {
            BCryptGenRandom(
                null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_output_pipe_is_split_off_the_end_only() {
        let a = args(&[
            "firewall",
            "remove",
            OUTPUT_FLAG,
            r"\\.\pipe\gatewizz-elevated-1-ab",
        ]);
        let (rest, pipe) = split_output(&a);
        assert_eq!(rest, &a[..2]);
        assert_eq!(pipe, Some(r"\\.\pipe\gatewizz-elevated-1-ab"));
        // Not a pipe, or not at the end: left alone, so parsing rejects it.
        let file = args(&["firewall", "remove", OUTPUT_FLAG, r"C:\out.txt"]);
        assert_eq!(split_output(&file), (&file[..], None));
        let early = args(&[OUTPUT_FLAG, r"\\.\pipe\x", "firewall", "remove"]);
        assert_eq!(split_output(&early), (&early[..], None));
    }

    #[test]
    fn elevated_args_make_the_config_path_absolute() {
        let cwd = std::env::current_dir().unwrap();
        let out = elevated_args(
            &args(&["firewall", "apply", "--config", "rules.toml"]),
            &cwd,
            r"\\.\pipe\p",
        );
        assert_eq!(out[3], cwd.join("rules.toml").to_string_lossy());
        assert_eq!(&out[4..], [OUTPUT_FLAG, r"\\.\pipe\p"]);
        let abs = cwd.join("x.toml").to_string_lossy().into_owned();
        let out = elevated_args(
            &args(&["firewall", "install", "--config", &abs]),
            &cwd,
            r"\\.\pipe\p",
        );
        assert_eq!(out[3], abs);
    }

    #[test]
    fn command_lines_quote_like_windows_splits_them() {
        assert_eq!(
            command_line(&args(&["firewall", "status"])),
            "firewall status"
        );
        assert_eq!(
            command_line(&args(&[r"C:\My Rules\a.toml"])),
            r#""C:\My Rules\a.toml""#
        );
        // A trailing backslash inside quotes is doubled, so it does not escape the closing quote.
        assert_eq!(command_line(&args(&[r"C:\My Dir\"])), r#""C:\My Dir\\""#);
        assert_eq!(command_line(&args(&[r#"a"b"#])), r#""a\"b""#);
        assert_eq!(command_line(&args(&[""])), r#""""#);
        assert_eq!(command_line(&args(&[r"\\.\pipe\x"])), r"\\.\pipe\x");
    }
}
