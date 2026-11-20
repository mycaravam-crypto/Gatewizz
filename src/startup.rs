//! Per-user Windows login startup and per-session single-instance guard.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "Gatewizz";

#[cfg(windows)]
fn reg_exe() -> Result<std::path::PathBuf, String> {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .ok_or_else(|| "[startup] Windows system directory is unavailable".to_string())?;
    let executable = std::path::PathBuf::from(root)
        .join("System32")
        .join("reg.exe");
    if !executable.is_file() {
        return Err(format!(
            "[startup] registry utility not found at {}",
            executable.display()
        ));
    }
    Ok(executable)
}

#[cfg(windows)]
pub fn install(config: Option<&Path>) -> Result<String, String> {
    use std::process::Command;

    let executable = std::env::current_exe()
        .map_err(|error| format!("[startup] cannot locate executable: {error}"))?;
    let mut command = quote_arg(&executable);
    if let Some(path) = config {
        let path = path
            .canonicalize()
            .map_err(|error| format!("[startup] cannot resolve config path: {error}"))?;
        command.push_str(" --config ");
        command.push_str(&quote_arg(&path));
    }

    let output = Command::new(reg_exe()?)
        .args(["add", &format!("HKCU\\{RUN_KEY}"), "/v", RUN_VALUE, "/t", "REG_SZ", "/d"])
        .arg(&command)
        .arg("/f")
        .output()
        .map_err(|error| format!("[startup] cannot run reg.exe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "[startup] registry update failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok("Gatewizz will start automatically when this Windows user signs in.".into())
}

#[cfg(not(windows))]
pub fn install(_config: Option<&Path>) -> Result<String, String> {
    Err("[startup] automatic login startup is supported only on Windows".into())
}

#[cfg(windows)]
pub fn remove() -> Result<String, String> {
    use std::process::Command;

    if status()?.is_none() {
        return Ok("Gatewizz was not registered for automatic startup.".into());
    }
    let output = Command::new(reg_exe()?)
        .args(["delete", &format!("HKCU\\{RUN_KEY}"), "/v", RUN_VALUE, "/f"])
        .output()
        .map_err(|error| format!("[startup] cannot run reg.exe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "[startup] registry removal failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok("Gatewizz automatic startup has been removed.".into())
}

#[cfg(not(windows))]
pub fn remove() -> Result<String, String> {
    Err("[startup] automatic login startup is supported only on Windows".into())
}

#[cfg(windows)]
pub fn status() -> Result<Option<String>, String> {
    use std::process::Command;

    let output = Command::new(reg_exe()?)
        .args(["query", &format!("HKCU\\{RUN_KEY}"), "/v", RUN_VALUE])
        .output()
        .map_err(|error| format!("[startup] cannot run reg.exe: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .find(|line| line.trim_start().starts_with(RUN_VALUE))
        .map(|line| line.trim().to_string()))
}

#[cfg(not(windows))]
pub fn status() -> Result<Option<String>, String> {
    Err("[startup] automatic login startup is supported only on Windows".into())
}

/// Quotes one Windows command-line argument using the CommandLineToArgvW/CRT backslash rules.
#[cfg(windows)]
fn quote_arg(value: &Path) -> String {
    let value = value.to_string_lossy();
    let mut quoted = String::from("\"");
    let mut slashes = 0usize;
    for ch in value.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(slashes * 2 + 1));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(ch);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

/// A named mutex is scoped to the interactive Windows session, not the whole machine.
#[cfg(windows)]
pub struct SingleInstance(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl SingleInstance {
    pub fn acquire() -> Result<Option<Self>, String> {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, SetLastError};
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name: Vec<u16> = "Local\\Gatewizz.SingleInstance"
            .encode_utf16()
            .chain([0])
            .collect();
        // CreateMutexW only documents a last-error value for the already-exists case.
        unsafe { SetLastError(0) };
        let handle = unsafe { CreateMutexW(None, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "[startup] cannot create single-instance mutex (Windows error {})",
                unsafe { GetLastError() }
            ));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

#[cfg(windows)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn quotes_paths_with_spaces() {
        use super::quote_arg;
        use std::path::Path;

        assert_eq!(
            quote_arg(Path::new(r"C:\Program Files\Gatewizz\gatewizz.exe")),
            r#""C:\Program Files\Gatewizz\gatewizz.exe""#
        );
        assert_eq!(
            quote_arg(Path::new(r"C:\folder\name with spaces\config.toml")),
            r#""C:\folder\name with spaces\config.toml""#
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_mutex_allows_only_one_instance_and_is_released() {
        use super::SingleInstance;

        let first = SingleInstance::acquire().unwrap().expect("first instance");
        assert!(SingleInstance::acquire().unwrap().is_none());
        drop(first);
        assert!(SingleInstance::acquire().unwrap().is_some());
    }
}
