//! Tray icon and approval window (#35). Windows only; elsewhere gatewizz stays a console proxy.
//!
//! The UI owns the main thread and the proxy runs on its own thread. The window stays hidden until a request waits for
//! approval or the tray icon is clicked; eframe still calls `App::logic` while it is hidden, which handles the tray.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::process::Process;

/// What the tray icon shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayState {
    Running,
    Paused,
    Waiting,
}

impl TrayState {
    pub fn of(paused: bool, waiting: usize) -> Self {
        if waiting > 0 {
            Self::Waiting
        } else if paused {
            Self::Paused
        } else {
            Self::Running
        }
    }

    fn rgb(self) -> [u8; 3] {
        match self {
            Self::Running => [0x50, 0xd0, 0x80],
            Self::Paused => [0x7a, 0x80, 0x8c],
            Self::Waiting => [0xf0, 0xb0, 0x40],
        }
    }

    fn tooltip(self, waiting: usize) -> String {
        match self {
            Self::Running => "gatewizz: running".into(),
            Self::Paused => "gatewizz: paused (approvals are blocked)".into(),
            Self::Waiting => format!("gatewizz: {waiting} approval(s) waiting"),
        }
    }
}

/// A filled circle in the state's colour on a transparent square, RGBA.
fn icon_rgba(rgb: [u8; 3], size: u32) -> Vec<u8> {
    let r = size as f32 / 2.0;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let (dx, dy) = (x as f32 + 0.5 - r, y as f32 + 0.5 - r);
            let alpha = ((r - 1.0 - (dx * dx + dy * dy).sqrt()) + 1.0).clamp(0.0, 1.0);
            out.extend_from_slice(&[rgb[0], rgb[1], rgb[2], (alpha * 255.0) as u8]);
        }
    }
    out
}

/// The program's file name, for the window: `smartwizz.exe` rather than its full path.
/// A client Gatewizz cannot name. WSL and VMs get their own label: that is expected, not a failure.
fn unknown_label(why: &str) -> String {
    if why == crate::process::OUTSIDE_WINDOWS {
        "WSL / VM".into()
    } else {
        format!("unknown ({why})")
    }
}

fn program(process: &Process) -> String {
    match process {
        Process::Known { image, .. } => image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(image)
            .to_string(),
        Process::Unknown(why) => unknown_label(why),
    }
}

/// Time left before a held request is denied, as `m:ss`.
fn countdown(left: std::time::Duration) -> String {
    let secs = left.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// A grant duration for buttons: `15 min`, `1 hour`, `8 hours`, `1 h 30 min`.
fn duration_label(minutes: u32) -> String {
    match (minutes / 60, minutes % 60) {
        (0, m) => format!("{m} min"),
        (1, 0) => "1 hour".into(),
        (h, 0) => format!("{h} hours"),
        (h, m) => format!("{h} h {m} min"),
    }
}

/// Connections grouped by program for the Network tab, programs sorted by name. `filter` matches the program, the
/// hostname or the IP, ignoring case.
fn network_groups<'a>(
    connections: &'a [crate::connections::LiveConnection],
    filter: &str,
) -> Vec<(String, Vec<&'a crate::connections::LiveConnection>)> {
    let filter = filter.trim().to_lowercase();
    let mut groups: Vec<(String, Vec<&crate::connections::LiveConnection>)> = Vec::new();
    for conn in connections {
        let name = program(&conn.process);
        let matches = filter.is_empty()
            || name.to_lowercase().contains(&filter)
            || conn
                .hostname
                .as_deref()
                .is_some_and(|h| h.to_lowercase().contains(&filter))
            || conn.remote.ip().to_string().contains(&filter);
        if !matches {
            continue;
        }
        match groups.iter_mut().find(|(n, _)| *n == name) {
            Some((_, list)) => list.push(conn),
            None => groups.push((name, vec![conn])),
        }
    }
    groups.sort_by_key(|(name, _)| name.to_lowercase());
    groups
}

/// The distinct PIDs behind a group of connections, in ascending order.
fn process_ids(list: &[&crate::connections::LiveConnection]) -> Vec<u32> {
    let mut pids: Vec<u32> = list
        .iter()
        .filter_map(|c| match c.process {
            Process::Known { pid, .. } => Some(pid),
            Process::Unknown(_) => None,
        })
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// Where a blocked connection went, as the prompt shows it: `93.184.215.14:443 tcp`, `[2001:db8::1]:53 udp`.
fn destination(remote: std::net::IpAddr, port: u16, protocol: crate::firewall::Protocol) -> String {
    let protocol = match protocol {
        crate::firewall::Protocol::Tcp => "tcp",
        crate::firewall::Protocol::Udp => "udp",
        crate::firewall::Protocol::Any => "ip",
    };
    match remote {
        std::net::IpAddr::V6(ip) => format!("[{ip}]:{port} {protocol}"),
        std::net::IpAddr::V4(ip) => format!("{ip}:{port} {protocol}"),
    }
}

/// What a rule from the prompt will cover, in words, for the scope the user picked.
fn prompt_scope(
    program: &str,
    remote: std::net::IpAddr,
    port: u16,
    any_host: bool,
    any_port: bool,
) -> String {
    match (any_host, any_port) {
        (false, false) => format!("{program} connecting to {remote} on port {port}"),
        (true, false) => format!("{program} connecting to any address on port {port}"),
        (false, true) => format!("{program} connecting to {remote} on any port"),
        (true, true) => format!("{program} connecting anywhere"),
    }
}

#[cfg(windows)]
pub use app::run;

#[cfg(windows)]
mod app {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use eframe::egui::{
        self, Align, Align2, Color32, CornerRadius, CursorIcon, FontFamily, FontId, Layout, Margin,
        Rect, RichText, Sense, Stroke, ViewportCommand,
    };
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    use super::{
        TrayState, countdown, destination, duration_label, icon_rgba, network_groups, process_ids,
        program, prompt_scope, unknown_label,
    };
    use crate::approve::{Approvals, Held, Verdict, Window};
    use crate::connections::{Direction, Live};
    use crate::firewall::RuleAction;
    use crate::pipe;
    use crate::process::Process;
    use crate::prompt::{Decision, Inbox, Lasting, Message, Notice};
    use crate::rules::Action;

    // Palette values are refreshed from the Windows personalization settings while the app runs.
    // The dark palette remains the safe fallback when registry values are unavailable.
    const ACCENT_FALLBACK: Color32 = Color32::from_rgb(0x6e, 0x9d, 0xff);
    const SYMBOLS: &str = "gatewizz-system-icons";

    #[derive(Clone, Copy, PartialEq)]
    struct Palette {
        light: bool,
        bg: Color32,
        surface: Color32,
        raised: Color32,
        border: Color32,
        border_strong: Color32,
        text: Color32,
        muted: Color32,
        subtle: Color32,
        blue: Color32,
        green: Color32,
        amber: Color32,
        red: Color32,
        green_fill: Color32,
        extreme: Color32,
    }

    impl Palette {
        fn dark(accent: Color32) -> Self {
            Self {
                light: false,
                bg: Color32::from_rgb(0x0b, 0x0e, 0x14),
                surface: Color32::from_rgb(0x12, 0x16, 0x1f),
                raised: Color32::from_rgb(0x1a, 0x20, 0x2c),
                border: Color32::from_rgb(0x24, 0x2b, 0x39),
                border_strong: Color32::from_rgb(0x35, 0x3f, 0x52),
                text: Color32::from_rgb(0xe8, 0xec, 0xf3),
                muted: Color32::from_rgb(0x9a, 0xa4, 0xb6),
                subtle: Color32::from_rgb(0x7d, 0x87, 0x9a),
                blue: accent,
                green: Color32::from_rgb(0x41, 0xc4, 0x83),
                amber: Color32::from_rgb(0xf0, 0xab, 0x3e),
                red: Color32::from_rgb(0xef, 0x63, 0x63),
                green_fill: Color32::from_rgb(0x1d, 0x8a, 0x58),
                extreme: Color32::from_rgb(0x0e, 0x12, 0x1a),
            }
        }

        fn light(accent: Color32) -> Self {
            let accent = accent.gamma_multiply(0.78);
            Self {
                light: true,
                bg: Color32::from_rgb(0xf3, 0xf5, 0xf8),
                surface: Color32::from_rgb(0xff, 0xff, 0xff),
                raised: Color32::from_rgb(0xe9, 0xee, 0xf5),
                border: Color32::from_rgb(0xd7, 0xde, 0xe8),
                border_strong: Color32::from_rgb(0xb8, 0xc3, 0xd2),
                text: Color32::from_rgb(0x1b, 0x24, 0x32),
                muted: Color32::from_rgb(0x4b, 0x57, 0x68),
                subtle: Color32::from_rgb(0x5c, 0x68, 0x79),
                blue: accent,
                green: Color32::from_rgb(0x17, 0x74, 0x4a),
                amber: Color32::from_rgb(0x8a, 0x53, 0x00),
                red: Color32::from_rgb(0xb4, 0x23, 0x18),
                green_fill: Color32::from_rgb(0x17, 0x74, 0x4a),
                extreme: Color32::from_rgb(0xea, 0xed, 0xf2),
            }
        }
    }

    std::thread_local! {
        static PALETTE: std::cell::Cell<Palette> = std::cell::Cell::new(Palette::dark(ACCENT_FALLBACK));
    }

    fn colors() -> Palette {
        PALETTE.with(std::cell::Cell::get)
    }

    fn set_colors(palette: Palette) {
        PALETTE.with(|current| current.set(palette));
    }

    fn registry_dword(subkey: &str, value: &str) -> Option<u32> {
        use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RegGetValueW};

        let subkey: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let value: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        // Read the DWORD directly. Spawning reg.exe from a GUI process can flash a console window.
        let result = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                value.as_ptr(),
                0x10, // RRF_RT_REG_DWORD
                std::ptr::null_mut(),
                (&mut data as *mut u32).cast(),
                &mut size,
            )
        };
        (result == 0).then_some(data)
    }

    fn system_palette() -> Palette {
        let light = registry_dword(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "AppsUseLightTheme",
        ) == Some(1);
        let accent = registry_dword("Software\\Microsoft\\Windows\\DWM", "AccentColor")
            .map(|argb| {
                Color32::from_rgb(
                    ((argb >> 16) & 0xff) as u8,
                    ((argb >> 8) & 0xff) as u8,
                    (argb & 0xff) as u8,
                )
            })
            .unwrap_or(ACCENT_FALLBACK);
        if light {
            Palette::light(accent)
        } else {
            Palette::dark(accent)
        }
    }
    /// Font family name for headings and labels; falls back to the regular face.
    const SEMIBOLD: &str = "semibold";

    // Type scale: every text size in the workspace is one of these.
    const CAPTION: f32 = 11.5;
    const SMALL: f32 = 12.5;
    const BODY: f32 = 13.5;
    const SUBHEAD: f32 = 15.0;
    const TITLE: f32 = 18.0;
    const DISPLAY: f32 = 22.0;
    const HERO: f32 = 28.0;
    // Corner radii: controls, cards and banners, chips and badges.
    const R_CONTROL: u8 = 6;
    const R_CARD: u8 = 10;
    const R_PILL: u8 = 255;
    // Spacing grid (multiples of 4) and control heights.
    const SPACE_XS: f32 = 4.0;
    const SPACE_S: f32 = 8.0;
    const SPACE_M: f32 = 12.0;
    const SPACE_L: f32 = 16.0;
    const SPACE_XL: f32 = 24.0;
    const SPACE_XXL: f32 = 40.0;
    const CONTROL_H_LG: f32 = 40.0;
    const CONTROL_H: f32 = 32.0;
    const CONTROL_H_SM: f32 = 28.0;
    /// How long "Copied" confirmations stay visible.
    const FEEDBACK: Duration = Duration::from_secs(2);
    /// Blocked connections the queue keeps waiting at most; the oldest goes first.
    const INBOX_MAX: usize = 64;
    /// The duration the prompt's "Allow for" starts with, one of `prompt::PRESETS`.
    const NOTICE_MINUTES: u32 = 15;
    /// How often a hidden app wakes while notices wait, so expired ones leave the queue.
    const INBOX_TICK: Duration = Duration::from_secs(5);
    /// How long the service's answer to a decision stays in the status bar.
    const RESULT_SHOWN: Duration = Duration::from_secs(8);

    /// Starts the proxy on its own thread with a stop signal, shows the tray, and returns the proxy's result once it
    /// has stopped: after Quit, Ctrl+C or a proxy error.
    pub fn run(
        listen: SocketAddr,
        events_path: Option<PathBuf>,
        approvals: Arc<Approvals>,
        network: Option<Arc<Live>>,
        proxy: impl FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        let (quit, stop) = tokio::sync::oneshot::channel();
        let mut viewport = egui::ViewportBuilder::default()
            .with_title("Gatewizz")
            .with_app_id("gatewizz")
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([820.0, 580.0])
            .with_resizable(true)
            .with_visible(false);
        if let Some(geometry) = geometry_path().as_deref().and_then(load_geometry) {
            viewport = viewport
                .with_inner_size([geometry.width, geometry.height])
                .with_position([geometry.x, geometry.y]);
        }
        let options = eframe::NativeOptions {
            viewport,
            ..Default::default()
        };
        let ui = eframe::run_native(
            "gatewizz",
            options,
            Box::new(move |cc| {
                App::new(
                    cc,
                    listen,
                    events_path,
                    approvals,
                    network,
                    quit,
                    stop,
                    proxy,
                )
                .map(|app| Box::new(app) as Box<dyn eframe::App>)
                .map_err(|error| {
                    Box::new(std::io::Error::other(error))
                        as Box<dyn std::error::Error + Send + Sync>
                })
            }),
        );
        // The app owns the stop signal and the thread; dropping it (on any exit) has stopped the proxy.
        let result = APP_RESULT
            .lock()
            .expect("result poisoned")
            .take()
            .unwrap_or(Ok(()));
        ui.map_err(|e| format!("[ui] {e}"))?;
        result
    }

    /// The proxy's result, handed out of the app when it closes.
    static APP_RESULT: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);

    struct Items {
        pause: MenuItem,
        open_log: MenuItem,
        copy: MenuItem,
        quit: MenuItem,
    }

    enum Wake {
        Tray(TrayIconEvent),
        Menu(MenuEvent),
    }

    struct App {
        approvals: Arc<Approvals>,
        _window: Window,
        _tray: TrayIcon,
        items: Items,
        wake: mpsc::Receiver<Wake>,
        state: Option<TrayState>,
        waiting: usize,
        shown: bool,
        selected: Option<u64>,
        minutes: u32,
        listen: SocketAddr,
        events_path: Option<PathBuf>,
        quit: Option<tokio::sync::oneshot::Sender<()>>,
        proxy: Option<JoinHandle<Result<(), String>>>,
        tab: Tab,
        history_filter: String,
        history_decision: String,
        history_selected: Option<usize>,
        history: Vec<HistoryEvent>,
        history_rx: Receiver<Vec<HistoryEvent>>,
        history_stop: Sender<()>,
        history_worker: Option<JoinHandle<()>>,
        /// When the proxy address was last copied, for the button's confirmation.
        address_copied: Option<Instant>,
        /// When the CSV was last copied, and how many rows.
        csv_copied: Option<(Instant, usize)>,
        /// The connection monitor's live list, when `[monitor] enabled` (#57).
        network: Option<Arc<Live>>,
        network_filter: String,
        /// The firewall service's prompt (#59): connections blocked by an `ask` rule, answered over the pipe. The
        /// client keeps connecting while the app runs; without the service there is simply nothing to ask.
        firewall: pipe::Client,
        firewall_events: Receiver<pipe::Event>,
        firewall_connected: bool,
        inbox: Inbox,
        notice_selected: Option<u64>,
        /// The scope and duration picked for the shown notice. The scope belongs to `scope_for`, the notice it was
        /// picked for: any other notice starts from the narrowest scope.
        any_host: bool,
        any_port: bool,
        scope_for: Option<u64>,
        notice_minutes: u32,
        /// The service's answer to the last decision, shown in the status bar for a while.
        firewall_result: Option<(Instant, bool, String)>,
        icons_available: bool,
        last_theme_check: Instant,
        geometry_path: Option<PathBuf>,
        last_geometry_save: Instant,
        saved_geometry: Option<WindowGeometry>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct WindowGeometry {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
    }

    fn geometry_path() -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|root| root.join("gatewizz").join("window.json"))
    }

    fn clamp_geometry(mut geometry: WindowGeometry) -> WindowGeometry {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
            SM_YVIRTUALSCREEN,
        };
        let (left, top, width, height) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN) as f32,
                GetSystemMetrics(SM_YVIRTUALSCREEN) as f32,
                GetSystemMetrics(SM_CXVIRTUALSCREEN).max(820) as f32,
                GetSystemMetrics(SM_CYVIRTUALSCREEN).max(580) as f32,
            )
        };
        geometry.width = geometry.width.clamp(820.0, width);
        geometry.height = geometry.height.clamp(580.0, height);
        geometry.x = geometry
            .x
            .clamp(left - geometry.width + 120.0, left + width - 120.0);
        geometry.y = geometry
            .y
            .clamp(top - geometry.height + 64.0, top + height - 64.0);
        geometry
    }

    fn load_geometry(path: &Path) -> Option<WindowGeometry> {
        let bytes = std::fs::read(path).ok()?;
        let geometry = serde_json::from_slice::<WindowGeometry>(&bytes).ok()?;
        Some(clamp_geometry(geometry))
    }

    fn save_geometry(path: &Path, geometry: WindowGeometry) -> std::io::Result<()> {
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "window path has no parent",
            )
        })?;
        std::fs::create_dir_all(parent)?;
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&geometry)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(temporary, path)
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Tab {
        Overview,
        Activity,
        Network,
    }

    const MAX_LOG_ROTATIONS: usize = 5;
    const MAX_HISTORY_ROWS: usize = 500;
    const MAX_HISTORY_FILE_BYTES: u64 = 1024 * 1024;
    const HISTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

    #[derive(Debug, Clone, Default, serde::Deserialize)]
    #[serde(default)]
    struct HistoryEvent {
        /// Set on records that are not requests (`"connection"` from the monitor); those are not activity rows.
        kind: Option<String>,
        time: String,
        host: String,
        status: u16,
        action: Option<Action>,
        process: HistoryProcess,
        method: String,
        port: u16,
        path: String,
        coverage: String,
        rule: Option<String>,
        reason: Option<String>,
        model: Option<String>,
    }

    #[derive(Debug, Clone, Default, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum HistoryProcess {
        Known {
            image: String,
        },
        Unknown(String),
        #[default]
        Unavailable,
    }

    impl HistoryEvent {
        fn process_name(&self) -> String {
            match &self.process {
                HistoryProcess::Known { image } => image
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(image)
                    .to_string(),
                HistoryProcess::Unknown(reason) => unknown_label(reason),
                HistoryProcess::Unavailable => "unknown".into(),
            }
        }

        /// What happened to the request, not which rule matched: an approval that was denied or timed out, and a
        /// request refused before any rule (bad CONNECT port, oversized body), were blocked too.
        fn decision(&self) -> &'static str {
            match self.action {
                Some(Action::Block) => "block",
                _ if self.coverage == "blocked" => "block",
                Some(Action::Allow) => "allow",
                Some(Action::Approve) => "approve",
                None => "-",
            }
        }
    }

    impl App {
        #[allow(clippy::too_many_arguments)]
        fn new(
            cc: &eframe::CreationContext,
            listen: SocketAddr,
            events_path: Option<PathBuf>,
            approvals: Arc<Approvals>,
            network: Option<Arc<Live>>,
            quit: tokio::sync::oneshot::Sender<()>,
            stop: tokio::sync::oneshot::Receiver<()>,
            proxy: impl FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<(), String>
            + Send
            + 'static,
        ) -> Result<Self, String> {
            set_colors(system_palette());
            let icons_available = setup_style(&cc.egui_ctx);
            let geometry_path = geometry_path();
            let saved_geometry = geometry_path.as_deref().and_then(load_geometry);
            let (tx, wake) = mpsc::channel();
            for kind in [true, false] {
                let (tx, ctx) = (tx.clone(), cc.egui_ctx.clone());
                if kind {
                    TrayIconEvent::set_event_handler(Some(move |e| {
                        let _ = tx.send(Wake::Tray(e));
                        ctx.request_repaint();
                    }));
                } else {
                    MenuEvent::set_event_handler(Some(move |e| {
                        let _ = tx.send(Wake::Menu(e));
                        ctx.request_repaint();
                    }));
                }
            }
            // Wakes the hidden app whenever the number of waiting requests changes.
            let (mut count, ctx) = (approvals.watch(), cc.egui_ctx.clone());
            std::thread::spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() else {
                    return;
                };
                rt.block_on(async {
                    while count.changed().await.is_ok() {
                        ctx.request_repaint();
                    }
                });
            });
            let (history_tx, history_rx) = mpsc::channel();
            let (history_stop, stop_history) = mpsc::channel();
            let history_worker = if let Some(history_path) = events_path.clone() {
                let history_ctx = cc.egui_ctx.clone();
                Some(
                    std::thread::Builder::new()
                        .name("activity-history".into())
                        .spawn(move || {
                            loop {
                                if history_tx.send(load_history(&history_path)).is_err() {
                                    break;
                                }
                                history_ctx.request_repaint();
                                match stop_history.recv_timeout(HISTORY_REFRESH_INTERVAL) {
                                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                                }
                            }
                        })
                        .map_err(|e| format!("[ui] cannot start activity history worker: {e}"))?,
                )
            } else {
                None
            };

            let items = Items {
                pause: MenuItem::new("Pause", true, None),
                open_log: MenuItem::new("Open event log", events_path.is_some(), None),
                copy: MenuItem::new(format!("Copy proxy address ({listen})"), true, None),
                quit: MenuItem::new("Quit", true, None),
            };
            let menu = Menu::new();
            let built = menu.append_items(&[
                &items.pause,
                &items.open_log,
                &items.copy,
                &PredefinedMenuItem::separator(),
                &items.quit,
            ]);
            built.map_err(|e| format!("[ui] cannot build tray menu: {e}"))?;
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_menu_on_left_click(false)
                .with_icon(icon(TrayState::Running))
                .with_tooltip(TrayState::Running.tooltip(0))
                .build()
                .map_err(|e| format!("[ui] cannot create tray icon: {e}"))?;
            let (firewall_tx, firewall_events) = mpsc::channel();
            let firewall_ctx = cc.egui_ctx.clone();
            // Only the running service is trusted as the pipe's server: anyone can create a pipe of that name while
            // the service is stopped.
            let firewall = pipe::connect(
                pipe::NAME,
                |server| crate::service::pid() == Some(server),
                firewall_tx,
                move || firewall_ctx.request_repaint(),
            )?;
            // Attach before starting the proxy so an immediate approval cannot race window registration.
            let window = approvals.attach();
            // Start the proxy only after the tray exists. A UI initialization failure must never leave an
            // unmanageable proxy running in a detached worker thread.
            let proxy = std::thread::spawn(move || proxy(stop));
            Ok(Self {
                _window: window,
                approvals,
                _tray: tray,
                items,
                wake,
                state: None,
                waiting: 0,
                shown: false,
                selected: None,
                minutes: 15,
                listen,
                events_path,
                quit: Some(quit),
                proxy: Some(proxy),
                tab: Tab::Overview,
                history_filter: String::new(),
                history_decision: "all".into(),
                history_selected: None,
                history: Vec::new(),
                history_rx,
                history_stop,
                history_worker,
                address_copied: None,
                csv_copied: None,
                network,
                network_filter: String::new(),
                firewall,
                firewall_events,
                firewall_connected: false,
                inbox: Inbox::new(INBOX_MAX),
                notice_selected: None,
                any_host: false,
                any_port: false,
                scope_for: None,
                notice_minutes: NOTICE_MINUTES,
                firewall_result: None,
                icons_available,
                last_theme_check: Instant::now(),
                geometry_path,
                last_geometry_save: Instant::now(),
                saved_geometry,
            })
        }

        fn show(&mut self, ctx: &egui::Context, visible: bool) {
            if self.shown != visible {
                self.shown = visible;
                ctx.send_viewport_cmd(ViewportCommand::Visible(visible));
            }
            if visible {
                ctx.send_viewport_cmd(ViewportCommand::Focus);
            }
        }

        fn quit(&mut self, ctx: &egui::Context) {
            // A shutdown withdraws every outstanding approval; nothing is restored on the next launch.
            self.approvals.set_paused(true);
            if let Some(quit) = self.quit.take() {
                let _ = quit.send(());
            }
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }

        fn on_menu(&mut self, ctx: &egui::Context, event: &MenuEvent) {
            let id = event.id();
            if id == self.items.pause.id() {
                self.set_paused(!self.approvals.paused());
            } else if id == self.items.open_log.id() {
                self.open_log();
            } else if id == self.items.copy.id() {
                copy_to_clipboard(&format!("http://{}", self.listen));
            } else if id == self.items.quit.id() {
                self.quit(ctx);
            }
        }
    }

    /// `clip.exe` ships with Windows; no clipboard code needed.
    fn copy_to_clipboard(text: &str) {
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("clip")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }

    fn semibold(size: f32) -> FontId {
        FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
    }

    /// Frame margins from the spacing grid.
    fn pad(x: f32, y: f32) -> Margin {
        Margin::symmetric(x as i8, y as i8)
    }

    fn mono(size: f32) -> FontId {
        FontId::new(size, FontFamily::Monospace)
    }

    /// A status colour at low opacity, for badge and banner backgrounds.
    fn tint(color: Color32) -> Color32 {
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 34)
    }

    fn card() -> egui::Frame {
        egui::Frame::new()
            .fill(colors().surface)
            .stroke(Stroke::new(1.0, colors().border))
            .corner_radius(R_CARD)
            .inner_margin(pad(SPACE_L, SPACE_L))
    }

    /// Small uppercase heading above a group of content.
    fn caption(ui: &mut egui::Ui, text: &str) {
        ui.label(
            RichText::new(text)
                .font(semibold(CAPTION))
                .extra_letter_spacing(0.6)
                .color(colors().muted),
        );
    }

    /// Glyph-free status dot: painted, so it renders with any font.
    fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(radius * 2.0, radius * 2.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), radius, color);
    }

    /// A rounded badge painted into `rect`'s left edge, vertically centred.
    fn paint_badge(painter: &egui::Painter, rect: Rect, text: &str, color: Color32) -> Rect {
        let galley = painter.layout_no_wrap(text.to_owned(), semibold(CAPTION), color);
        let size = galley.size() + egui::vec2(SPACE_L, SPACE_XS);
        let badge = Rect::from_min_size(
            egui::pos2(rect.left(), rect.center().y - size.y / 2.0),
            size,
        );
        painter.rect_filled(badge, CornerRadius::same(R_PILL), tint(color));
        painter.galley(
            badge.min + egui::vec2(SPACE_S, SPACE_XS / 2.0),
            galley,
            color,
        );
        badge
    }

    /// The header's state indicator: a dot and a label on a tinted capsule.
    fn status_pill(ui: &mut egui::Ui, text: &str, color: Color32) {
        let galley = ui
            .painter()
            .layout_no_wrap(text.to_owned(), semibold(SMALL), color);
        let size = egui::vec2(galley.size().x + 40.0, 30.0);
        let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(R_PILL), tint(color));
        painter.circle_filled(egui::pos2(rect.left() + 16.0, rect.center().y), 4.0, color);
        let pos = egui::pos2(rect.left() + 28.0, rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
    }

    fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
        let width = ui
            .painter()
            .layout_no_wrap(text.to_owned(), semibold(CAPTION), color)
            .size()
            .x;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(width + 16.0, 22.0), Sense::hover());
        paint_badge(ui.painter(), rect, text, color);
    }

    /// Single-line text cut to `rect`'s width with an ellipsis, vertically centred.
    fn paint_cell(painter: &egui::Painter, rect: Rect, text: &str, font: FontId, color: Color32) {
        let mut job = egui::text::LayoutJob::simple_singleline(text.to_owned(), font, color);
        job.wrap = egui::text::TextWrapping::truncate_at_width(rect.width().max(1.0));
        let galley = painter.layout_job(job);
        let pos = egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
    }

    /// A circled check mark for empty states.
    fn check_icon(ui: &mut egui::Ui, color: Color32, size: f32) {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), Sense::hover());
        let painter = ui.painter();
        let c = rect.center();
        painter.circle_filled(c, size / 2.0, tint(color));
        let s = size / 2.0;
        let stroke = Stroke::new(size / 14.0, color);
        let points = [
            c + egui::vec2(-0.38 * s, 0.02 * s),
            c + egui::vec2(-0.1 * s, 0.3 * s),
            c + egui::vec2(0.4 * s, -0.26 * s),
        ];
        painter.line_segment([points[0], points[1]], stroke);
        painter.line_segment([points[1], points[2]], stroke);
    }

    fn button(text: &str, fill: Color32, color: Color32) -> egui::Button<'static> {
        egui::Button::new(RichText::new(text).font(semibold(BODY)).color(color))
            .fill(fill)
            .corner_radius(R_CONTROL)
            .min_size(egui::vec2(0.0, CONTROL_H))
    }

    fn quiet_button(text: &str) -> egui::Button<'static> {
        egui::Button::new(RichText::new(text).size(SMALL).color(colors().muted))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, colors().border))
            .corner_radius(R_CONTROL)
    }

    /// A toggle chip: filters and duration presets.
    fn chip(ui: &mut egui::Ui, text: &str, selected: bool) -> egui::Response {
        let (fill, stroke, color) = if selected {
            (
                tint(colors().blue),
                Stroke::new(1.0, colors().blue),
                colors().text,
            )
        } else {
            (
                Color32::TRANSPARENT,
                Stroke::new(1.0, colors().border),
                colors().muted,
            )
        };
        ui.add(
            egui::Button::new(RichText::new(text).size(SMALL).color(color))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(R_PILL)
                .min_size(egui::vec2(0.0, CONTROL_H_SM)),
        )
        .on_hover_cursor(CursorIcon::PointingHand)
    }

    fn stat_card(ui: &mut egui::Ui, label: &str, value: usize, color: Color32, hint: &str) {
        card().inner_margin(pad(SPACE_L, SPACE_L)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                dot(ui, color, 4.0);
                ui.label(
                    RichText::new(label)
                        .font(semibold(SMALL))
                        .color(colors().muted),
                );
            });
            ui.label(
                RichText::new(value.to_string())
                    .font(mono(HERO))
                    .color(colors().text),
            );
            ui.add(
                egui::Label::new(RichText::new(hint).size(CAPTION).color(colors().subtle))
                    .truncate(),
            );
        });
    }

    /// Label/value pairs in two aligned columns.
    fn details(ui: &mut egui::Ui, id: &str, rows: &[(&str, &str)]) {
        ui.spacing_mut().interact_size.y = 20.0;
        egui::Grid::new(id)
            .num_columns(2)
            .spacing([SPACE_XL, SPACE_S])
            .show(ui, |ui| {
                for (key, value) in rows {
                    ui.label(RichText::new(*key).size(SMALL).color(colors().subtle));
                    ui.add(
                        egui::Label::new(RichText::new(*value).size(BODY).color(colors().text))
                            .wrap(),
                    );
                    ui.end_row();
                }
            });
    }

    fn decision_style(event: &HistoryEvent) -> (&'static str, Color32) {
        match event.decision() {
            "allow" => ("Allowed", colors().green),
            "block" if event.action == Some(Action::Approve) => ("Denied", colors().red),
            "block" => ("Blocked", colors().red),
            "approve" => ("Approved", colors().amber),
            _ => ("Unknown", colors().subtle),
        }
    }

    fn urgency(left: Duration) -> Color32 {
        if left.as_secs() < 15 {
            colors().red
        } else {
            colors().amber
        }
    }

    /// Column rectangles of an activity row: time, program, destination, decision, status.
    fn history_columns(rect: Rect) -> [Rect; 5] {
        let inner = rect.shrink2(egui::vec2(SPACE_M, 0.0));
        let flex = (inner.width() - 150.0 - 104.0 - 52.0).max(120.0);
        let mut x = inner.left();
        [150.0, flex * 0.4, flex * 0.6, 104.0, 52.0].map(|width| {
            let column = Rect::from_min_max(
                egui::pos2(x, inner.top()),
                egui::pos2(x + width - 10.0, inner.bottom()),
            );
            x += width;
            column
        })
    }

    fn history_header(ui: &mut egui::Ui) {
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), Sense::hover());
        let columns = history_columns(rect);
        for (column, title) in
            columns
                .iter()
                .zip(["TIME (UTC)", "PROGRAM", "DESTINATION", "DECISION", "STATUS"])
        {
            paint_cell(
                ui.painter(),
                *column,
                title,
                semibold(CAPTION),
                colors().subtle,
            );
        }
        ui.painter().hline(
            rect.x_range(),
            rect.bottom(),
            Stroke::new(1.0, colors().border),
        );
    }

    /// One clickable, full-width activity row.
    fn history_row(ui: &mut egui::Ui, event: &HistoryEvent, active: bool) -> egui::Response {
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), Sense::click());
        let response = response.on_hover_cursor(CursorIcon::PointingHand);
        let painter = ui.painter();
        if active {
            painter.rect_filled(rect, 6, tint(colors().blue));
        } else if response.hovered() {
            painter.rect_filled(rect, R_CONTROL, colors().raised);
        }
        let [time, program, host, decision, status] = history_columns(rect);
        let (label, color) = decision_style(event);
        let when = event.time.replace('T', " ");
        paint_cell(
            painter,
            time,
            when.trim_end_matches('Z'),
            mono(SMALL),
            colors().muted,
        );
        paint_cell(
            painter,
            program,
            &event.process_name(),
            FontId::proportional(13.5),
            colors().text,
        );
        paint_cell(painter, host, &event.host, mono(SMALL), colors().blue);
        paint_badge(painter, decision, label, color);
        let status_color = if event.status >= 400 {
            colors().red
        } else {
            colors().muted
        };
        paint_cell(
            painter,
            status,
            &event.status.to_string(),
            mono(SMALL),
            status_color,
        );
        response
    }

    /// Loads only a bounded tail from each log file. File I/O and JSON parsing run on a worker thread.
    /// Accepts a borrowed path so callers do not need to allocate a `PathBuf`.
    /// `path` comes from the local events.path configuration, which intentionally supports custom locations.
    fn load_history(path: &Path) -> Vec<HistoryEvent> {
        let mut rows = Vec::new();
        for suffix in 0..=MAX_LOG_ROTATIONS {
            let candidate = if suffix == 0 {
                path.to_path_buf()
            } else {
                let mut name = path.as_os_str().to_owned();
                name.push(format!(".{suffix}"));
                PathBuf::from(name)
            };
            let Ok(mut file) = File::open(candidate) else {
                continue;
            };
            let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
                continue;
            };
            let offset = length.saturating_sub(MAX_HISTORY_FILE_BYTES);
            if file.seek(SeekFrom::Start(offset)).is_err() {
                continue;
            }
            let mut bytes = Vec::new();
            if file
                .take(MAX_HISTORY_FILE_BYTES)
                .read_to_end(&mut bytes)
                .is_err()
            {
                continue;
            }
            // The bounded offset may land inside a UTF-8 code point. Decode lossily so one
            // partial character cannot discard otherwise valid recent log records.
            let mut contents = String::from_utf8_lossy(&bytes).into_owned();
            // A bounded tail can begin halfway through a JSON line. Discard that partial record.
            if offset > 0 {
                let Some(newline) = contents.find('\n') else {
                    continue;
                };
                contents.drain(..=newline);
            }
            for line in contents.lines().rev() {
                if let Ok(event) = serde_json::from_str::<HistoryEvent>(line)
                    && event.kind.is_none()
                {
                    rows.push(event);
                    if rows.len() >= MAX_HISTORY_ROWS {
                        return rows;
                    }
                }
            }
        }
        rows
    }

    /// CSV-escapes one metadata field. Quotes are doubled and the field is always quoted.
    fn csv_field(value: &str) -> String {
        format!("\"{}\"", value.replace('"', "\"\""))
    }

    /// Rows whose host or process name contains `text` (case-insensitive) and whose decision
    /// equals `decision` ("all" matches every decision). Both filters must match.
    fn filter_history<'a>(
        rows: &'a [HistoryEvent],
        text: &str,
        decision: &str,
    ) -> Vec<&'a HistoryEvent> {
        let needle = text.to_lowercase();
        rows.iter()
            .filter(|event| {
                let text_match = needle.is_empty()
                    || format!("{} {}", event.host, event.process_name())
                        .to_lowercase()
                        .contains(&needle);
                text_match && (decision == "all" || event.decision() == decision)
            })
            .collect()
    }

    /// Exports only the same metadata fields already persisted in the event log.
    fn history_csv(events: &[&HistoryEvent]) -> String {
        let mut csv = String::from(
            "time_utc,process,host,port,method,path,decision,status,coverage,rule,reason,model\r\n",
        );
        for event in events {
            let fields = [
                event.time.clone(),
                event.process_name(),
                event.host.clone(),
                event.port.to_string(),
                event.method.clone(),
                event.path.clone(),
                event.decision().to_string(),
                event.status.to_string(),
                event.coverage.clone(),
                event.rule.clone().unwrap_or_default(),
                event.reason.clone().unwrap_or_default(),
                event.model.clone().unwrap_or_default(),
            ];
            csv.push_str(
                &fields
                    .iter()
                    .map(|field| csv_field(field))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            csv.push_str("\r\n");
        }
        csv
    }

    fn icon(state: TrayState) -> Icon {
        Icon::from_rgba(icon_rgba(state.rgb(), 32), 32, 32).expect("32x32 RGBA is a valid icon")
    }

    /// Prefers the Windows UI fonts (Segoe UI, Segoe UI Semibold, Consolas) from the system font folder, so text looks
    /// native and crisp. Each missing face falls back to egui's bundled fonts, which also cover glyphs Segoe UI lacks.
    fn setup_fonts(ctx: &egui::Context) -> bool {
        let mut fonts = egui::FontDefinitions::default();
        let dir = std::env::var_os("WINDIR").map(|windows| PathBuf::from(windows).join("Fonts"));
        let mut load = |name: &str, file: &str| -> Option<String> {
            let bytes = std::fs::read(dir.as_ref()?.join(file)).ok()?;
            fonts
                .font_data
                .insert(name.into(), Arc::new(egui::FontData::from_owned(bytes)));
            Some(name.into())
        };
        let regular = load("segoe-ui", "segoeui.ttf");
        let semibold = load("segoe-ui-semibold", "seguisb.ttf");
        let mono = load("consolas", "consola.ttf");
        let symbols = load("system-icons", "SegoeIcons.ttf")
            .or_else(|| load("system-icons-mdl2", "segmdl2.ttf"));
        let family = |fonts: &mut egui::FontDefinitions, family: FontFamily| {
            fonts.families.entry(family).or_default().clone()
        };
        let mut proportional = family(&mut fonts, FontFamily::Proportional);
        proportional.splice(0..0, regular);
        let mut heading = proportional.clone();
        heading.splice(0..0, semibold);
        let mut monospace = family(&mut fonts, FontFamily::Monospace);
        monospace.splice(0..0, mono);
        fonts
            .families
            .insert(FontFamily::Proportional, proportional);
        fonts
            .families
            .insert(FontFamily::Name(SEMIBOLD.into()), heading);
        fonts.families.insert(FontFamily::Monospace, monospace);
        let icons_available = symbols.is_some();
        if let Some(symbols) = symbols {
            fonts
                .families
                .insert(FontFamily::Name(SYMBOLS.into()), vec![symbols]);
        }
        ctx.set_fonts(fonts);
        icons_available
    }

    fn setup_style(ctx: &egui::Context) -> bool {
        let icons_available = setup_fonts(ctx);
        let palette = colors();
        ctx.set_theme(if palette.light {
            egui::Theme::Light
        } else {
            egui::Theme::Dark
        });
        ctx.all_styles_mut(|style| {
            use egui::TextStyle;
            style.text_styles = [
                (TextStyle::Small, FontId::proportional(11.5)),
                (TextStyle::Body, FontId::proportional(13.5)),
                (TextStyle::Button, FontId::proportional(13.5)),
                (TextStyle::Heading, semibold(TITLE)),
                (TextStyle::Monospace, mono(SMALL)),
            ]
            .into();
            style.animation_time = 0.12;
            style.spacing.item_spacing = egui::vec2(SPACE_S, SPACE_S);
            style.spacing.button_padding = egui::vec2(SPACE_L, SPACE_XS);
            style.spacing.interact_size.y = CONTROL_H_SM;
            style.interaction.selectable_labels = false;
            let visuals = &mut style.visuals;
            visuals.panel_fill = colors().bg;
            visuals.window_fill = colors().surface;
            visuals.window_stroke = Stroke::new(1.0, colors().border);
            visuals.window_corner_radius = CornerRadius::same(R_CARD);
            visuals.menu_corner_radius = CornerRadius::same(R_CONTROL);
            visuals.extreme_bg_color = colors().extreme;
            visuals.faint_bg_color = colors().surface;
            visuals.override_text_color = None;
            visuals.selection.bg_fill = tint(colors().blue);
            visuals.selection.stroke = Stroke::new(1.0, colors().blue);
            visuals.hyperlink_color = colors().blue;
            let widgets = &mut visuals.widgets;
            widgets.noninteractive.bg_stroke = Stroke::new(1.0, colors().border);
            widgets.noninteractive.fg_stroke = Stroke::new(1.0, colors().text);
            for (state, fill, stroke) in [
                (&mut widgets.inactive, colors().surface, colors().border),
                (
                    &mut widgets.hovered,
                    colors().raised,
                    colors().border_strong,
                ),
                (&mut widgets.active, colors().raised, colors().blue),
                (&mut widgets.open, colors().raised, colors().border_strong),
            ] {
                state.bg_fill = fill;
                state.weak_bg_fill = fill;
                state.bg_stroke = Stroke::new(1.0, stroke);
                state.fg_stroke = Stroke::new(1.0, colors().text);
                state.corner_radius = CornerRadius::same(R_CONTROL);
                state.expansion = 0.0;
            }
        });
        icons_available
    }

    fn tab_icon(ui: &mut egui::Ui, tab: Tab, font_available: bool, color: Color32) {
        let glyph = match tab {
            Tab::Overview => '\u{e80f}',
            Tab::Activity => '\u{e81c}',
            Tab::Network => '\u{e968}',
        };
        if font_available {
            ui.label(
                RichText::new(glyph.to_string())
                    .font(FontId::new(16.0, FontFamily::Name(SYMBOLS.into())))
                    .color(color),
            );
            return;
        }

        let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::hover());
        let painter = ui.painter();
        let center = rect.center();
        let stroke = Stroke::new(1.5, color);
        match tab {
            Tab::Overview => {
                for offset in [
                    egui::vec2(-4.0, -4.0),
                    egui::vec2(4.0, -4.0),
                    egui::vec2(-4.0, 4.0),
                    egui::vec2(4.0, 4.0),
                ] {
                    painter.rect_filled(
                        Rect::from_center_size(center + offset, egui::vec2(5.0, 5.0)),
                        1.0,
                        color,
                    );
                }
            }
            Tab::Activity => {
                painter.circle_stroke(center, 7.0, stroke);
                painter.line_segment([center, center + egui::vec2(0.0, -4.0)], stroke);
                painter.line_segment([center, center + egui::vec2(4.0, 2.0)], stroke);
            }
            Tab::Network => {
                let nodes = [
                    center + egui::vec2(-5.0, -4.0),
                    center + egui::vec2(5.0, -4.0),
                    center + egui::vec2(0.0, 5.0),
                ];
                painter.line_segment([nodes[0], nodes[1]], stroke);
                painter.line_segment([nodes[0], nodes[2]], stroke);
                painter.line_segment([nodes[1], nodes[2]], stroke);
                for node in nodes {
                    painter.circle_filled(node, 2.5, color);
                }
            }
        }
    }

    /// Workspace views. Each draws one region; all decisions go through `Approvals`.
    impl App {
        fn header(&mut self, ui: &mut egui::Ui, state: TrayState, waiting: usize) {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), Sense::hover());
                ui.painter().rect_filled(rect, 9, colors().blue);
                ui.painter().text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    "G",
                    semibold(TITLE),
                    Color32::from_rgb(0x0b, 0x12, 0x24),
                );
                ui.add_space(SPACE_XS);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(
                        RichText::new("Gatewizz")
                            .font(semibold(TITLE))
                            .color(colors().text),
                    );
                    ui.label(
                        RichText::new("Local security gate for outgoing traffic")
                            .size(SMALL)
                            .color(colors().muted),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (text, color) = match state {
                        TrayState::Running => ("Proxy running".to_string(), colors().green),
                        TrayState::Paused => ("Approvals paused".to_string(), colors().muted),
                        TrayState::Waiting => {
                            (format!("{waiting} awaiting review"), colors().amber)
                        }
                    };
                    status_pill(ui, &text, color);
                });
            });
            ui.add_space(SPACE_L);
            egui::Frame::new()
                .fill(colors().surface)
                .stroke(Stroke::new(1.0, colors().border))
                .corner_radius(R_CARD)
                .inner_margin(pad(SPACE_XS, SPACE_XS))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        for (tab, label, badge) in [
                            (Tab::Overview, "Overview", waiting),
                            (Tab::Activity, "Activity", 0),
                            (Tab::Network, "Network", 0),
                        ] {
                            let selected = self.tab == tab;
                            let progress = ui.ctx().animate_bool_with_time(
                                egui::Id::new(("tab-selected", label)),
                                selected,
                                0.12,
                            );
                            let mut button =
                                egui::Button::new(RichText::new(label).font(semibold(BODY)).color(
                                    if selected {
                                        colors().text
                                    } else {
                                        colors().muted
                                    },
                                ))
                                .corner_radius(R_CONTROL)
                                .min_size(egui::vec2(112.0, CONTROL_H_SM))
                                .fill(Color32::from_rgba_unmultiplied(
                                    colors().raised.r(),
                                    colors().raised.g(),
                                    colors().raised.b(),
                                    (progress * 255.0) as u8,
                                ))
                                .stroke(Stroke::new(
                                    1.0,
                                    colors().border_strong.gamma_multiply(progress),
                                ));
                            if badge > 0 {
                                button = button.right_text(
                                    RichText::new(badge.to_string())
                                        .font(mono(SMALL))
                                        .color(colors().amber),
                                );
                            }
                            ui.horizontal(|ui| {
                                tab_icon(
                                    ui,
                                    tab,
                                    self.icons_available,
                                    if selected {
                                        colors().text
                                    } else {
                                        colors().muted
                                    },
                                );
                                if ui
                                    .add(button)
                                    .on_hover_cursor(CursorIcon::PointingHand)
                                    .clicked()
                                {
                                    self.tab = tab;
                                }
                            });
                        }
                    });
                });
            ui.add_space(SPACE_L);
        }

        fn status_bar(&mut self, ui: &mut egui::Ui, state: TrayState) {
            ui.horizontal(|ui| {
                let paused = state == TrayState::Paused;
                dot(
                    ui,
                    if paused {
                        colors().subtle
                    } else {
                        colors().green
                    },
                    4.0,
                );
                ui.label(
                    RichText::new(format!("Proxy on http://{}", self.listen))
                        .size(SMALL)
                        .color(colors().muted),
                );
                let copied = self
                    .address_copied
                    .is_some_and(|at| at.elapsed() < FEEDBACK);
                let copy = ui
                    .add(quiet_button(if copied { "Copied" } else { "Copy" }))
                    .on_hover_text("Copy the proxy address, for HTTPS_PROXY");
                if copy.clicked() {
                    copy_to_clipboard(&format!("http://{}", self.listen));
                    self.address_copied = Some(Instant::now());
                    ui.ctx().request_repaint_after(FEEDBACK);
                }
                if let Some(path) = &self.events_path {
                    let open = ui
                        .add(quiet_button("Open log"))
                        .on_hover_text(path.display().to_string());
                    if open.clicked() {
                        self.open_log();
                    }
                }
                if self.firewall_connected {
                    ui.add_space(SPACE_S);
                    dot(ui, colors().green, 4.0);
                    ui.label(
                        RichText::new("Firewall prompt on")
                            .size(SMALL)
                            .color(colors().muted),
                    )
                    .on_hover_text("Connected to the Gatewizz firewall service");
                }
                if let Some((at, ok, message)) = &self.firewall_result {
                    let shown = RESULT_SHOWN;
                    if at.elapsed() < shown {
                        ui.add_space(SPACE_S);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("Firewall: {message}"))
                                    .size(SMALL)
                                    .color(if *ok { colors().green } else { colors().red }),
                            )
                            .truncate(),
                        );
                        ui.ctx().request_repaint_after(shown - at.elapsed());
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(quiet_button("Hide to tray"))
                        .on_hover_text("Gatewizz keeps running in the notification area")
                        .clicked()
                    {
                        let ctx = ui.ctx().clone();
                        self.show(&ctx, false);
                    }
                    let (text, hint) = if paused {
                        ("Resume approvals", "Hold requests for review again")
                    } else {
                        (
                            "Pause approvals",
                            "Block every request that needs approval until resumed",
                        )
                    };
                    if ui.add(quiet_button(text)).on_hover_text(hint).clicked() {
                        self.set_paused(!paused);
                    }
                });
            });
        }

        fn paused_banner(&mut self, ui: &mut egui::Ui) {
            egui::Frame::new()
                .fill(tint(colors().amber))
                .stroke(Stroke::new(1.0, colors().amber.gamma_multiply(0.45)))
                .corner_radius(R_CARD)
                .inner_margin(pad(SPACE_L, SPACE_S))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        dot(ui, colors().amber, 4.0);
                        ui.label(
                            RichText::new(
                                "Approvals are paused. Requests that need approval are blocked.",
                            )
                            .size(BODY)
                            .color(colors().text),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add(button("Resume", colors().amber, colors().bg))
                                .clicked()
                            {
                                self.set_paused(false);
                            }
                        });
                    });
                });
            ui.add_space(SPACE_M);
        }

        fn overview(&mut self, ui: &mut egui::Ui, pending: &[(u64, Held, Duration)]) {
            // While requests wait, the decision gets the space; the summary returns once the queue is clear.
            if pending.is_empty() && self.inbox.is_empty() {
                let loaded = self.history.len();
                let allowed = self
                    .history
                    .iter()
                    .filter(|event| event.decision() == "allow")
                    .count();
                let blocked = self
                    .history
                    .iter()
                    .filter(|event| event.decision() == "block")
                    .count();
                let logged = self.events_path.is_some();
                let source = if logged {
                    "latest entries in the event log"
                } else {
                    "event log disabled"
                };
                let live_connections = self
                    .network
                    .as_ref()
                    .map(|network| network.snapshot().connections.len());
                card().inner_margin(pad(SPACE_M, SPACE_L)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal_wrapped(|ui| {
                        caption(ui, "SYSTEM COMPONENTS");
                        ui.add_space(SPACE_S);
                        status_pill(ui, "Proxy running", colors().green);
                        status_pill(
                            ui,
                            if self.firewall_connected {
                                "Firewall connected"
                            } else {
                                "Firewall not connected"
                            },
                            if self.firewall_connected {
                                colors().green
                            } else {
                                colors().subtle
                            },
                        );
                        status_pill(
                            ui,
                            if self.network.is_some() {
                                "Connection monitor on"
                            } else {
                                "Connection monitor off"
                            },
                            if self.network.is_some() {
                                colors().green
                            } else {
                                colors().subtle
                            },
                        );
                    });
                });
                ui.add_space(SPACE_M);
                ui.columns(4, |columns| {
                    stat_card(
                        &mut columns[0],
                        "Loaded events",
                        loaded,
                        colors().blue,
                        source,
                    );
                    stat_card(&mut columns[1], "Allowed", allowed, colors().green, source);
                    stat_card(&mut columns[2], "Blocked", blocked, colors().red, source);
                    stat_card(
                        &mut columns[3],
                        "Live connections",
                        live_connections.unwrap_or(0),
                        if live_connections.is_some() {
                            colors().green
                        } else {
                            colors().subtle
                        },
                        if live_connections.is_some() {
                            "currently observed"
                        } else {
                            "monitor disabled"
                        },
                    );
                });
                ui.add_space(SPACE_L);
            }

            egui::Panel::left("approval_queue")
                .resizable(false)
                .exact_size(290.0)
                .show_separator_line(false)
                .frame(egui::Frame::new().inner_margin(Margin {
                    right: 16,
                    ..Margin::ZERO
                }))
                .show(ui, |ui| self.queue(ui, pending));

            let selected = self
                .selected
                .and_then(|id| pending.iter().find(|p| p.0 == id));
            let notice = self
                .notice_selected
                .and_then(|id| self.inbox.get(id))
                .cloned();
            match (selected, notice) {
                (Some((id, held, left)), _) => self.request(ui, *id, held, *left),
                (None, Some(notice)) => self.connection(ui, &notice),
                (None, None) => self.latest_activity(ui),
            }
        }

        fn queue(&mut self, ui: &mut egui::Ui, pending: &[(u64, Held, Duration)]) {
            ui.horizontal(|ui| {
                caption(ui, "APPROVAL QUEUE");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new((pending.len() + self.inbox.len()).to_string())
                            .font(mono(SMALL))
                            .color(colors().muted),
                    );
                });
            });
            ui.add_space(SPACE_XS);
            if pending.is_empty() && self.inbox.is_empty() {
                card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.vertical_centered(|ui| {
                        ui.add_space(SPACE_L);
                        check_icon(ui, colors().green, 40.0);
                        ui.add_space(SPACE_S);
                        ui.label(
                            RichText::new("Queue is clear")
                                .font(semibold(SUBHEAD))
                                .color(colors().text),
                        );
                        ui.label(
                            RichText::new(if self.firewall_connected {
                                "Held requests and blocked connections appear here and open this window."
                            } else {
                                "Held requests appear here and open this window."
                            })
                            .size(SMALL)
                            .color(colors().muted),
                        );
                        ui.add_space(SPACE_L);
                    });
                });
                return;
            }
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (id, held, left) in pending {
                        let active = self.selected == Some(*id);
                        let response = egui::Frame::new()
                            .fill(if active {
                                colors().raised
                            } else {
                                colors().surface
                            })
                            .stroke(Stroke::new(
                                if active { 1.5 } else { 1.0 },
                                if active {
                                    colors().blue
                                } else {
                                    colors().border
                                },
                            ))
                            .corner_radius(R_CARD)
                            .inner_margin(pad(SPACE_M, SPACE_M))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(program(&held.process))
                                                .font(semibold(SUBHEAD))
                                                .color(colors().text),
                                        )
                                        .truncate(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        badge(ui, &countdown(*left), urgency(*left));
                                    });
                                });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&held.host)
                                            .font(mono(SMALL))
                                            .color(colors().muted),
                                    )
                                    .truncate(),
                                );
                                let (findings, color) = match held.findings.len() {
                                    0 => ("Held by rule".to_string(), colors().subtle),
                                    1 => ("1 finding".to_string(), colors().amber),
                                    n => (format!("{n} findings"), colors().amber),
                                };
                                ui.label(RichText::new(findings).size(SMALL).color(color));
                            })
                            .response
                            .interact(Sense::click())
                            .on_hover_cursor(CursorIcon::PointingHand);
                        if response.clicked() {
                            self.selected = Some(*id);
                        }
                        ui.add_space(SPACE_XS);
                    }
                    let notices: Vec<Notice> = self.inbox.notices().cloned().collect();
                    for notice in &notices {
                        let active =
                            self.selected.is_none() && self.notice_selected == Some(notice.id);
                        let response = egui::Frame::new()
                            .fill(if active { colors().raised } else { colors().surface })
                            .stroke(Stroke::new(
                                if active { 1.5 } else { 1.0 },
                                if active { colors().blue } else { colors().border },
                            ))
                            .corner_radius(R_CARD)
                            .inner_margin(pad(SPACE_M, SPACE_M))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&notice.program)
                                                .font(semibold(SUBHEAD))
                                                .color(colors().text),
                                        )
                                        .truncate(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if notice.held {
                                            badge(ui, "Waiting", colors().amber);
                                        } else {
                                            badge(ui, "Blocked", colors().red);
                                        }
                                    });
                                });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(destination(
                                            notice.remote,
                                            notice.port,
                                            notice.protocol,
                                        ))
                                        .font(mono(SMALL))
                                        .color(colors().muted),
                                    )
                                    .truncate(),
                                );
                                let attempts = match notice.count {
                                    1 => "Connection · 1 attempt".to_string(),
                                    n => format!("Connection · {n} attempts"),
                                };
                                ui.label(
                                    RichText::new(attempts).size(SMALL).color(colors().subtle),
                                );
                            })
                            .response
                            .interact(Sense::click())
                            .on_hover_cursor(CursorIcon::PointingHand);
                        if response.clicked() {
                            self.selected = None;
                            self.notice_selected = Some(notice.id);
                        }
                        ui.add_space(SPACE_XS);
                    }
                });
        }

        /// A connection the firewall blocked and asks about. Unlike a held request it has no timer: it is blocked
        /// already, and the app retries once a rule allows it.
        fn connection(&mut self, ui: &mut egui::Ui, notice: &Notice) {
            // A widening picked for one notice never carries over to another (another selection, an expiry, or a
            // repeat folding in under a new id).
            if self.scope_for != Some(notice.id) {
                self.scope_for = Some(notice.id);
                self.any_host = false;
                self.any_port = false;
            }
            let mut decision = None;
            egui::Panel::bottom("connection_decision")
                .resizable(false)
                .show_separator_line(false)
                .frame(egui::Frame::new().inner_margin(Margin {
                    top: 12,
                    ..Margin::ZERO
                }))
                .show(ui, |ui| {
                    decision = self.connection_decision(ui, notice);
                });
            let protocol = destination(notice.remote, notice.port, notice.protocol);
            let protocol = protocol.rsplit(' ').next().unwrap_or_default().to_string();
            card().inner_margin(pad(SPACE_XL, SPACE_XL)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height());
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            caption(
                                ui,
                                if notice.held {
                                    "CONNECTION WAITING"
                                } else {
                                    "CONNECTION BLOCKED"
                                },
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if notice.held {
                                    badge(ui, "Held", colors().amber);
                                } else {
                                    badge(ui, "Firewall", colors().red);
                                }
                            });
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(&notice.program).font(semibold(DISPLAY)).color(colors().text),
                            )
                            .truncate(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(destination(notice.remote, notice.port, notice.protocol))
                                    .font(mono(SUBHEAD))
                                    .color(colors().blue),
                            )
                            .wrap(),
                        );
                        ui.add_space(SPACE_L);
                        caption(ui, if notice.held { "WHY IT IS WAITING" } else { "WHY IT WAS BLOCKED" });
                        ui.label(
                            RichText::new(if notice.held {
                                "No connection rule allows this, and the firewall asks about it. The connection is \
                                 held: allowed, it simply goes on; denied or left unanswered, the program is told \
                                 the connection was refused."
                            } else {
                                "No connection rule allows this, and the firewall asks about it. The first attempt \
                                 has failed; most programs retry once a rule allows them."
                            })
                            .size(BODY)
                            .color(colors().muted),
                        );
                        ui.add_space(SPACE_L);
                        caption(ui, "CONNECTION");
                        let (address, port, attempts) = (
                            notice.remote.to_string(),
                            notice.port.to_string(),
                            notice.count.to_string(),
                        );
                        details(
                            ui,
                            "blocked_connection",
                            &[
                                ("Program", &notice.path),
                                ("Address", &address),
                                ("Port", &port),
                                ("Protocol", &protocol),
                                ("Attempts", &attempts),
                            ],
                        );
                    });
            });
            if let Some(decision) = decision {
                let sent = self.firewall.send(&Message::Decision(decision));
                self.inbox.take(notice.id);
                self.notice_selected = None;
                if !sent {
                    self.firewall_result = Some((
                        Instant::now(),
                        false,
                        "the firewall service is not connected; the connection stays blocked"
                            .into(),
                    ));
                }
            }
        }

        /// Deny always, allow once, for one of the service's durations, or always; scoped to this address and port
        /// unless widened.
        fn connection_decision(&mut self, ui: &mut egui::Ui, notice: &Notice) -> Option<Decision> {
            let mut answer = None;
            card().inner_margin(pad(SPACE_L, SPACE_L)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
                    let deny = button("Deny always", Color32::TRANSPARENT, colors().red)
                        .stroke(Stroke::new(1.0, colors().red.gamma_multiply(0.7)))
                        .min_size(egui::vec2(width, CONTROL_H_LG));
                    if ui
                        .add(deny)
                        .on_hover_text("Keep blocking, and stop asking")
                        .clicked()
                    {
                        answer = Some((RuleAction::Block, Lasting::Always));
                    }
                    let allow = button("Allow once", colors().green_fill, Color32::WHITE)
                        .min_size(egui::vec2(width, CONTROL_H_LG));
                    if ui
                        .add(allow)
                        .on_hover_text(
                            "Allow for two minutes, long enough for the program to retry",
                        )
                        .clicked()
                    {
                        answer = Some((RuleAction::Allow, Lasting::Once));
                    }
                });
                ui.add_space(SPACE_M);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Or allow for")
                            .size(SMALL)
                            .color(colors().muted),
                    );
                    // Only the service's durations: it refuses any other.
                    for minutes in crate::prompt::PRESETS {
                        if chip(ui, &duration_label(minutes), self.notice_minutes == minutes)
                            .clicked()
                        {
                            self.notice_minutes = minutes;
                        }
                    }
                });
                ui.add_space(SPACE_S);
                ui.horizontal(|ui| {
                    let grant = quiet_button(&format!(
                        "Allow for {}",
                        duration_label(self.notice_minutes)
                    ))
                    .min_size(egui::vec2(150.0, CONTROL_H));
                    if ui.add(grant).clicked() {
                        answer = Some((RuleAction::Allow, Lasting::Minutes(self.notice_minutes)));
                    }
                    let always =
                        quiet_button("Allow always").min_size(egui::vec2(120.0, CONTROL_H));
                    if ui
                        .add(always)
                        .on_hover_text("Add a permanent rule to the firewall configuration")
                        .clicked()
                    {
                        answer = Some((RuleAction::Allow, Lasting::Always));
                    }
                });
                ui.add_space(SPACE_S);
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut self.any_host, "Any address");
                    ui.checkbox(&mut self.any_port, "Any port");
                });
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "The rule covers only {}. Closing the window {}.",
                            prompt_scope(
                                &notice.program,
                                notice.remote,
                                notice.port,
                                self.any_host,
                                self.any_port,
                            ),
                            if notice.held {
                                "refuses it when the hold runs out"
                            } else {
                                "keeps it blocked"
                            }
                        ))
                        .size(SMALL)
                        .color(colors().subtle),
                    )
                    .wrap(),
                );
            });
            answer.map(|(action, lasting)| Decision {
                id: notice.id,
                action,
                lasting,
                any_host: self.any_host,
                any_port: self.any_port,
            })
        }

        fn request(&mut self, ui: &mut egui::Ui, id: u64, held: &Held, left: Duration) {
            let name = program(&held.process);
            let (image, pid, user) = match &held.process {
                Process::Known {
                    image, pid, user, ..
                } => (image.clone(), pid.to_string(), user.clone()),
                Process::Unknown(why) => (
                    format!("Unknown ({why})"),
                    "Unknown".into(),
                    "Unknown".into(),
                ),
            };
            // The decision stays pinned and visible; only the request details scroll.
            let mut verdict = None;
            egui::Panel::bottom("decision")
                .resizable(false)
                .show_separator_line(false)
                .frame(egui::Frame::new().inner_margin(Margin {
                    top: 12,
                    ..Margin::ZERO
                }))
                .show(ui, |ui| {
                    verdict = self.decision(ui, &name, &held.host);
                });
            card().inner_margin(pad(SPACE_XL, SPACE_XL)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height());
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            caption(ui, "APPROVAL REQUIRED");
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                badge(
                                    ui,
                                    &format!("Auto-deny in {}", countdown(left)),
                                    urgency(left),
                                );
                            });
                        });
                        ui.add(
                            egui::Label::new(
                                RichText::new(&name).font(semibold(DISPLAY)).color(colors().text),
                            )
                            .truncate(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(&held.host).font(mono(SUBHEAD)).color(colors().blue),
                            )
                            .wrap(),
                        );
                        ui.add_space(SPACE_L);
                        caption(ui, "WHY IT WAS HELD");
                        if held.findings.is_empty() {
                            ui.label(
                            RichText::new(format!(
                                "Rule \"{}\" asks for approval before traffic reaches this host.",
                                held.rule
                            ))
                            .size(BODY)
                            .color(colors().muted),
                        );
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                for finding in &held.findings {
                                    badge(ui, finding, colors().amber);
                                }
                            });
                        }
                        ui.add_space(SPACE_L);
                        caption(ui, "REQUEST");
                        details(
                            ui,
                            "held_request",
                            &[
                                ("Program", &image),
                                ("Process ID", &pid),
                                ("User", &user),
                                ("Matched rule", &held.rule),
                            ],
                        );
                        ui.add_space(SPACE_L);
                        caption(ui, "CONTENT");
                        match &held.request {
                            Some(text) => {
                                egui::Frame::new()
                                    .fill(ui.visuals().extreme_bg_color)
                                    .stroke(Stroke::new(1.0, colors().border))
                                    .corner_radius(R_CONTROL)
                                    .inner_margin(pad(SPACE_M, SPACE_S))
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        egui::ScrollArea::vertical()
                                            .id_salt("held_preview")
                                            .max_height(220.0)
                                            .show(ui, |ui| {
                                                ui.add(
                                                    egui::Label::new(
                                                        RichText::new(text)
                                                            .font(mono(SMALL))
                                                            .color(colors().muted),
                                                    )
                                                    .wrap(),
                                                );
                                            });
                                    });
                            }
                            None => {
                                ui.label(
                                    RichText::new(
                                        "Not visible: this HTTPS connection is tunneled. Turn on TLS interception \
                                         (intercept = true) to see a request before you allow it.",
                                    )
                                    .size(BODY)
                                    .color(colors().muted),
                                );
                            }
                        }
                    });
            });
            if let Some(verdict) = verdict {
                self.approvals.answer(id, verdict);
                self.selected = None;
            }
        }

        /// Deny, allow once, or allow this program and host for a while.
        fn decision(&mut self, ui: &mut egui::Ui, name: &str, host: &str) -> Option<Verdict> {
            let mut verdict = None;
            card().inner_margin(pad(SPACE_L, SPACE_L)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
                    let deny = button("Deny", Color32::TRANSPARENT, colors().red)
                        .stroke(Stroke::new(1.0, colors().red.gamma_multiply(0.7)))
                        .min_size(egui::vec2(width, CONTROL_H_LG));
                    if ui.add(deny).on_hover_text("Block this request").clicked() {
                        verdict = Some(Verdict::Deny);
                    }
                    let allow = button("Allow once", colors().green_fill, Color32::WHITE).min_size(egui::vec2(width, CONTROL_H_LG));
                    if ui.add(allow).on_hover_text("Send this request only").clicked() {
                        verdict = Some(Verdict::AllowOnce);
                    }
                });
                ui.add_space(SPACE_M);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Or allow for").size(SMALL).color(colors().muted));
                    for minutes in [5, 15, 60, 480] {
                        if chip(ui, &duration_label(minutes), self.minutes == minutes).clicked() {
                            self.minutes = minutes;
                        }
                    }
                    ui.add(egui::DragValue::new(&mut self.minutes).range(1..=480).suffix(" min"))
                        .on_hover_text("Custom duration, 1 to 480 minutes");
                });
                ui.add_space(SPACE_S);
                ui.horizontal(|ui| {
                    let grant = quiet_button(&format!("Allow for {}", duration_label(self.minutes)))
                        .min_size(egui::vec2(150.0, CONTROL_H));
                    if ui.add(grant).clicked() {
                        verdict = Some(Verdict::AllowFor(Duration::from_secs(
                            u64::from(self.minutes) * 60,
                        )));
                    }
                    ui.add_space(SPACE_XS);
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "Covers only {name} connecting to {host}. Closing the window or letting the timer run out denies the request."
                            ))
                            .size(SMALL)
                            .color(colors().subtle),
                        )
                        .wrap(),
                    );
                });
            });
            verdict
        }

        /// Shown beside an empty queue: the latest decisions, one click away from their details.
        fn latest_activity(&mut self, ui: &mut egui::Ui) {
            card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height());
                ui.horizontal(|ui| {
                    caption(ui, "LATEST ACTIVITY");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !self.history.is_empty() && ui.add(quiet_button("View all")).clicked() {
                            self.tab = Tab::Activity;
                        }
                    });
                });
                ui.add_space(SPACE_XS);
                if self.history.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(SPACE_XXL);
                        check_icon(ui, colors().green, 48.0);
                        ui.add_space(SPACE_S);
                        ui.label(
                            RichText::new("You're all caught up")
                                .font(semibold(TITLE))
                                .color(colors().text),
                        );
                        ui.label(
                            RichText::new(self.empty_history_message())
                                .size(SMALL)
                                .color(colors().muted),
                        );
                    });
                    return;
                }
                history_header(ui);
                ui.spacing_mut().item_spacing.y = 2.0;
                let rows = ((ui.available_height() - 8.0) / 38.0).max(1.0) as usize;
                let mut open = None;
                for (index, event) in self.history.iter().enumerate().take(rows) {
                    if history_row(ui, event, false).clicked() {
                        open = Some(index);
                    }
                }
                if let Some(index) = open {
                    self.history_selected = Some(index);
                    self.tab = Tab::Activity;
                }
            });
        }

        /// Live connections per program (#57). Read-only: the monitor never blocks anything.
        fn network(&mut self, ui: &mut egui::Ui) {
            let Some(live) = self.network.clone() else {
                card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    caption(ui, "CONNECTION MONITOR IS OFF");
                    ui.add_space(SPACE_XS);
                    ui.label(
                        RichText::new(
                            "Turn it on to see every outgoing TCP connection on this computer, per program, with \
                             the hostname where Windows' DNS cache knows it. It only watches; nothing is blocked.",
                        )
                        .size(BODY)
                        .color(colors().muted),
                    );
                    ui.add_space(SPACE_S);
                    ui.label(
                        RichText::new("[monitor]\nenabled = true")
                            .font(mono(SMALL))
                            .color(colors().text),
                    );
                    ui.add_space(SPACE_XS);
                    ui.label(
                        RichText::new("Add this to your configuration file and restart Gatewizz.")
                            .size(SMALL)
                            .color(colors().subtle),
                    );
                });
                return;
            };
            // The sampler updates about once a second; follow it while this tab is visible.
            ui.ctx().request_repaint_after(Duration::from_secs(1));
            let state = live.snapshot();
            let groups = network_groups(&state.connections, &self.network_filter);
            let new = state.connections.iter().filter(|c| c.first_seen).count();

            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.network_filter)
                        .hint_text("Search program, host or IP")
                        .desired_width(240.0)
                        .margin(pad(SPACE_M, SPACE_S)),
                );
                ui.add_space(SPACE_S);
                ui.label(
                    RichText::new(format!(
                        "{} connections · {} programs · {new} new",
                        state.connections.len(),
                        groups.len()
                    ))
                    .font(mono(SMALL))
                    .color(colors().muted),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let age = state.sampled.map(|at| at.elapsed().as_secs());
                    let text = match age {
                        Some(0 | 1) => "Live".to_string(),
                        Some(secs) => format!("Updated {secs} s ago"),
                        None => "Starting…".to_string(),
                    };
                    ui.label(RichText::new(text).size(SMALL).color(colors().subtle));
                });
            });
            ui.add_space(SPACE_M);
            if let Some(error) = &state.error {
                card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        dot(ui, colors().red, 4.0);
                        ui.label(RichText::new(error).size(BODY).color(colors().text));
                    });
                });
                ui.add_space(SPACE_M);
            }
            if let Some(error) = &state.dns_error {
                ui.horizontal(|ui| {
                    dot(ui, colors().amber, 3.5);
                    ui.label(
                        RichText::new(format!("Hostnames unavailable: {error}"))
                            .size(SMALL)
                            .color(colors().muted),
                    );
                });
                ui.add_space(SPACE_S);
            }
            if groups.is_empty() {
                ui.add_space(SPACE_XL);
                ui.vertical_centered(|ui| {
                    check_icon(ui, colors().green, 40.0);
                    ui.add_space(SPACE_S);
                    ui.label(
                        RichText::new(if self.network_filter.trim().is_empty() {
                            "No outgoing connections right now."
                        } else {
                            "No connection matches the search."
                        })
                        .size(BODY)
                        .color(colors().muted),
                    );
                });
                return;
            }
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (name, list) in &groups {
                        card()
                            .inner_margin(pad(SPACE_L, SPACE_M))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(name).font(semibold(SUBHEAD)).color(colors().text));
                                    ui.label(
                                        RichText::new(format!("{}", list.len()))
                                            .font(mono(SMALL))
                                            .color(colors().subtle),
                                    );
                                    // Several instances of one program share a group; name the PID only
                                    // when there is one.
                                    let label = match process_ids(list).as_slice() {
                                        [] => None,
                                        [pid] => Some(format!("PID {pid}")),
                                        pids => Some(format!("{} processes", pids.len())),
                                    };
                                    if let Some(label) = label {
                                        ui.label(
                                            RichText::new(label).font(mono(CAPTION)).color(colors().subtle),
                                        );
                                    }
                                });
                                ui.add_space(SPACE_S);
                                for conn in list {
                                    // Scale the two long fields to the available width instead of
                                    // reserving 500 px even when the window is at its minimum size.
                                    let row_width = ui.available_width();
                                    let host_width = (row_width * 0.38).clamp(140.0, 280.0);
                                    let remote_width = (row_width * 0.30).clamp(120.0, 220.0);
                                    ui.horizontal(|ui| {
                                        let host = conn
                                            .hostname
                                            .clone()
                                            .unwrap_or_else(|| conn.remote.ip().to_string());
                                        dot(
                                            ui,
                                            if conn.first_seen { colors().amber } else { colors().green },
                                            3.5,
                                        );
                                        ui.add_sized(
                                            [host_width, 20.0],
                                            egui::Label::new(
                                                RichText::new(host).size(BODY).color(colors().text),
                                            )
                                            .truncate(),
                                        );
                                        ui.add_sized(
                                            [remote_width, 20.0],
                                            egui::Label::new(
                                                RichText::new(conn.remote.to_string())
                                                    .font(mono(SMALL))
                                                    .color(colors().muted),
                                            )
                                            .truncate(),
                                        );
                                        ui.label(
                                            RichText::new(match conn.direction {
                                                Direction::Outbound => "TCP out",
                                                Direction::Inbound => "TCP in",
                                            })
                                            .size(SMALL)
                                            .color(colors().subtle),
                                        );
                                        if conn.first_seen {
                                            badge(ui, "New", colors().amber);
                                        }
                                    })
                                    .response
                                    .on_hover_text(if conn.first_seen {
                                        "First connection from this program to this host since Gatewizz started"
                                    } else {
                                        "Seen before since Gatewizz started"
                                    });
                                }
                            });
                        ui.add_space(SPACE_S);
                    }
                });
        }

        fn empty_history_message(&self) -> &'static str {
            if self.events_path.is_some() {
                "No events recorded yet. New requests appear here automatically."
            } else {
                "Activity history is off because events are written to stdout."
            }
        }

        fn activity(&mut self, ui: &mut egui::Ui) {
            let rows = &self.history;
            let count = |decision: &str| {
                rows.iter()
                    .filter(|event| event.decision() == decision)
                    .count()
            };
            let counts = [
                ("all", "All", rows.len()),
                ("allow", "Allowed", count("allow")),
                ("block", "Blocked", count("block")),
                ("approve", "Approved", count("approve")),
            ];
            let filtered = filter_history(rows, &self.history_filter, &self.history_decision);

            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.history_filter)
                        .hint_text("Search program or host")
                        .desired_width(220.0)
                        .margin(pad(SPACE_M, SPACE_S)),
                );
                ui.add_space(SPACE_S);
                for (value, label, n) in counts {
                    if chip(ui, &format!("{label}  {n}"), self.history_decision == value).clicked()
                    {
                        self.history_decision = value.into();
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let copied = self.csv_copied.filter(|(at, _)| at.elapsed() < FEEDBACK);
                    let text = match copied {
                        Some((_, n)) => format!("Copied {n} rows"),
                        None => "Copy CSV".into(),
                    };
                    let copy = ui
                        .add_enabled(!filtered.is_empty(), quiet_button(&text))
                        .on_hover_text("Copy the filtered rows' metadata to the clipboard");
                    if copy.clicked() {
                        copy_to_clipboard(&history_csv(&filtered));
                        self.csv_copied = Some((Instant::now(), filtered.len()));
                        ui.ctx().request_repaint_after(FEEDBACK);
                    }
                    ui.label(
                        RichText::new(format!("{} of {}", filtered.len(), rows.len()))
                            .font(mono(SMALL))
                            .color(colors().subtle),
                    );
                });
            });
            ui.add_space(SPACE_M);

            egui::Panel::bottom("privacy_note")
                .show_separator_line(false)
                .frame(egui::Frame::new().inner_margin(Margin { top: 8, ..Margin::ZERO }))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Metadata only. Request bodies, header values, query strings and secrets are never stored or exported.")
                            .size(CAPTION)
                            .color(colors().subtle),
                    );
                });

            let mut selected = self.history_selected.filter(|index| *index < rows.len());
            if let Some(event) = selected.and_then(|index| rows.get(index)) {
                egui::Panel::right("event_details")
                    .resizable(false)
                    .exact_size(310.0)
                    .show_separator_line(false)
                    .frame(egui::Frame::new().inner_margin(Margin {
                        left: 16,
                        ..Margin::ZERO
                    }))
                    .show(ui, |ui| {
                        if event_details(ui, event) {
                            selected = None;
                        }
                    });
            }

            card().inner_margin(pad(SPACE_S, SPACE_S)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height());
                if rows.is_empty() || filtered.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(SPACE_XXL);
                        let (title, message) = if rows.is_empty() {
                            ("No activity yet", self.empty_history_message())
                        } else {
                            (
                                "No matching events",
                                "Try another search or decision filter.",
                            )
                        };
                        check_icon(
                            ui,
                            if rows.is_empty() {
                                colors().green
                            } else {
                                colors().blue
                            },
                            40.0,
                        );
                        ui.add_space(SPACE_S);
                        ui.label(
                            RichText::new(title)
                                .font(semibold(SUBHEAD))
                                .color(colors().text),
                        );
                        ui.label(RichText::new(message).size(SMALL).color(colors().muted));
                    });
                    return;
                }
                history_header(ui);
                ui.spacing_mut().item_spacing.y = 2.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, 36.0, filtered.len(), |ui, range| {
                        for event in &filtered[range] {
                            let index = rows
                                .iter()
                                .position(|row| std::ptr::eq(row, *event))
                                .unwrap_or(usize::MAX);
                            let active = selected == Some(index);
                            if history_row(ui, event, active).clicked() {
                                selected = if active { None } else { Some(index) };
                            }
                        }
                    });
            });
            self.history_selected = selected;
        }

        fn set_paused(&mut self, paused: bool) {
            self.approvals.set_paused(paused);
            self.items
                .pause
                .set_text(if paused { "Resume" } else { "Pause" });
        }

        fn open_log(&self) {
            if let Some(path) = &self.events_path {
                // Opens the file with its default app, as a double click would.
                let _ = std::process::Command::new("explorer").arg(path).spawn();
            }
        }
    }

    /// The selected activity event. Returns true when the user closes it.
    fn event_details(ui: &mut egui::Ui, event: &HistoryEvent) -> bool {
        let mut close = false;
        card().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                caption(ui, "EVENT DETAILS");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    close = ui.add(quiet_button("Close")).clicked();
                });
            });
            ui.add(
                egui::Label::new(
                    RichText::new(event.process_name())
                        .font(semibold(TITLE))
                        .color(colors().text),
                )
                .truncate(),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{}:{}", event.host, event.port))
                        .font(mono(BODY))
                        .color(colors().blue),
                )
                .wrap(),
            );
            ui.add_space(SPACE_S);
            let (label, color) = decision_style(event);
            ui.horizontal(|ui| {
                badge(ui, label, color);
                badge(
                    ui,
                    &format!("HTTP {}", event.status),
                    if event.status >= 400 {
                        colors().red
                    } else {
                        colors().subtle
                    },
                );
            });
            ui.add_space(SPACE_M);
            let when = format!("{} UTC", event.time.replace('T', " ").trim_end_matches('Z'));
            let path = if event.path.is_empty() {
                "(CONNECT tunnel)"
            } else {
                &event.path
            };
            let mut rows = vec![
                ("Time", when.as_str()),
                ("Method", event.method.as_str()),
                ("Path", path),
                ("Coverage", event.coverage.as_str()),
                ("Rule", event.rule.as_deref().unwrap_or("Default action")),
            ];
            if let Some(model) = &event.model {
                rows.push(("Model", model));
            }
            if let Some(reason) = &event.reason {
                rows.push(("Reason", reason));
            }
            details(ui, "event_details_grid", &rows);
        });
        close
    }

    impl eframe::App for App {
        fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            if self.shown && self.last_theme_check.elapsed() >= Duration::from_secs(3) {
                self.last_theme_check = Instant::now();
                let palette = system_palette();
                if palette != colors() {
                    set_colors(palette);
                    let _ = setup_style(ctx);
                }
            }
            if self.shown && self.last_geometry_save.elapsed() >= Duration::from_secs(2) {
                self.last_geometry_save = Instant::now();
                if let (Some(path), Some(rect)) = (
                    self.geometry_path.as_deref(),
                    ctx.input(|input| input.viewport().outer_rect),
                ) {
                    let geometry = clamp_geometry(WindowGeometry {
                        x: rect.left(),
                        y: rect.top(),
                        width: rect.width(),
                        height: rect.height(),
                    });
                    let changed = self.saved_geometry.is_none_or(|previous| {
                        (previous.x - geometry.x).abs() > 2.0
                            || (previous.y - geometry.y).abs() > 2.0
                            || (previous.width - geometry.width).abs() > 2.0
                            || (previous.height - geometry.height).abs() > 2.0
                    });
                    if changed && save_geometry(path, geometry).is_ok() {
                        self.saved_geometry = Some(geometry);
                    }
                }
            }
            while let Ok(history) = self.history_rx.try_recv() {
                self.history = history;
            }
            while let Ok(wake) = self.wake.try_recv() {
                match wake {
                    Wake::Tray(TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }) => self.show(ctx, true),
                    Wake::Tray(_) => {}
                    Wake::Menu(event) => self.on_menu(ctx, &event),
                }
            }
            while let Ok(event) = self.firewall_events.try_recv() {
                match event {
                    pipe::Event::Connected => self.firewall_connected = true,
                    pipe::Event::Disconnected => {
                        // A restarted service does not know these ids; the connections stay blocked.
                        self.firewall_connected = false;
                        self.inbox.clear();
                    }
                    // Paused means nothing is asked: the connection stays blocked (fail closed).
                    pipe::Event::Message(Message::Notice(notice)) if !self.approvals.paused() => {
                        self.inbox.add(notice, Instant::now());
                    }
                    pipe::Event::Message(Message::Result { ok, message, .. }) => {
                        self.firewall_result = Some((Instant::now(), ok, message));
                    }
                    pipe::Event::Message(_) => {}
                }
            }
            self.inbox.expire(Instant::now());
            if !self.inbox.is_empty() {
                // Expiry needs a frame now and then, also while hidden.
                ctx.request_repaint_after(INBOX_TICK);
            }
            let waiting = self.approvals.pending().len() + self.inbox.len();
            // A newly held request or blocked connection opens the window.
            if waiting > self.waiting {
                self.show(ctx, true);
            }
            self.waiting = waiting;
            let state = TrayState::of(self.approvals.paused(), waiting);
            if self.state != Some(state) {
                self.state = Some(state);
                let _ = self._tray.set_icon(Some(icon(state)));
                let _ = self._tray.set_tooltip(Some(state.tooltip(waiting)));
            }
            // The proxy stopped on its own (Ctrl+C or an error): close the UI too.
            if self.proxy.as_ref().is_some_and(JoinHandle::is_finished) {
                self.quit(ctx);
            }
        }

        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            let ctx = ui.ctx().clone();
            let pending = self.approvals.pending();

            if ctx.input(|i| i.viewport().close_requested()) && self.quit.is_some() {
                // Closing the workspace means dismissing every pending request, then hiding to the tray.
                ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                for (id, _, _) in &pending {
                    self.approvals.answer(*id, Verdict::Deny);
                }
                // Blocked connections stay blocked; they are only no longer asked about.
                self.inbox.clear();
                self.selected = None;
                self.notice_selected = None;
                self.show(&ctx, false);
                return;
            }

            // One item is shown: the held request or the blocked connection the user picked, else the first held
            // request (their timers run), else the first blocked connection.
            let notice_shown = self
                .notice_selected
                .is_some_and(|id| self.inbox.get(id).is_some());
            if !self
                .selected
                .is_some_and(|id| pending.iter().any(|p| p.0 == id))
            {
                self.selected = if notice_shown {
                    None
                } else {
                    pending.first().map(|p| p.0)
                };
            }
            if self.selected.is_none() && !notice_shown {
                self.notice_selected = self.inbox.notices().next().map(|n| n.id);
            }
            let waiting = pending.len() + self.inbox.len();
            let state = TrayState::of(self.approvals.paused(), waiting);

            egui::Panel::top("header")
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(colors().bg).inner_margin(Margin {
                    left: 20,
                    right: 20,
                    top: 16,
                    bottom: 0,
                }))
                .show(ui, |ui| self.header(ui, state, waiting));
            egui::Panel::bottom("status_bar")
                .frame(
                    egui::Frame::new()
                        .fill(colors().surface)
                        .inner_margin(pad(SPACE_XL, SPACE_S)),
                )
                .show(ui, |ui| self.status_bar(ui, state));
            egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(colors().bg).inner_margin(Margin {
                    left: 20,
                    right: 20,
                    top: 0,
                    bottom: 16,
                }))
                .show(ui, |ui| {
                    if self.approvals.paused() {
                        self.paused_banner(ui);
                    }
                    match self.tab {
                        Tab::Overview => self.overview(ui, &pending),
                        Tab::Activity => self.activity(ui),
                        Tab::Network => self.network(ui),
                    }
                });

            if !pending.is_empty() {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
        }

        fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
            let _ = self.history_stop.send(());
            if let Some(worker) = self.history_worker.take() {
                let _ = worker.join();
            }
            self.approvals.set_paused(true);
            if let Some(quit) = self.quit.take() {
                let _ = quit.send(());
            }
            let result = self.proxy.take().map(|p| {
                p.join()
                    .unwrap_or_else(|_| Err("[network] proxy panicked".into()))
            });
            *APP_RESULT.lock().expect("result poisoned") = result;
        }
    }

    #[cfg(test)]
    mod history_tests {
        use super::*;

        #[test]
        fn connection_records_are_not_activity_rows() {
            let dir =
                std::env::temp_dir().join(format!("gatewizz-history-kind-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("events.jsonl");
            std::fs::write(
                &path,
                concat!(
                    r#"{"time":"2026-11-20T11:00:00Z","host":"example.com","status":200,"action":"allow"}"#,
                    "\n",
                    r#"{"kind":"connection","time":"2026-11-20T11:00:01Z","state":"opened","remote_ip":"1.1.1.1","port":443}"#,
                    "\n",
                ),
            )
            .unwrap();
            let rows = load_history(&path);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].host, "example.com");
        }

        #[test]
        fn bounded_tail_survives_offset_inside_utf8_character() {
            let event = br#"{"time":"2026-11-20T11:00:00Z","host":"example.com","status":200,"action":"allow","process":{"known":{"image":"C:\\Tools\\curl.exe"}}}"#;
            let total_len = MAX_HISTORY_FILE_BYTES as usize + 3;
            let prefix_len = total_len - event.len() - 1;
            let mut bytes = vec![b'a'; prefix_len];
            bytes[1..4].copy_from_slice("€".as_bytes());
            bytes.push(b'\n');
            bytes.extend_from_slice(event);
            assert_eq!(bytes.len(), total_len);

            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock is after UNIX epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "gatewizz-history-{}-{unique}.jsonl",
                std::process::id()
            ));
            std::fs::write(&path, bytes).expect("write test event log");

            let rows = load_history(&path);
            let _ = std::fs::remove_file(&path);

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].host, "example.com");
            assert_eq!(rows[0].process_name(), "curl.exe");
        }

        fn history_rows() -> Vec<HistoryEvent> {
            [
                r#"{"host":"api.openai.com","action":"allow","process":{"known":{"image":"C:\\Tools\\Code.exe"}}}"#,
                r#"{"host":"api.anthropic.com","action":"block","process":{"known":{"image":"C:\\Tools\\curl.exe"}}}"#,
                r#"{"host":"internal.example.com","action":"approve","process":{"unknown":"access denied"}}"#,
                r#"{"host":"example.org"}"#,
                r#"{"host":"denied.example.com","action":"approve","coverage":"blocked","status":403}"#,
            ]
            .iter()
            .map(|line| serde_json::from_str(line).expect("parse test event"))
            .collect()
        }

        fn hosts(rows: &[&HistoryEvent]) -> Vec<String> {
            rows.iter().map(|event| event.host.clone()).collect()
        }

        #[test]
        fn empty_filters_keep_every_row() {
            let rows = history_rows();
            assert_eq!(filter_history(&rows, "", "all").len(), rows.len());
        }

        #[test]
        fn text_filter_matches_host_or_process_case_insensitively() {
            let rows = history_rows();
            assert_eq!(
                hosts(&filter_history(&rows, "ANTHROPIC", "all")),
                ["api.anthropic.com"]
            );
            assert_eq!(
                hosts(&filter_history(&rows, "code.EXE", "all")),
                ["api.openai.com"]
            );
            assert_eq!(
                hosts(&filter_history(&rows, "access denied", "all")),
                ["internal.example.com"]
            );
            assert_eq!(filter_history(&rows, "api.", "all").len(), 2);
        }

        #[test]
        fn decision_filter_matches_each_action() {
            let rows = history_rows();
            assert_eq!(
                hosts(&filter_history(&rows, "", "allow")),
                ["api.openai.com"]
            );
            assert_eq!(
                hosts(&filter_history(&rows, "", "block")),
                ["api.anthropic.com", "denied.example.com"]
            );
            assert_eq!(decision_style(&rows[4]).0, "Denied");
            assert_eq!(
                hosts(&filter_history(&rows, "", "approve")),
                ["internal.example.com"]
            );
        }

        #[test]
        fn both_filters_must_match() {
            let rows = history_rows();
            assert_eq!(
                hosts(&filter_history(&rows, "api.", "block")),
                ["api.anthropic.com"]
            );
            assert!(filter_history(&rows, "openai", "block").is_empty());
            assert!(filter_history(&rows, "no-such-host", "all").is_empty());
        }

        #[test]
        fn csv_uses_crlf_rows_and_quotes_every_field() {
            let event: HistoryEvent = serde_json::from_str(
                r#"{"time":"2026-11-20T11:00:00Z","host":"api.example.com","port":443,"status":403,"action":"block","process":{"known":{"image":"C:\\Tools\\curl.exe"}},"reason":"say \"no\""}"#,
            )
            .expect("parse test event");

            let csv = history_csv(&[&event]);
            let lines: Vec<&str> = csv.split("\r\n").collect();

            assert!(!csv.contains("\\r\\n"));
            assert_eq!(lines.len(), 3, "header, one row, trailing empty: {csv:?}");
            assert!(lines[0].starts_with("time_utc,process,host,"));
            assert!(lines[1].contains("\"curl.exe\",\"api.example.com\",\"443\""));
            assert!(lines[1].contains("\"block\",\"403\""));
            assert!(lines[1].contains("\"say \"\"no\"\"\""));
            assert_eq!(lines[2], "");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(image: &str, host: Option<&str>, remote: &str) -> crate::connections::LiveConnection {
        conn_pid(1, image, host, remote)
    }

    fn conn_pid(
        pid: u32,
        image: &str,
        host: Option<&str>,
        remote: &str,
    ) -> crate::connections::LiveConnection {
        crate::connections::LiveConnection {
            process: Process::Known {
                pid,
                start: 1,
                image: image.into(),
                user: String::new(),
            },
            remote: remote.parse().unwrap(),
            hostname: host.map(str::to_string),
            direction: crate::connections::Direction::Outbound,
            first_seen: false,
            opened: std::time::Instant::now(),
        }
    }

    #[test]
    fn network_groups_by_program_and_filters_program_host_or_ip() {
        let list = [
            conn(
                r"C:\b\Zed.exe",
                Some("api.example.com"),
                "93.184.215.14:443",
            ),
            conn(r"C:\a\curl.exe", None, "1.1.1.1:443"),
            conn(r"C:\b\Zed.exe", Some("cdn.example.net"), "151.101.1.1:443"),
        ];
        let groups = network_groups(&list, "");
        let names: Vec<_> = groups.iter().map(|(n, l)| (n.as_str(), l.len())).collect();
        assert_eq!(names, [("curl.exe", 1), ("Zed.exe", 2)]);
        assert_eq!(network_groups(&list, "ZED")[0].1.len(), 2);
        assert_eq!(network_groups(&list, "Example.NET")[0].1.len(), 1);
        let by_ip = network_groups(&list, "1.1.1.1");
        assert_eq!((by_ip.len(), by_ip[0].0.as_str()), (1, "curl.exe"));
        assert!(network_groups(&list, "nothing").is_empty());
    }

    #[test]
    fn process_ids_counts_each_instance_once() {
        let list = [
            conn_pid(7, r"C:\\a\\app.exe", None, "1.1.1.1:443"),
            conn_pid(3, r"C:\\a\\app.exe", None, "8.8.8.8:443"),
            conn_pid(7, r"C:\\a\\app.exe", None, "9.9.9.9:443"),
        ];
        let refs: Vec<_> = list.iter().collect();
        assert_eq!(process_ids(&refs), [3, 7]);
        assert_eq!(process_ids(&refs[..1]), [7]);
    }

    #[test]
    fn tray_state_prefers_waiting_then_paused() {
        assert_eq!(TrayState::of(false, 0), TrayState::Running);
        assert_eq!(TrayState::of(true, 0), TrayState::Paused);
        assert_eq!(TrayState::of(false, 2), TrayState::Waiting);
        assert_eq!(TrayState::of(true, 1), TrayState::Waiting);
        assert!(TrayState::Waiting.tooltip(3).contains('3'));
    }

    #[test]
    fn icon_is_a_round_dot() {
        let rgba = icon_rgba([1, 2, 3], 32);
        assert_eq!(rgba.len(), 32 * 32 * 4);
        let alpha = |x: usize, y: usize| rgba[(y * 32 + x) * 4 + 3];
        assert_eq!(alpha(16, 16), 255);
        assert_eq!(alpha(0, 0), 0);
        assert_eq!(&rgba[(16 * 32 + 16) * 4..][..3], &[1, 2, 3]);
    }

    #[test]
    fn prompt_destinations_and_scopes_read_naturally() {
        use crate::firewall::Protocol;
        let v4: std::net::IpAddr = "93.184.215.14".parse().unwrap();
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(destination(v4, 443, Protocol::Tcp), "93.184.215.14:443 tcp");
        assert_eq!(destination(v6, 53, Protocol::Udp), "[2001:db8::1]:53 udp");
        assert_eq!(destination(v4, 0, Protocol::Any), "93.184.215.14:0 ip");
        assert_eq!(
            prompt_scope("curl.exe", v4, 443, false, false),
            "curl.exe connecting to 93.184.215.14 on port 443"
        );
        assert_eq!(
            prompt_scope("curl.exe", v4, 443, true, false),
            "curl.exe connecting to any address on port 443"
        );
        assert_eq!(
            prompt_scope("curl.exe", v4, 443, false, true),
            "curl.exe connecting to 93.184.215.14 on any port"
        );
        assert_eq!(
            prompt_scope("curl.exe", v4, 443, true, true),
            "curl.exe connecting anywhere"
        );
    }

    #[test]
    fn countdown_is_minutes_and_seconds() {
        use std::time::Duration;
        assert_eq!(countdown(Duration::from_secs(0)), "0:00");
        assert_eq!(countdown(Duration::from_millis(9_900)), "0:09");
        assert_eq!(countdown(Duration::from_secs(102)), "1:42");
    }

    #[test]
    fn duration_label_reads_naturally() {
        assert_eq!(duration_label(5), "5 min");
        assert_eq!(duration_label(60), "1 hour");
        assert_eq!(duration_label(480), "8 hours");
        assert_eq!(duration_label(90), "1 h 30 min");
    }

    #[test]
    fn program_is_the_file_name() {
        let known = Process::Known {
            pid: 1,
            start: 2,
            image: r"C:\Program Files\dotnet\dotnet.exe".into(),
            user: String::new(),
        };
        assert_eq!(program(&known), "dotnet.exe");
        assert_eq!(
            program(&Process::Unknown("pid reused")),
            "unknown (pid reused)"
        );
        assert_eq!(
            program(&Process::Unknown(crate::process::OUTSIDE_WINDOWS)),
            "WSL / VM"
        );
    }
}
