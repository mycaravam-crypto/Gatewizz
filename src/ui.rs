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

    fn label(self) -> &'static str {
        match self {
            Self::Running => "PROTECTED",
            Self::Paused => "PAUSED",
            Self::Waiting => "ACTION REQUIRED",
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
fn program(process: &Process) -> String {
    match process {
        Process::Known { image, .. } => image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(image)
            .to_string(),
        Process::Unknown(why) => format!("unknown ({why})"),
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
    use std::time::Duration;

    use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, ViewportCommand};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    use super::{TrayState, icon_rgba, program};
    use crate::approve::{Approvals, Verdict, Window};
    use crate::process::Process;
    use crate::rules::Action;

    const BG: Color32 = Color32::from_rgb(0x0d, 0x11, 0x18);
    const PANEL: Color32 = Color32::from_rgb(0x15, 0x1b, 0x25);
    const PANEL_HOVER: Color32 = Color32::from_rgb(0x1d, 0x26, 0x34);
    const BORDER: Color32 = Color32::from_rgb(0x2a, 0x35, 0x45);
    const TEXT: Color32 = Color32::from_rgb(0xe7, 0xec, 0xf4);
    const MUTED: Color32 = Color32::from_rgb(0x91, 0x9e, 0xb0);
    const AMBER: Color32 = Color32::from_rgb(0xf2, 0xb7, 0x4b);
    const GREEN: Color32 = Color32::from_rgb(0x55, 0xd6, 0x91);
    const RED: Color32 = Color32::from_rgb(0xf0, 0x6b, 0x73);
    const BLUE: Color32 = Color32::from_rgb(0x75, 0xa9, 0xff);

    /// Starts the proxy on its own thread with a stop signal, shows the tray, and returns the proxy's result once it
    /// has stopped: after Quit, Ctrl+C or a proxy error.
    pub fn run(
        listen: SocketAddr,
        events_path: Option<PathBuf>,
        approvals: Arc<Approvals>,
        proxy: impl FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        let (quit, stop) = tokio::sync::oneshot::channel();
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("gatewizz: approval")
                .with_inner_size([980.0, 700.0])
                .with_min_inner_size([760.0, 560.0])
                .with_resizable(true)
                .with_visible(false),
            ..Default::default()
        };
        let ui = eframe::run_native(
            "gatewizz",
            options,
            Box::new(move |cc| {
                App::new(cc, listen, events_path, approvals, quit, stop, proxy)
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
        history: Vec<HistoryEvent>,
        history_rx: Receiver<Vec<HistoryEvent>>,
        history_stop: Sender<()>,
        history_worker: Option<JoinHandle<()>>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Tab {
        Overview,
        Activity,
    }

    const MAX_LOG_ROTATIONS: usize = 5;
    const MAX_HISTORY_ROWS: usize = 500;
    const MAX_HISTORY_FILE_BYTES: u64 = 1024 * 1024;
    const HISTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(2);

    #[derive(Debug, Clone, Default, serde::Deserialize)]
    #[serde(default)]
    struct HistoryEvent {
        time: String,
        host: String,
        status: u16,
        action: Option<Action>,
        process: HistoryProcess,
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
                HistoryProcess::Unknown(reason) => format!("unknown ({reason})"),
                HistoryProcess::Unavailable => "unknown".into(),
            }
        }

        fn decision(&self) -> &'static str {
            match self.action {
                Some(Action::Allow) => "allow",
                Some(Action::Block) => "block",
                Some(Action::Approve) => "approve",
                None => "-",
            }
        }
    }

    impl App {
        fn new(
            cc: &eframe::CreationContext,
            listen: SocketAddr,
            events_path: Option<PathBuf>,
            approvals: Arc<Approvals>,
            quit: tokio::sync::oneshot::Sender<()>,
            stop: tokio::sync::oneshot::Receiver<()>,
            proxy: impl FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<(), String>
            + Send
            + 'static,
        ) -> Result<Self, String> {
            setup_style(&cc.egui_ctx);
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
                        .spawn(move || loop {
                            if history_tx.send(load_history(&history_path)).is_err() {
                                break;
                            }
                            history_ctx.request_repaint();
                            match stop_history.recv_timeout(HISTORY_REFRESH_INTERVAL) {
                                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                Err(mpsc::RecvTimeoutError::Timeout) => {}
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
                history: Vec::new(),
                history_rx,
                history_stop,
                history_worker,
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
                let paused = !self.approvals.paused();
                self.approvals.set_paused(paused);
                self.items
                    .pause
                    .set_text(if paused { "Resume" } else { "Pause" });
            } else if id == self.items.open_log.id() {
                if let Some(path) = &self.events_path {
                    // Opens the file with its default app, as a double click would.
                    let _ = std::process::Command::new("explorer").arg(path).spawn();
                }
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

    fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(105.0);
            ui.label(RichText::new(value).size(21.0).strong().color(color));
            ui.label(RichText::new(label).size(9.0).strong().color(MUTED));
        });
    }

    fn metadata(ui: &mut egui::Ui, key: &str, value: &str) {
        ui.horizontal(|ui| {
            ui.add_sized(
                [92.0, 18.0],
                egui::Label::new(RichText::new(key).size(9.0).strong().color(MUTED)),
            );
            ui.label(RichText::new(value).size(11.0));
        });
    }

    /// Loads only a bounded tail from each log file. File I/O and JSON parsing run on a worker thread.
    /// Accepts a borrowed path so callers do not need to allocate a `PathBuf`.
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
            let mut contents = String::new();
            if file
                .take(MAX_HISTORY_FILE_BYTES)
                .read_to_string(&mut contents)
                .is_err()
            {
                continue;
            }
            // A bounded tail can begin halfway through a JSON line. Discard that partial record.
            if offset > 0 {
                let Some(newline) = contents.find('\n') else {
                    continue;
                };
                contents.drain(..=newline);
            }
            for line in contents.lines().rev() {
                if let Ok(event) = serde_json::from_str::<HistoryEvent>(line) {
                    rows.push(event);
                    if rows.len() >= MAX_HISTORY_ROWS {
                        return rows;
                    }
                }
            }
        }
        rows
    }

    fn icon(state: TrayState) -> Icon {
        Icon::from_rgba(icon_rgba(state.rgb(), 32), 32, 32).expect("32x32 RGBA is a valid icon")
    }

    fn setup_style(ctx: &egui::Context) {
        ctx.set_theme(egui::Theme::Dark);
        ctx.all_styles_mut(|style| {
            for font in style.text_styles.values_mut() {
                font.family = egui::FontFamily::Proportional;
            }
            style.spacing.item_spacing = egui::vec2(9.0, 7.0);
            style.spacing.button_padding = egui::vec2(12.0, 7.0);
            style.visuals.panel_fill = BG;
            style.visuals.window_fill = BG;
            style.visuals.extreme_bg_color = PANEL;
            style.visuals.override_text_color = Some(TEXT);
            style.visuals.widgets.inactive.bg_fill = PANEL;
            style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
            style.visuals.widgets.hovered.bg_fill = PANEL_HOVER;
            style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, BLUE);
            style.visuals.widgets.active.bg_fill = Color32::from_rgb(0x25, 0x35, 0x49);
        });
    }

    impl eframe::App for App {
        fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
            let waiting = self.approvals.pending().len();
            // A newly held request opens the window.
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
                self.selected = None;
                self.show(&ctx, false);
                return;
            }

            if !self
                .selected
                .is_some_and(|id| pending.iter().any(|p| p.0 == id))
            {
                self.selected = pending.first().map(|p| p.0);
            }
            let state = TrayState::of(self.approvals.paused(), pending.len());

            egui::CentralPanel::default().show(ui, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("gatewizz").size(23.0).strong());
                    ui.label(RichText::new("LOCAL SECURITY GATE").size(10.0).strong().color(MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let (color, message) = match state {
                            TrayState::Running => (GREEN, "Proxy active"),
                            TrayState::Paused => (MUTED, "Approvals paused"),
                            TrayState::Waiting => (AMBER, "Approval required"),
                        };
                        ui.label(RichText::new(state.label()).size(10.0).strong().color(color));
                        ui.label(RichText::new("●").color(color));
                        if !pending.is_empty() {
                            ui.label(RichText::new(format!("{} waiting", pending.len())).strong().color(AMBER));
                        }
                        ui.label(RichText::new(message).size(11.0).color(MUTED));
                    });
                });
                ui.label(RichText::new("Review outbound requests before they reach an external model endpoint.")
                    .size(11.0).color(MUTED));
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let overview = ui.selectable_label(self.tab == Tab::Overview, "  Overview  ");
                    if overview.clicked() { self.tab = Tab::Overview; }
                    let activity = ui.selectable_label(self.tab == Tab::Activity, "  Activity history  ");
                    if activity.clicked() { self.tab = Tab::Activity; }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(format!("{} pending", pending.len())).size(10.0).color(AMBER));
                    });
                });
                ui.separator();
                if self.tab == Tab::Activity {
                    let rows = &self.history;
                    let blocked = rows.iter().filter(|event| event.action == Some(Action::Block)).count();
                    let allowed = rows.len().saturating_sub(blocked);
                    ui.horizontal(|ui| {
                        stat_card(ui, "RECENT EVENTS", &rows.len().to_string(), BLUE);
                        stat_card(ui, "BLOCKED", &blocked.to_string(), RED);
                        stat_card(ui, "OTHER", &allowed.to_string(), GREEN);
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("ACTIVITY").strong().size(11.0));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.history_filter).hint_text("Filter host or process...").desired_width(220.0));
                        });
                    });
                    ui.add_space(5.0);
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                        egui::Grid::new("activity_grid").striped(true).num_columns(5).show(ui, |ui| {
                            for heading in ["TIME (UTC)", "APPLICATION", "DESTINATION", "DECISION", "STATUS"] {
                                ui.label(RichText::new(heading).size(9.0).strong().color(MUTED));
                            }
                            ui.end_row();
                            let filter = self.history_filter.to_lowercase();
                            for event in rows.iter().filter(|event| {
                                let hay = format!("{} {}", event.host, event.process_name()).to_lowercase();
                                filter.is_empty() || hay.contains(&filter)
                            }) {
                                let decision = event.decision();
                                let color = match event.action {
                                    Some(Action::Block) => RED,
                                    Some(Action::Approve) => AMBER,
                                    _ => GREEN,
                                };
                                ui.label(RichText::new(event.time.replace('T', " ").trim_end_matches('Z').to_string()).size(10.0).color(MUTED));
                                ui.label(RichText::new(event.process_name()).size(10.0));
                                ui.label(RichText::new(&event.host).size(10.0).color(BLUE));
                                ui.label(RichText::new(decision).size(10.0));
                                ui.label(RichText::new(event.status.to_string()).size(10.0).strong().color(color));
                                ui.end_row();
                            }
                        });
                        if rows.is_empty() {
                            ui.add_space(12.0);
                            let message = if self.events_path.is_some() { "No events recorded yet. New requests will appear here automatically." } else { "Persistent history is disabled because events are sent to stdout." };
                            ui.label(RichText::new(message).color(MUTED));
                        }
                    });
                    ui.add_space(8.0);
                    ui.label(RichText::new("History contains request metadata only. Bodies, header values and query strings are never stored.").size(10.0).color(MUTED));
                    return;
                }
                let recent = &self.history;
                let blocked = recent.iter().filter(|event| event.action == Some(Action::Block)).count();
                let allowed = recent.len().saturating_sub(blocked);
                ui.horizontal(|ui| {
                    stat_card(ui, "RECENT REQUESTS", &recent.len().to_string(), BLUE);
                    stat_card(ui, "BLOCKED", &blocked.to_string(), RED);
                    stat_card(ui, "OTHER DECISIONS", &allowed.to_string(), GREEN);
                    stat_card(ui, "AWAITING REVIEW", &pending.len().to_string(), AMBER);
                });
                ui.add_space(10.0);

                ui.columns(2, |columns| {
                    columns[0].set_min_width(205.0);
                    columns[0].set_max_width(270.0);
                    columns[0].vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("PENDING").size(10.0).strong().color(MUTED));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(pending.len().to_string()).strong());
                            });
                        });
                        ui.add_space(6.0);
                        if pending.is_empty() {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(120.0);
                                ui.vertical_centered(|ui| {
                                    ui.add_space(18.0);
                                    ui.label(RichText::new("✓").size(25.0).color(GREEN));
                                    ui.label(RichText::new("Queue is clear").strong());
                                    ui.label(RichText::new("Nothing needs your attention.").size(11.0).color(MUTED));
                                    ui.add_space(12.0);
                                });
                            });
                        } else {
                            for (id, held, left) in &pending {
                                let active = self.selected == Some(*id);
                                let fill = if active {
                                    Color32::from_rgb(0x1d, 0x26, 0x34)
                                } else {
                                    Color32::from_rgb(0x15, 0x1b, 0x25)
                                };
                                let stroke = if active {
                                    Stroke::new(1.5, BLUE)
                                } else {
                                    Stroke::new(1.0, Color32::from_rgb(0x2a, 0x35, 0x45))
                                };
                                let response = egui::Frame::group(ui.style())
                                    .fill(fill)
                                    .stroke(stroke)
                                    .show(ui, |ui| {
                                        ui.set_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.vertical(|ui| {
                                                ui.label(RichText::new(program(&held.process)).strong());
                                                ui.label(RichText::new(&held.host).size(10.0).color(MUTED));
                                            });
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                ui.label(RichText::new(format!("{}s", left.as_secs()))
                                                    .size(10.0).strong().color(if left.as_secs() < 15 { RED } else { AMBER }));
                                            });
                                        });
                                        ui.label(RichText::new(format!("{} finding(s)", held.findings.len()))
                                            .size(10.0).color(AMBER));
                                    });
                                if response.response.interact(egui::Sense::click()).clicked() {
                                    self.selected = Some(*id);
                                }
                                ui.add_space(4.0);
                            }
                        }
                    });

                    let selected = self.selected.and_then(|id| pending.iter().find(|p| p.0 == id));
                    columns[1].vertical(|ui| {
                        let Some((id, held, left)) = selected else {
                            egui::Frame::group(ui.style()).show(ui, |ui| {
                                ui.set_min_height(280.0);
                                ui.vertical_centered(|ui| {
                                    ui.add_space(55.0);
                                    ui.label(RichText::new("All clear").size(22.0).strong().color(GREEN));
                                    ui.label(RichText::new("Request details will appear here when approval is needed.")
                                        .size(11.0).color(MUTED));
                                });
                            });
                            return;
                        };

                        let (pid, user) = match &held.process {
                            Process::Known { pid, user, .. } => (pid.to_string(), user.clone()),
                            Process::Unknown(why) => ("Unknown".into(), why.to_string()),
                        };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("REQUEST DETAILS").size(10.0).strong().color(MUTED));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format!("{}s remaining", left.as_secs()))
                                    .size(11.0).strong().color(if left.as_secs() < 15 { RED } else { AMBER }));
                            });
                        });
                        ui.add_space(6.0);
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.label(RichText::new(program(&held.process)).size(20.0).strong());
                            ui.label(RichText::new(&held.host).size(13.0).color(BLUE));
                            ui.add_space(8.0);
                            ui.separator();
                            metadata(ui, "PROCESS ID", &pid);
                            metadata(ui, "USER", &user);
                            metadata(ui, "MATCHED RULE", &held.rule);
                            ui.add_space(8.0);
                            ui.label(RichText::new("DETECTION").size(10.0).strong().color(MUTED));
                            if held.findings.is_empty() {
                                ui.label(RichText::new("No finding details supplied by the rule engine.")
                                    .size(11.0).color(MUTED));
                            } else {
                                for finding in &held.findings {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("◆").color(AMBER));
                                        ui.label(RichText::new(finding).size(11.0));
                                    });
                                }
                            }
                            ui.add_space(8.0);
                            ui.separator();
                            ui.label(RichText::new("The request remains held until you decide.")
                                .size(11.0).color(MUTED));
                            ui.add_space(7.0);
                            ui.horizontal(|ui| {
                                if ui.add_sized([90.0, 34.0],
                                    egui::Button::new(RichText::new("Deny").strong().color(RED))).clicked() {
                                    self.approvals.answer(*id, Verdict::Deny);
                                    self.selected = None;
                                }
                                if ui.add_sized([120.0, 34.0],
                                    egui::Button::new(RichText::new("Allow once").strong().color(Color32::WHITE))
                                        .fill(Color32::from_rgb(0x25, 0x8b, 0x60))).clicked() {
                                    self.approvals.answer(*id, Verdict::AllowOnce);
                                    self.selected = None;
                                }
                            });
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Temporary grant").strong());
                                ui.add(egui::DragValue::new(&mut self.minutes).range(1..=480).suffix(" min"));
                            });
                            if ui.add_sized([250.0, 30.0],
                                egui::Button::new("Allow this program + host for this duration")).clicked() {
                                self.approvals.answer(*id,
                                    Verdict::AllowFor(Duration::from_secs(u64::from(self.minutes) * 60)));
                                self.selected = None;
                            }
                            ui.label(RichText::new("Grant applies only to this executable and destination host.")
                                .size(10.0).color(MUTED));
                        });
                    });
                });

                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(if state == TrayState::Paused { MUTED } else { GREEN }));
                    ui.label(RichText::new(format!("Proxy  {}", self.listen)).size(10.0).color(MUTED));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Hide to tray").clicked() {
                            self.show(&ctx, false);
                        }
                        if state == TrayState::Paused {
                            ui.label(RichText::new("New approval requests are blocked while paused.")
                                .size(10.0).color(AMBER));
                        }
                    });
                });
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
