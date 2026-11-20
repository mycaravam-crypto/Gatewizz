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
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use eframe::egui::{self, Color32, RichText, ViewportCommand};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{
        Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    };

    use super::{TrayState, icon_rgba, program};
    use crate::approve::{Approvals, Verdict, Window};
    use crate::process::Process;

    const BG: Color32 = Color32::from_rgb(0x10, 0x12, 0x18);
    const TEXT: Color32 = Color32::from_rgb(0xc8, 0xcc, 0xd4);
    const MUTED: Color32 = Color32::from_rgb(0x7a, 0x80, 0x8c);
    const WARN: Color32 = Color32::from_rgb(0xf0, 0xb0, 0x40);

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
                .with_inner_size([460.0, 300.0])
                .with_resizable(false)
                .with_visible(false),
            ..Default::default()
        };
        let ui = eframe::run_native(
            "gatewizz",
            options,
            Box::new(move |cc| {
                Ok(Box::new(App::new(
                    cc,
                    listen,
                    events_path,
                    approvals,
                    quit,
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
        minutes: u32,
        listen: SocketAddr,
        events_path: Option<PathBuf>,
        quit: Option<tokio::sync::oneshot::Sender<()>>,
        proxy: Option<JoinHandle<Result<(), String>>>,
    }

    impl App {
        fn new(
            cc: &eframe::CreationContext,
            listen: SocketAddr,
            events_path: Option<PathBuf>,
            approvals: Arc<Approvals>,
            quit: tokio::sync::oneshot::Sender<()>,
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
            // Start the proxy only after the tray exists. A UI initialization failure must never leave an
            // unmanageable proxy running in a detached worker thread.
            let proxy = std::thread::spawn(move || proxy(stop));
            Ok(Self {
                _window: approvals.attach(),
                approvals,
                _tray: tray,
                items,
                wake,
                state: None,
                waiting: 0,
                shown: false,
                minutes: 15,
                listen,
                events_path,
                quit: Some(quit),
                proxy: Some(proxy),
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

    fn icon(state: TrayState) -> Icon {
        Icon::from_rgba(icon_rgba(state.rgb(), 32), 32, 32).expect("32x32 RGBA is a valid icon")
    }

    fn setup_style(ctx: &egui::Context) {
        ctx.set_theme(egui::Theme::Dark);
        ctx.all_styles_mut(|s| {
            for f in s.text_styles.values_mut() {
                f.family = egui::FontFamily::Monospace;
                f.size = f.size.min(13.0);
            }
            s.visuals.panel_fill = BG;
            s.visuals.window_fill = BG;
            s.visuals.override_text_color = Some(TEXT);
        });
    }

    impl eframe::App for App {
        fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                // Closing the window denies what it shows and hides it; only Quit ends gatewizz.
                ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                if let Some((id, ..)) = pending.first() {
                    self.approvals.answer(*id, Verdict::Deny);
                }
                self.show(&ctx, false);
                return;
            }
            egui::CentralPanel::default().show(ui, |ui| {
                let Some((id, held, left)) = pending.first() else {
                    ui.label(RichText::new("No approval waiting.").color(MUTED));
                    ui.label(self.state.map_or("", |s| match s {
                        TrayState::Paused => "Paused: requests that need approval are blocked.",
                        _ => "Requests that need approval will show here.",
                    }));
                    if ui.button("Hide").clicked() {
                        self.show(&ctx, false);
                    }
                    return;
                };
                ui.label(RichText::new("Approval needed").size(16.0).color(WARN));
                ui.add_space(6.0);
                egui::Grid::new("held").num_columns(2).show(ui, |ui| {
                    let (pid, user) = match &held.process {
                        Process::Known { pid, user, .. } => (pid.to_string(), user.clone()),
                        Process::Unknown(_) => ("-".into(), "-".into()),
                    };
                    for (k, v) in [
                        ("program", program(&held.process)),
                        ("pid", pid),
                        ("user", user),
                        ("host", held.host.clone()),
                        ("rule", held.rule.clone()),
                        ("findings", held.findings.join(", ")),
                        ("time left", format!("{} s", left.as_secs())),
                    ] {
                        ui.label(RichText::new(k).color(MUTED));
                        ui.label(v);
                        ui.end_row();
                    }
                });
                ui.add_space(8.0);
                let mut verdict = None;
                ui.horizontal(|ui| {
                    if ui.button("Allow once").clicked() {
                        verdict = Some(Verdict::AllowOnce);
                    }
                    if ui.button("Deny").clicked() {
                        verdict = Some(Verdict::Deny);
                    }
                });
                ui.horizontal(|ui| {
                    if ui
                        .button(format!("Allow {} for", program(&held.process)))
                        .clicked()
                    {
                        let minutes = u64::from(self.minutes);
                        verdict = Some(Verdict::AllowFor(Duration::from_secs(minutes * 60)));
                    }
                    ui.add(
                        egui::DragValue::new(&mut self.minutes)
                            .range(1..=480)
                            .suffix(" min"),
                    );
                });
                if pending.len() > 1 {
                    ui.label(
                        RichText::new(format!("{} more waiting", pending.len() - 1)).color(MUTED),
                    );
                }
                if let Some(verdict) = verdict {
                    self.approvals.answer(*id, verdict);
                    if pending.len() == 1 {
                        self.show(&ctx, false);
                    }
                }
            });
            // The countdown ticks while something waits.
            if !pending.is_empty() {
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }

        fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
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
