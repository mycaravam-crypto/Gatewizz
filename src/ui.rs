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
                .with_inner_size([780.0, 560.0])
                .with_min_inner_size([640.0, 460.0])
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

    fn metadata(ui: &mut egui::Ui, key: &str, value: &str) {
        ui.horizontal(|ui| {
            ui.add_sized([92.0, 18.0], egui::Label::new(RichText::new(key).size(9.0).strong().color(MUTED)));
            ui.label(RichText::new(value).size(11.0));
        });
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
            style.visuals.panel_fill = Color32::from_rgb(0x0d, 0x11, 0x18);
            style.visuals.window_fill = Color32::from_rgb(0x0d, 0x11, 0x18);
            style.visuals.extreme_bg_color = Color32::from_rgb(0x15, 0x1b, 0x25);
            style.visuals.override_text_color = Some(Color32::from_rgb(0xe7, 0xec, 0xf4));
            style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(0x15, 0x1b, 0x25);
            style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x2a, 0x35, 0x45));
            style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x1d, 0x26, 0x34);
            style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x75, 0xa9, 0xff));
            style.visuals.widgets.active.bg_fill = Color32::from_rgb(0x25, 0x35, 0x49);
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
                // Closing the workspace means dismissing every pending request, then hiding to the tray.
                ctx.send_viewport_cmd(ViewportCommand::CancelClose);
                for (id, _, _) in &pending {
                    self.approvals.answer(*id, Verdict::Deny);
                }
                self.selected = None;
                self.show(&ctx, false);
                return;
            }

            if !self.selected.is_some_and(|id| pending.iter().any(|p| p.0 == id)) {
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
                ui.add_space(8.0);

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
