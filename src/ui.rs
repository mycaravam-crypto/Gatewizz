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

    use super::{TrayState, countdown, duration_label, icon_rgba, program};
    use crate::approve::{Approvals, Held, Verdict, Window};
    use crate::process::Process;
    use crate::rules::Action;

    // Design tokens: one dark theme. Surfaces step up in lightness; status colours are used for meaning only.
    const BG: Color32 = Color32::from_rgb(0x0b, 0x0e, 0x14);
    const SURFACE: Color32 = Color32::from_rgb(0x12, 0x16, 0x1f);
    const RAISED: Color32 = Color32::from_rgb(0x1a, 0x20, 0x2c);
    const BORDER: Color32 = Color32::from_rgb(0x24, 0x2b, 0x39);
    const BORDER_STRONG: Color32 = Color32::from_rgb(0x35, 0x3f, 0x52);
    const TEXT: Color32 = Color32::from_rgb(0xe8, 0xec, 0xf3);
    const MUTED: Color32 = Color32::from_rgb(0x9a, 0xa4, 0xb6);
    const SUBTLE: Color32 = Color32::from_rgb(0x6b, 0x75, 0x88);
    const BLUE: Color32 = Color32::from_rgb(0x6e, 0x9d, 0xff);
    const GREEN: Color32 = Color32::from_rgb(0x41, 0xc4, 0x83);
    const AMBER: Color32 = Color32::from_rgb(0xf0, 0xab, 0x3e);
    const RED: Color32 = Color32::from_rgb(0xef, 0x63, 0x63);
    const GREEN_FILL: Color32 = Color32::from_rgb(0x1d, 0x8a, 0x58);
    /// Font family name for headings and labels; falls back to the regular face.
    const SEMIBOLD: &str = "semibold";
    /// How long "Copied" confirmations stay visible.
    const FEEDBACK: Duration = Duration::from_secs(2);

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
                .with_title("Gatewizz")
                .with_inner_size([1040.0, 720.0])
                .with_min_inner_size([820.0, 580.0])
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

    fn mono(size: f32) -> FontId {
        FontId::new(size, FontFamily::Monospace)
    }

    /// A status colour at low opacity, for badge and banner backgrounds.
    fn tint(color: Color32) -> Color32 {
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 34)
    }

    fn card() -> egui::Frame {
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(10)
            .inner_margin(Margin::same(16))
    }

    /// Small uppercase heading above a group of content.
    fn caption(ui: &mut egui::Ui, text: &str) {
        ui.label(RichText::new(text).font(semibold(11.0)).color(SUBTLE));
    }

    /// Glyph-free status dot: painted, so it renders with any font.
    fn dot(ui: &mut egui::Ui, color: Color32, radius: f32) {
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(radius * 2.0, radius * 2.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), radius, color);
    }

    /// A rounded badge painted into `rect`'s left edge, vertically centred.
    fn paint_badge(painter: &egui::Painter, rect: Rect, text: &str, color: Color32) -> Rect {
        let galley = painter.layout_no_wrap(text.to_owned(), semibold(11.5), color);
        let size = galley.size() + egui::vec2(16.0, 6.0);
        let badge = Rect::from_min_size(
            egui::pos2(rect.left(), rect.center().y - size.y / 2.0),
            size,
        );
        painter.rect_filled(badge, CornerRadius::same(255), tint(color));
        painter.galley(badge.min + egui::vec2(8.0, 3.0), galley, color);
        badge
    }

    /// The header's state indicator: a dot and a label on a tinted capsule.
    fn status_pill(ui: &mut egui::Ui, text: &str, color: Color32) {
        let galley = ui
            .painter()
            .layout_no_wrap(text.to_owned(), semibold(12.5), color);
        let size = egui::vec2(galley.size().x + 40.0, 30.0);
        let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(rect, CornerRadius::same(255), tint(color));
        painter.circle_filled(egui::pos2(rect.left() + 16.0, rect.center().y), 4.0, color);
        let pos = egui::pos2(rect.left() + 28.0, rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
    }

    fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
        let width = ui
            .painter()
            .layout_no_wrap(text.to_owned(), semibold(11.5), color)
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
        egui::Button::new(RichText::new(text).font(semibold(13.5)).color(color))
            .fill(fill)
            .corner_radius(8)
            .min_size(egui::vec2(0.0, 34.0))
    }

    fn quiet_button(text: &str) -> egui::Button<'static> {
        egui::Button::new(RichText::new(text).size(12.5).color(MUTED))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, BORDER))
            .corner_radius(6)
    }

    /// A toggle chip: filters and duration presets.
    fn chip(ui: &mut egui::Ui, text: &str, selected: bool) -> egui::Response {
        let (fill, stroke, color) = if selected {
            (tint(BLUE), Stroke::new(1.0, BLUE), TEXT)
        } else {
            (Color32::TRANSPARENT, Stroke::new(1.0, BORDER), MUTED)
        };
        ui.add(
            egui::Button::new(RichText::new(text).size(12.5).color(color))
                .fill(fill)
                .stroke(stroke)
                .corner_radius(255)
                .min_size(egui::vec2(0.0, 28.0)),
        )
        .on_hover_cursor(CursorIcon::PointingHand)
    }

    fn stat_card(ui: &mut egui::Ui, label: &str, value: usize, color: Color32, hint: &str) {
        card()
            .inner_margin(Margin::symmetric(16, 14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    dot(ui, color, 4.0);
                    ui.label(RichText::new(label).font(semibold(12.5)).color(MUTED));
                });
                ui.label(
                    RichText::new(value.to_string())
                        .font(semibold(28.0))
                        .color(TEXT),
                );
                ui.add(egui::Label::new(RichText::new(hint).size(11.5).color(SUBTLE)).truncate());
            });
    }

    /// Label/value pairs in two aligned columns.
    fn details(ui: &mut egui::Ui, id: &str, rows: &[(&str, &str)]) {
        ui.spacing_mut().interact_size.y = 20.0;
        egui::Grid::new(id)
            .num_columns(2)
            .spacing([20.0, 8.0])
            .show(ui, |ui| {
                for (key, value) in rows {
                    ui.label(RichText::new(*key).size(12.5).color(SUBTLE));
                    ui.add(egui::Label::new(RichText::new(*value).size(13.0).color(TEXT)).wrap());
                    ui.end_row();
                }
            });
    }

    fn decision_style(action: Option<Action>) -> (&'static str, Color32) {
        match action {
            Some(Action::Allow) => ("Allowed", GREEN),
            Some(Action::Block) => ("Blocked", RED),
            Some(Action::Approve) => ("Approval", AMBER),
            None => ("Unknown", SUBTLE),
        }
    }

    fn urgency(left: Duration) -> Color32 {
        if left.as_secs() < 15 { RED } else { AMBER }
    }

    /// Column rectangles of an activity row: time, program, destination, decision, status.
    fn history_columns(rect: Rect) -> [Rect; 5] {
        let inner = rect.shrink2(egui::vec2(12.0, 0.0));
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
            paint_cell(ui.painter(), *column, title, semibold(11.0), SUBTLE);
        }
        ui.painter()
            .hline(rect.x_range(), rect.bottom(), Stroke::new(1.0, BORDER));
    }

    /// One clickable, full-width activity row.
    fn history_row(ui: &mut egui::Ui, event: &HistoryEvent, active: bool) -> egui::Response {
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 36.0), Sense::click());
        let response = response.on_hover_cursor(CursorIcon::PointingHand);
        let painter = ui.painter();
        if active {
            painter.rect_filled(rect, 6, tint(BLUE));
        } else if response.hovered() {
            painter.rect_filled(rect, 6, RAISED);
        }
        let [time, program, host, decision, status] = history_columns(rect);
        let (label, color) = decision_style(event.action);
        let when = event.time.replace('T', " ");
        paint_cell(painter, time, when.trim_end_matches('Z'), mono(12.0), MUTED);
        paint_cell(
            painter,
            program,
            &event.process_name(),
            FontId::proportional(13.5),
            TEXT,
        );
        paint_cell(painter, host, &event.host, mono(12.5), BLUE);
        paint_badge(painter, decision, label, color);
        let status_color = if event.status >= 400 { RED } else { MUTED };
        paint_cell(
            painter,
            status,
            &event.status.to_string(),
            mono(12.5),
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
    fn setup_fonts(ctx: &egui::Context) {
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
        ctx.set_fonts(fonts);
    }

    fn setup_style(ctx: &egui::Context) {
        setup_fonts(ctx);
        ctx.set_theme(egui::Theme::Dark);
        ctx.all_styles_mut(|style| {
            use egui::TextStyle;
            style.text_styles = [
                (TextStyle::Small, FontId::proportional(11.5)),
                (TextStyle::Body, FontId::proportional(13.5)),
                (TextStyle::Button, FontId::proportional(13.5)),
                (TextStyle::Heading, semibold(20.0)),
                (TextStyle::Monospace, mono(12.5)),
            ]
            .into();
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(14.0, 6.0);
            style.spacing.interact_size.y = 28.0;
            style.interaction.selectable_labels = false;
            let visuals = &mut style.visuals;
            visuals.panel_fill = BG;
            visuals.window_fill = SURFACE;
            visuals.window_stroke = Stroke::new(1.0, BORDER);
            visuals.window_corner_radius = CornerRadius::same(10);
            visuals.menu_corner_radius = CornerRadius::same(8);
            visuals.extreme_bg_color = Color32::from_rgb(0x0e, 0x12, 0x1a);
            visuals.faint_bg_color = SURFACE;
            visuals.override_text_color = None;
            visuals.selection.bg_fill = tint(BLUE);
            visuals.selection.stroke = Stroke::new(1.0, BLUE);
            visuals.hyperlink_color = BLUE;
            let widgets = &mut visuals.widgets;
            widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
            widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
            for (state, fill, stroke) in [
                (&mut widgets.inactive, SURFACE, BORDER),
                (&mut widgets.hovered, RAISED, BORDER_STRONG),
                (&mut widgets.active, RAISED, BLUE),
                (&mut widgets.open, RAISED, BORDER_STRONG),
            ] {
                state.bg_fill = fill;
                state.weak_bg_fill = fill;
                state.bg_stroke = Stroke::new(1.0, stroke);
                state.fg_stroke = Stroke::new(1.0, TEXT);
                state.corner_radius = CornerRadius::same(7);
                state.expansion = 0.0;
            }
        });
    }

    /// Workspace views. Each draws one region; all decisions go through `Approvals`.
    impl App {
        fn header(&mut self, ui: &mut egui::Ui, state: TrayState, waiting: usize) {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), Sense::hover());
                ui.painter().rect_filled(rect, 9, BLUE);
                ui.painter().text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    "G",
                    semibold(20.0),
                    Color32::from_rgb(0x0b, 0x12, 0x24),
                );
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(RichText::new("Gatewizz").font(semibold(18.0)).color(TEXT));
                    ui.label(
                        RichText::new("Local security gate for traffic to AI models")
                            .size(12.0)
                            .color(MUTED),
                    );
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (text, color) = match state {
                        TrayState::Running => ("Protected".to_string(), GREEN),
                        TrayState::Paused => ("Approvals paused".to_string(), MUTED),
                        TrayState::Waiting => (format!("{waiting} awaiting review"), AMBER),
                    };
                    status_pill(ui, &text, color);
                });
            });
            ui.add_space(14.0);
            egui::Frame::new()
                .fill(SURFACE)
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(9)
                .inner_margin(Margin::same(3))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 2.0;
                        for (tab, label, badge) in [
                            (Tab::Overview, "Overview", waiting),
                            (Tab::Activity, "Activity", 0),
                        ] {
                            let selected = self.tab == tab;
                            let mut button = egui::Button::new(
                                RichText::new(label)
                                    .font(semibold(13.0))
                                    .color(if selected { TEXT } else { MUTED }),
                            )
                            .corner_radius(7)
                            .min_size(egui::vec2(96.0, 30.0))
                            .fill(if selected {
                                RAISED
                            } else {
                                Color32::TRANSPARENT
                            })
                            .stroke(if selected {
                                Stroke::new(1.0, BORDER_STRONG)
                            } else {
                                Stroke::NONE
                            });
                            if badge > 0 {
                                button = button.right_text(
                                    RichText::new(badge.to_string())
                                        .font(semibold(12.0))
                                        .color(AMBER),
                                );
                            }
                            if ui
                                .add(button)
                                .on_hover_cursor(CursorIcon::PointingHand)
                                .clicked()
                            {
                                self.tab = tab;
                            }
                        }
                    });
                });
            ui.add_space(14.0);
        }

        fn status_bar(&mut self, ui: &mut egui::Ui, state: TrayState) {
            ui.horizontal(|ui| {
                let paused = state == TrayState::Paused;
                dot(ui, if paused { SUBTLE } else { GREEN }, 4.0);
                ui.label(
                    RichText::new(format!("Proxy on http://{}", self.listen))
                        .size(12.5)
                        .color(MUTED),
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
                .fill(tint(AMBER))
                .stroke(Stroke::new(1.0, AMBER.gamma_multiply(0.45)))
                .corner_radius(8)
                .inner_margin(Margin::symmetric(14, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        dot(ui, AMBER, 4.0);
                        ui.label(
                            RichText::new(
                                "Approvals are paused. Requests that need approval are blocked.",
                            )
                            .size(13.0)
                            .color(TEXT),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.add(button("Resume", AMBER, BG)).clicked() {
                                self.set_paused(false);
                            }
                        });
                    });
                });
            ui.add_space(12.0);
        }

        fn overview(&mut self, ui: &mut egui::Ui, pending: &[(u64, Held, Duration)]) {
            // While requests wait, the decision gets the space; the summary returns once the queue is clear.
            if pending.is_empty() {
                let recent = self.history.len();
                let blocked = self
                    .history
                    .iter()
                    .filter(|event| event.action == Some(Action::Block))
                    .count();
                let logged = self.events_path.is_some();
                let source = if logged {
                    "from the event log"
                } else {
                    "event log disabled"
                };
                ui.columns(4, |columns| {
                    stat_card(
                        &mut columns[0],
                        "Awaiting review",
                        pending.len(),
                        AMBER,
                        "held until you decide",
                    );
                    stat_card(&mut columns[1], "Recent requests", recent, BLUE, source);
                    stat_card(&mut columns[2], "Blocked", blocked, RED, source);
                    stat_card(
                        &mut columns[3],
                        "Not blocked",
                        recent - blocked,
                        GREEN,
                        source,
                    );
                });
                ui.add_space(16.0);
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
            match selected {
                Some((id, held, left)) => self.request(ui, *id, held, *left),
                None => self.latest_activity(ui),
            }
        }

        fn queue(&mut self, ui: &mut egui::Ui, pending: &[(u64, Held, Duration)]) {
            ui.horizontal(|ui| {
                caption(ui, "APPROVAL QUEUE");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(pending.len().to_string())
                            .font(semibold(12.0))
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(4.0);
            if pending.is_empty() {
                card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.vertical_centered(|ui| {
                        ui.add_space(14.0);
                        check_icon(ui, GREEN, 40.0);
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("Queue is clear")
                                .font(semibold(14.5))
                                .color(TEXT),
                        );
                        ui.label(
                            RichText::new("Held requests appear here and open this window.")
                                .size(12.0)
                                .color(MUTED),
                        );
                        ui.add_space(14.0);
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
                            .fill(if active { RAISED } else { SURFACE })
                            .stroke(Stroke::new(
                                if active { 1.5 } else { 1.0 },
                                if active { BLUE } else { BORDER },
                            ))
                            .corner_radius(10)
                            .inner_margin(Margin::same(12))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(program(&held.process))
                                                .font(semibold(14.0))
                                                .color(TEXT),
                                        )
                                        .truncate(),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        badge(ui, &countdown(*left), urgency(*left));
                                    });
                                });
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&held.host).font(mono(12.5)).color(MUTED),
                                    )
                                    .truncate(),
                                );
                                let (findings, color) = match held.findings.len() {
                                    0 => ("Held by rule".to_string(), SUBTLE),
                                    1 => ("1 finding".to_string(), AMBER),
                                    n => (format!("{n} findings"), AMBER),
                                };
                                ui.label(RichText::new(findings).size(12.0).color(color));
                            })
                            .response
                            .interact(Sense::click())
                            .on_hover_cursor(CursorIcon::PointingHand);
                        if response.clicked() {
                            self.selected = Some(*id);
                        }
                        ui.add_space(4.0);
                    }
                });
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
            card().inner_margin(Margin::same(20)).show(ui, |ui| {
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
                            egui::Label::new(RichText::new(&name).font(semibold(22.0)).color(TEXT))
                                .truncate(),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(&held.host).font(mono(14.0)).color(BLUE),
                            )
                            .wrap(),
                        );
                        ui.add_space(14.0);
                        caption(ui, "WHY IT WAS HELD");
                        if held.findings.is_empty() {
                            ui.label(
                            RichText::new(format!(
                                "Rule \"{}\" asks for approval before traffic reaches this host.",
                                held.rule
                            ))
                            .size(13.0)
                            .color(MUTED),
                        );
                        } else {
                            ui.horizontal_wrapped(|ui| {
                                for finding in &held.findings {
                                    badge(ui, finding, AMBER);
                                }
                            });
                        }
                        ui.add_space(14.0);
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
            card().inner_margin(Margin::same(16)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - ui.spacing().item_spacing.x) / 2.0;
                    let deny = button("Deny", tint(RED), RED)
                        .stroke(Stroke::new(1.0, RED.gamma_multiply(0.5)))
                        .min_size(egui::vec2(width, 38.0));
                    if ui.add(deny).on_hover_text("Block this request").clicked() {
                        verdict = Some(Verdict::Deny);
                    }
                    let allow = button("Allow once", GREEN_FILL, Color32::WHITE).min_size(egui::vec2(width, 38.0));
                    if ui.add(allow).on_hover_text("Send this request only").clicked() {
                        verdict = Some(Verdict::AllowOnce);
                    }
                });
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Or allow for").size(12.5).color(MUTED));
                    for minutes in [5, 15, 60, 480] {
                        if chip(ui, &duration_label(minutes), self.minutes == minutes).clicked() {
                            self.minutes = minutes;
                        }
                    }
                    ui.add(egui::DragValue::new(&mut self.minutes).range(1..=480).suffix(" min"))
                        .on_hover_text("Custom duration, 1 to 480 minutes");
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let grant = button(
                        &format!("Allow for {}", duration_label(self.minutes)),
                        RAISED,
                        TEXT,
                    )
                    .stroke(Stroke::new(1.0, BORDER_STRONG))
                    .min_size(egui::vec2(150.0, 32.0));
                    if ui.add(grant).clicked() {
                        verdict = Some(Verdict::AllowFor(Duration::from_secs(
                            u64::from(self.minutes) * 60,
                        )));
                    }
                    ui.add_space(4.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "Covers only {name} connecting to {host}. Closing the window or letting the timer run out denies the request."
                            ))
                            .size(12.0)
                            .color(SUBTLE),
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
                ui.add_space(4.0);
                if self.history.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        check_icon(ui, GREEN, 48.0);
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("You're all caught up")
                                .font(semibold(17.0))
                                .color(TEXT),
                        );
                        ui.label(
                            RichText::new(self.empty_history_message())
                                .size(12.5)
                                .color(MUTED),
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
                ("approve", "Approval", count("approve")),
            ];
            let filtered = filter_history(rows, &self.history_filter, &self.history_decision);

            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.history_filter)
                        .hint_text("Search program or host")
                        .desired_width(220.0)
                        .margin(Margin::symmetric(10, 6)),
                );
                ui.add_space(6.0);
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
                            .size(12.0)
                            .color(SUBTLE),
                    );
                });
            });
            ui.add_space(12.0);

            egui::Panel::bottom("privacy_note")
                .show_separator_line(false)
                .frame(egui::Frame::new().inner_margin(Margin { top: 8, ..Margin::ZERO }))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("Metadata only. Request bodies, header values, query strings and secrets are never stored or exported.")
                            .size(11.5)
                            .color(SUBTLE),
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

            card().inner_margin(Margin::same(8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(ui.available_height());
                if rows.is_empty() || filtered.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(48.0);
                        let (title, message) = if rows.is_empty() {
                            ("No activity yet", self.empty_history_message())
                        } else {
                            (
                                "No matching events",
                                "Try another search or decision filter.",
                            )
                        };
                        ui.label(RichText::new(title).font(semibold(16.0)).color(TEXT));
                        ui.label(RichText::new(message).size(12.5).color(MUTED));
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
                        .font(semibold(17.0))
                        .color(TEXT),
                )
                .truncate(),
            );
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{}:{}", event.host, event.port))
                        .font(mono(13.0))
                        .color(BLUE),
                )
                .wrap(),
            );
            ui.add_space(6.0);
            let (label, color) = decision_style(event.action);
            ui.horizontal(|ui| {
                badge(ui, label, color);
                badge(
                    ui,
                    &format!("HTTP {}", event.status),
                    if event.status >= 400 { RED } else { SUBTLE },
                );
            });
            ui.add_space(10.0);
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

            egui::Panel::top("header")
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(BG).inner_margin(Margin {
                    left: 20,
                    right: 20,
                    top: 16,
                    bottom: 0,
                }))
                .show(ui, |ui| self.header(ui, state, pending.len()));
            egui::Panel::bottom("status_bar")
                .frame(
                    egui::Frame::new()
                        .fill(SURFACE)
                        .inner_margin(Margin::symmetric(20, 8)),
                )
                .show(ui, |ui| self.status_bar(ui, state));
            egui::CentralPanel::default()
                .frame(egui::Frame::new().fill(BG).inner_margin(Margin {
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
                ["api.anthropic.com"]
            );
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
    }
}
