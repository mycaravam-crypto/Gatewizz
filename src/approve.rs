//! Holding requests for approval (#34). The proxy asks; the approval window (#35) lists what waits and answers.
//!
//! Fail closed: a timeout, a full queue, no attached window or pause all block. Held requests carry metadata only.
// ponytail: unused until the approve action is wired into the proxy after #21 (#33) lands.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};

use crate::process::Process;

/// What the window shows for a held request: never content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub process: Process,
    pub host: String,
    pub rule: String,
    pub findings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    AllowOnce,
    Deny,
    /// Allows this process image and host without asking until the time is up.
    AllowFor(Duration),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Allowed(&'static str),
    Blocked(&'static str),
}

struct Pending {
    id: u64,
    held: Held,
    deadline: Instant,
    reply: oneshot::Sender<Verdict>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    pending: VecDeque<Pending>,
    /// (process image, host) → grant expiry.
    grants: HashMap<(String, String), Instant>,
    paused: bool,
    windows: usize,
}

pub struct Approvals {
    state: Mutex<State>,
    timeout: Duration,
    capacity: usize,
    /// Number of waiting requests, for the tray colour and to wake the window.
    count: watch::Sender<usize>,
}

/// While alive, an approval window is attached and requests can be held.
pub struct Window(Arc<Approvals>);

impl Drop for Window {
    fn drop(&mut self) {
        self.0.lock().windows -= 1;
    }
}

/// Removes the entry when `ask` ends for any reason, including a client that went away.
struct Unqueue<'a>(&'a Approvals, u64);

impl Drop for Unqueue<'_> {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.pending.retain(|p| p.id != self.1);
        self.0.count.send_replace(state.pending.len());
    }
}

fn image(process: &Process) -> Option<&str> {
    match process {
        Process::Known { image, .. } => Some(image),
        Process::Unknown(_) => None,
    }
}

impl Approvals {
    pub fn new(timeout: Duration, capacity: usize) -> Self {
        Self {
            state: Mutex::default(),
            timeout,
            capacity,
            count: watch::Sender::new(0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("approval state poisoned")
    }

    /// Holds the request until it is answered or a fail-closed condition applies.
    pub async fn ask(&self, held: Held) -> Outcome {
        let (id, answer) = {
            let mut state = self.lock();
            let now = Instant::now();
            state.grants.retain(|_, until| *until > now);
            if let Some(image) = image(&held.process)
                && state
                    .grants
                    .contains_key(&(image.to_string(), held.host.clone()))
            {
                return Outcome::Allowed("granted for process and host");
            }
            if state.paused {
                return Outcome::Blocked("approval paused");
            }
            if state.windows == 0 {
                return Outcome::Blocked("no approval window");
            }
            if state.pending.len() >= self.capacity {
                return Outcome::Blocked("approval queue full");
            }
            let id = state.next_id;
            state.next_id += 1;
            let (reply, answer) = oneshot::channel();
            state.pending.push_back(Pending {
                id,
                held,
                deadline: now + self.timeout,
                reply,
            });
            self.count.send_replace(state.pending.len());
            (id, answer)
        };
        let _unqueue = Unqueue(self, id);
        match tokio::time::timeout(self.timeout, answer).await {
            Ok(Ok(Verdict::AllowOnce)) => Outcome::Allowed("approved once"),
            Ok(Ok(Verdict::AllowFor(_))) => Outcome::Allowed("approved for process and host"),
            Ok(Ok(Verdict::Deny)) => Outcome::Blocked("approval denied"),
            // The sender is dropped by pause or a closing window.
            Ok(Err(_)) => Outcome::Blocked("approval withdrawn"),
            Err(_) => Outcome::Blocked("approval timed out"),
        }
    }

    /// Answers a waiting request; false if it is no longer waiting.
    pub fn answer(&self, id: u64, verdict: Verdict) -> bool {
        let mut state = self.lock();
        let Some(at) = state.pending.iter().position(|p| p.id == id) else {
            return false;
        };
        let pending = state.pending.remove(at).expect("position is in range");
        if let Verdict::AllowFor(duration) = verdict
            && let Some(image) = image(&pending.held.process)
        {
            state.grants.insert(
                (image.to_string(), pending.held.host.clone()),
                Instant::now() + duration,
            );
        }
        self.count.send_replace(state.pending.len());
        // The asker may have just timed out; then the verdict is moot.
        pending.reply.send(verdict).is_ok()
    }

    /// Waiting requests in arrival order, with their id and time left.
    pub fn pending(&self) -> Vec<(u64, Held, Duration)> {
        let now = Instant::now();
        self.lock()
            .pending
            .iter()
            .map(|p| {
                (
                    p.id,
                    p.held.clone(),
                    p.deadline.saturating_duration_since(now),
                )
            })
            .collect()
    }

    /// The number of waiting requests, updated on every change.
    pub fn watch(&self) -> watch::Receiver<usize> {
        self.count.subscribe()
    }

    /// Pausing blocks new and waiting approvals (fail closed); grants still apply.
    pub fn set_paused(&self, paused: bool) {
        let mut state = self.lock();
        state.paused = paused;
        if paused {
            // Dropping the reply senders blocks every waiting request.
            state.pending.clear();
            self.count.send_replace(0);
        }
    }

    pub fn paused(&self) -> bool {
        self.lock().paused
    }

    /// Attaches an approval window for as long as the guard lives.
    pub fn attach(self: &Arc<Self>) -> Window {
        self.lock().windows += 1;
        Window(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(host: &str) -> Held {
        Held {
            process: Process::Known {
                pid: 7,
                start: 1,
                image: r"C:\tools\smartwizz.exe".into(),
                user: r"PC\dev".into(),
            },
            host: host.into(),
            rule: "secrets-to-unknown-hosts".into(),
            findings: vec!["secret.github_token".into()],
        }
    }

    fn approvals(timeout_ms: u64, capacity: usize) -> Arc<Approvals> {
        Arc::new(Approvals::new(Duration::from_millis(timeout_ms), capacity))
    }

    /// Starts an ask in the background and waits until it is queued.
    async fn queued(a: &Arc<Approvals>, host: &str) -> (u64, tokio::task::JoinHandle<Outcome>) {
        let before = a.pending().len();
        let task = tokio::spawn({
            let (a, held) = (a.clone(), held(host));
            async move { a.ask(held).await }
        });
        let mut count = a.watch();
        count.wait_for(|n| *n > before).await.unwrap();
        (a.pending().last().unwrap().0, task)
    }

    #[tokio::test]
    async fn allow_once_and_deny() {
        let a = approvals(5_000, 4);
        let _window = a.attach();
        let (id, task) = queued(&a, "api.example.com").await;
        let (_, shown, left) = &a.pending()[0];
        assert_eq!(shown, &held("api.example.com"));
        assert!(*left <= Duration::from_secs(5));
        assert!(a.answer(id, Verdict::AllowOnce));
        assert_eq!(task.await.unwrap(), Outcome::Allowed("approved once"));
        assert!(!a.answer(id, Verdict::AllowOnce), "answered only once");

        let (id, task) = queued(&a, "api.example.com").await;
        a.answer(id, Verdict::Deny);
        assert_eq!(task.await.unwrap(), Outcome::Blocked("approval denied"));
        assert!(a.pending().is_empty());
        assert_eq!(*a.watch().borrow(), 0);
    }

    #[tokio::test]
    async fn timeout_blocks_and_unqueues() {
        let a = approvals(50, 4);
        let _window = a.attach();
        assert_eq!(
            a.ask(held("h")).await,
            Outcome::Blocked("approval timed out")
        );
        assert!(a.pending().is_empty());
    }

    #[tokio::test]
    async fn full_queue_blocks() {
        let a = approvals(5_000, 1);
        let _window = a.attach();
        let (_id, _task) = queued(&a, "one").await;
        assert_eq!(
            a.ask(held("two")).await,
            Outcome::Blocked("approval queue full")
        );
    }

    #[tokio::test]
    async fn no_window_blocks() {
        let a = approvals(5_000, 4);
        assert_eq!(
            a.ask(held("h")).await,
            Outcome::Blocked("no approval window")
        );
        drop(a.attach());
        assert_eq!(
            a.ask(held("h")).await,
            Outcome::Blocked("no approval window")
        );
    }

    #[tokio::test]
    async fn pause_blocks_new_and_waiting_requests() {
        let a = approvals(5_000, 4);
        let _window = a.attach();
        let (_id, task) = queued(&a, "h").await;
        a.set_paused(true);
        assert_eq!(task.await.unwrap(), Outcome::Blocked("approval withdrawn"));
        assert_eq!(a.ask(held("h")).await, Outcome::Blocked("approval paused"));
        a.set_paused(false);
        assert!(!a.paused());
    }

    #[tokio::test]
    async fn grants_cover_process_and_host_until_expiry() {
        let a = approvals(5_000, 4);
        let _window = a.attach();
        let (id, task) = queued(&a, "api.example.com").await;
        a.answer(id, Verdict::AllowFor(Duration::from_millis(150)));
        assert_eq!(
            task.await.unwrap(),
            Outcome::Allowed("approved for process and host")
        );
        // Granted without asking, even while paused.
        a.set_paused(true);
        assert_eq!(
            a.ask(held("api.example.com")).await,
            Outcome::Allowed("granted for process and host")
        );
        a.set_paused(false);
        // Another host still asks.
        let (id, task) = queued(&a, "other.example.com").await;
        a.answer(id, Verdict::Deny);
        assert_eq!(task.await.unwrap(), Outcome::Blocked("approval denied"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (_id, task) = queued(&a, "api.example.com").await;
        task.abort();
    }

    #[tokio::test]
    async fn unknown_processes_never_get_grants() {
        let a = approvals(5_000, 4);
        let _window = a.attach();
        let mut unknown = held("h");
        unknown.process = Process::Unknown("pid reused");
        let task = tokio::spawn({
            let (a, unknown) = (a.clone(), unknown.clone());
            async move { a.ask(unknown).await }
        });
        a.watch().wait_for(|n| *n == 1).await.unwrap();
        a.answer(a.pending()[0].0, Verdict::AllowFor(Duration::from_secs(60)));
        assert!(matches!(task.await.unwrap(), Outcome::Allowed(_)));
        let task = tokio::spawn({
            let a = a.clone();
            async move { a.ask(unknown).await }
        });
        a.watch().wait_for(|n| *n == 1).await.unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn a_client_that_leaves_is_unqueued() {
        let a = approvals(5_000, 4);
        let _window = a.attach();
        let (_id, task) = queued(&a, "h").await;
        task.abort();
        let _ = task.await;
        assert!(a.pending().is_empty());
        assert_eq!(*a.watch().borrow(), 0);
    }
}
