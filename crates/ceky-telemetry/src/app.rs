//! TUI Application state and render loop.

use crate::logger::LogMessage;
use crate::metrics::GlobalMetrics;
use crossbeam::channel::Receiver;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub struct TuiApp {
    pub metrics: Arc<GlobalMetrics>,
    pub log_rx: Receiver<LogMessage>,
    pub logs: Vec<LogMessage>,
    pub tx_history: Vec<u64>,
    pub rx_history: Vec<u64>,
}

impl TuiApp {
    pub fn new(metrics: Arc<GlobalMetrics>, log_rx: Receiver<LogMessage>) -> Self {
        Self {
            metrics,
            log_rx,
            logs: Vec::new(),
            tx_history: vec![0; 100],
            rx_history: vec![0; 100],
        }
    }

    pub fn on_tick(&mut self) {
        // Fetch new logs
        while let Ok(log) = self.log_rx.try_recv() {
            self.logs.push(log);
            if self.logs.len() > 100 {
                self.logs.remove(0);
            }
        }
        
        // Update history (shift left and push new)
        let tx = self.metrics.tx_rate.load(std::sync::atomic::Ordering::Relaxed) as u64;
        let rx = self.metrics.rx_rate.load(std::sync::atomic::Ordering::Relaxed) as u64;
        
        self.tx_history.remove(0);
        self.tx_history.push(tx);
        
        self.rx_history.remove(0);
        self.rx_history.push(rx);
    }
}

pub fn run_tui(
    metrics: Arc<GlobalMetrics>,
    log_rx: Receiver<LogMessage>,
    shutdown_token: CancellationToken,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = TuiApp::new(metrics, log_rx);
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| crate::ui::draw(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') | KeyCode::Char('Q') = key.code {
                    shutdown_token.cancel();
                    break;
                }
                if key.code == KeyCode::Char('c') && key.modifiers.contains(event::KeyModifiers::CONTROL) {
                    shutdown_token.cancel();
                    break;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        }

        if shutdown_token.is_cancelled() {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
