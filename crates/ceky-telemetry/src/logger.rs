//! Custom tracing subscriber to capture logs for the TUI.

use crossbeam::channel::Sender;
use tracing_core::{Event, Subscriber};
use tracing_subscriber::{layer::Context, Layer};
use chrono::Local;

#[derive(Clone, Debug)]
pub struct LogMessage {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

pub struct TuiLoggerLayer {
    sender: Sender<LogMessage>,
}

impl TuiLoggerLayer {
    pub fn new(sender: Sender<LogMessage>) -> Self {
        Self { sender }
    }
}

impl<S> Layer<S> for TuiLoggerLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = StringVisitor::new();
        event.record(&mut visitor);

        let log = LogMessage {
            timestamp: Local::now().format("%H:%M:%S").to_string(),
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.message,
        };

        let _ = self.sender.try_send(log);
    }
}

struct StringVisitor {
    message: String,
}

impl StringVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
        }
    }
}

impl tracing_core::field::Visit for StringVisitor {
    fn record_debug(&mut self, field: &tracing_core::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
            // strip quotes from debug format if any, but it's fine for now
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len()-1].to_string();
            }
        } else {
            self.message.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }
}
