use colored::*;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::format::{self, Writer};
use tracing_subscriber::registry::LookupSpan;

pub struct ZondFormatter {
    pub max_verbosity: u8,
}

impl<S, N> FormatEvent<S, N> for ZondFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> format::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();

        if meta.target() == "zond::print" {
            let mut visitor = RawVisitor::new(writer.by_ref());
            event.record(&mut visitor);
            return write!(writer, "\r\n");
        }

        let mut meta_visitor = MetaVisitor::default();
        event.record(&mut meta_visitor);

        let event_verbosity = meta_visitor.verbosity.unwrap_or(0);
        if event_verbosity > self.max_verbosity {
            return Ok(());
        }

        let (symbol, color_func): (&str, fn(ColoredString) -> ColoredString) = match *meta.level() {
            Level::TRACE => ("[ ]", |s| s.dimmed()),
            Level::DEBUG => ("[?]", |s| s.blue()),
            Level::INFO => match meta_visitor.status.as_deref() {
                Some("info") => ("[»]", |s| s.cyan().bold()),
                _ => ("[+]", |s| s.green().bold()),
            },
            Level::WARN => ("[*]", |s| s.yellow().bold()),
            Level::ERROR => ("[-]", |s| s.red().bold()),
        };

        write!(writer, "{} ", color_func(symbol.into()))?;

        let mut output_visitor = OutputVisitor::new(writer.by_ref());
        event.record(&mut output_visitor);

        write!(writer, "\r\n")
    }
}

#[derive(Default)]
struct MetaVisitor {
    status: Option<String>,
    verbosity: Option<u8>,
}

impl Visit for MetaVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "verbosity" {
            self.verbosity = Some(value as u8);
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "verbosity" {
            self.verbosity = Some(value as u8);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "status" {
            self.status = Some(value.to_string());
        }
    }
}

struct OutputVisitor<'a> {
    writer: Writer<'a>,
}

impl<'a> OutputVisitor<'a> {
    fn new(writer: Writer<'a>) -> Self {
        Self { writer }
    }
}

impl<'a> Visit for OutputVisitor<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "status" || field.name() == "verbosity" {
            return;
        }

        if field.name() == "message" {
            let _ = write!(self.writer, "{:?}", value);
        } else {
            let _ = write!(self.writer, " {}={:?}", field.name().italic(), value);
        }
    }
}

struct RawVisitor<'a> {
    writer: Writer<'a>,
}

impl<'a> RawVisitor<'a> {
    fn new(writer: Writer<'a>) -> Self {
        Self { writer }
    }
}

impl<'a> Visit for RawVisitor<'a> {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "raw_msg" {
            let replaced = value.replace('\n', "\r\n");
            let _ = write!(self.writer, "{}", replaced);
        }
    }
}

