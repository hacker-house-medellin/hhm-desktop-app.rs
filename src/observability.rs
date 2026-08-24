//! Bounded Ores/OpenTelemetry event emission.
//!
//! Events contain only fixed, low-cardinality state names and outcomes. Raw
//! tokens, QR payloads, beacon identifiers, identity attributes, and URLs are
//! deliberately excluded.

use std::sync::Arc;

use next_loggers::{JsonObject, Logger, OpenTelemetryTransport, Options, Value, json};

pub struct Observability {
    logger: Logger,
}

impl Observability {
    #[must_use]
    pub fn new() -> Self {
        let transport = OpenTelemetryTransport::new(|record| {
            tracing::info!(
                target: "ores_otel",
                otel_body = %record.body,
                otel_severity_text = %record.severity_text,
                otel_severity_number = record.severity_number,
                otel_attributes = ?record.attributes,
                "Ores structured desktop event"
            );
            Ok(())
        });
        Self {
            logger: Logger::new(Options {
                app_name: "hhm-desktop-app".to_owned(),
                console: false,
                transports: vec![Arc::new(transport)],
                ..Options::default()
            }),
        }
    }

    pub fn state_transition(&self, category: &'static str, outcome: &'static str) {
        let fields = JsonObject::from_iter([
            (
                "event.name".to_owned(),
                Value::String("desktop.state.transition".to_owned()),
            ),
            (
                "state.category".to_owned(),
                Value::String(category.to_owned()),
            ),
            (
                "event.outcome".to_owned(),
                Value::String(outcome.to_owned()),
            ),
        ]);

        if self
            .logger
            .info(vec![json!("desktop state transition")])
            .add_fields(fields)
            .send()
            .is_err()
        {
            tracing::warn!(target: "ores_otel", "Ores transport rejected a bounded event");
        }
    }
}

impl Default for Observability {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_event_is_accepted() {
        Observability::new().state_transition("proximity", "nearby");
    }
}
