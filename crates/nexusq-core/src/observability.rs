//! Safe, dependency-light observability primitives.
//!
//! Metrics contain aggregate counters and durations only. They deliberately
//! do not accept payloads, keys, passwords, plaintext, signatures, or tokens.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const OBSERVABILITY_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct Metrics {
    started_at: Instant,
    operations_total: Arc<AtomicU64>,
    errors_total: Arc<AtomicU64>,
    operation_duration_ns: Arc<AtomicU64>,
    operation_duration_count: Arc<AtomicU64>,
    requests_total: Arc<AtomicU64>,
    request_errors_total: Arc<AtomicU64>,
    request_duration_ns: Arc<AtomicU64>,
    request_duration_count: Arc<AtomicU64>,
    key_operations_total: Arc<AtomicU64>,
    vault_operations_total: Arc<AtomicU64>,
    hardware_status: Arc<AtomicU64>,
    next_request_id: Arc<AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            operations_total: Arc::new(AtomicU64::new(0)),
            errors_total: Arc::new(AtomicU64::new(0)),
            operation_duration_ns: Arc::new(AtomicU64::new(0)),
            operation_duration_count: Arc::new(AtomicU64::new(0)),
            requests_total: Arc::new(AtomicU64::new(0)),
            request_errors_total: Arc::new(AtomicU64::new(0)),
            request_duration_ns: Arc::new(AtomicU64::new(0)),
            request_duration_count: Arc::new(AtomicU64::new(0)),
            key_operations_total: Arc::new(AtomicU64::new(0)),
            vault_operations_total: Arc::new(AtomicU64::new(0)),
            hardware_status: Arc::new(AtomicU64::new(1)),
            next_request_id: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_operation(&self, operation: &str, elapsed: Duration, success: bool) {
        self.operations_total.fetch_add(1, Ordering::Relaxed);
        self.operation_duration_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.operation_duration_count
            .fetch_add(1, Ordering::Relaxed);
        if !success {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        if operation.starts_with("key.") {
            self.key_operations_total.fetch_add(1, Ordering::Relaxed);
        }
        if operation.starts_with("vault.") {
            self.vault_operations_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_request(&self, elapsed: Duration, success: bool) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.request_duration_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        self.request_duration_count.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.request_errors_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn set_hardware_status(&self, available: bool) {
        self.hardware_status
            .store(u64::from(available), Ordering::Relaxed);
    }

    pub fn request_id(&self) -> String {
        let sequence = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("nq-{millis:x}-{sequence:x}")
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn prometheus(&self) -> String {
        fn avg(sum: u64, count: u64) -> f64 {
            if count == 0 {
                0.0
            } else {
                (sum as f64 / count as f64) / 1_000_000_000.0
            }
        }
        let operations = self.operations_total.load(Ordering::Relaxed);
        let errors = self.errors_total.load(Ordering::Relaxed);
        let op_sum = self.operation_duration_ns.load(Ordering::Relaxed);
        let op_count = self.operation_duration_count.load(Ordering::Relaxed);
        let requests = self.requests_total.load(Ordering::Relaxed);
        let request_errors = self.request_errors_total.load(Ordering::Relaxed);
        let request_sum = self.request_duration_ns.load(Ordering::Relaxed);
        let request_count = self.request_duration_count.load(Ordering::Relaxed);
        let key_ops = self.key_operations_total.load(Ordering::Relaxed);
        let vault_ops = self.vault_operations_total.load(Ordering::Relaxed);
        let hardware = self.hardware_status.load(Ordering::Relaxed);
        let uptime = self.uptime().as_secs_f64();
        format!(
            "# HELP nexusq_operations_total Total NEXUS-Q operations.\\n# TYPE nexusq_operations_total counter\\nnexusq_operations_total {operations}\\n# HELP nexusq_errors_total Total failed NEXUS-Q operations.\\n# TYPE nexusq_errors_total counter\\nnexusq_errors_total {errors}\\n# HELP nexusq_operation_duration_seconds_sum Total operation duration in seconds.\\n# TYPE nexusq_operation_duration_seconds summary\\nnexusq_operation_duration_seconds_sum {}\\n# HELP nexusq_operation_duration_seconds_count Total observed operation durations.\\nnexusq_operation_duration_seconds_count {op_count}\\n# HELP nexusq_operation_latency_seconds Average observed operation latency in seconds.\\n# TYPE nexusq_operation_latency_seconds gauge\\nnexusq_operation_latency_seconds {}\\n# HELP nexusq_requests_total Total HTTP requests.\\n# TYPE nexusq_requests_total counter\\nnexusq_requests_total {requests}\\n# HELP nexusq_request_errors_total Total HTTP requests returning non-success status.\\n# TYPE nexusq_request_errors_total counter\\nnexusq_request_errors_total {request_errors}\\n# HELP nexusq_request_duration_seconds_sum Total HTTP request duration in seconds.\\n# TYPE nexusq_request_duration_seconds summary\\nnexusq_request_duration_seconds_sum {}\\n# HELP nexusq_request_duration_seconds_count Total observed HTTP request durations.\\nnexusq_request_duration_seconds_count {request_count}\\n# HELP nexusq_request_latency_seconds Average observed HTTP request latency in seconds.\\n# TYPE nexusq_request_latency_seconds gauge\\nnexusq_request_latency_seconds {}\\n# HELP nexusq_key_operations_total Total key lifecycle/usage operations.\\n# TYPE nexusq_key_operations_total counter\\nnexusq_key_operations_total {key_ops}\\n# HELP nexusq_vault_operations_total Total vault operations.\\n# TYPE nexusq_vault_operations_total counter\\nnexusq_vault_operations_total {vault_ops}\\n# HELP nexusq_hardware_status Hardware backend availability (1 available, 0 unavailable).\\n# TYPE nexusq_hardware_status gauge\\nnexusq_hardware_status {hardware}\\n# HELP nexusq_uptime_seconds Process uptime in seconds.\\n# TYPE nexusq_uptime_seconds gauge\\nnexusq_uptime_seconds {uptime:.6}\\n",
            op_sum as f64 / 1_000_000_000.0,
            avg(op_sum, op_count),
            request_sum as f64 / 1_000_000_000.0,
            avg(request_sum, request_count),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_aggregate_and_secret_free() {
        let metrics = Metrics::new();
        metrics.record_operation("key.generate", Duration::from_millis(2), true);
        metrics.record_operation("vault.unlock", Duration::from_millis(3), false);
        metrics.record_request(Duration::from_millis(5), true);
        let text = metrics.prometheus();
        assert!(text.contains("nexusq_key_operations_total 1"));
        assert!(text.contains("nexusq_vault_operations_total 1"));
        assert!(text.contains("nexusq_errors_total 1"));
        assert!(!text.contains("password"));
        assert!(!text.contains("plaintext"));
    }

    #[test]
    fn request_ids_are_unique() {
        let metrics = Metrics::new();
        assert_ne!(metrics.request_id(), metrics.request_id());
    }
}
