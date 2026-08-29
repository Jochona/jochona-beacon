use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use jochona_beacon::app::{self, Config};
use tracing_subscriber::EnvFilter;

/// Jochona Beacon: pairs with the Jochona Client and wakes registered
/// Jochona/Sunshine/Apollo Hosts on the local LAN.
#[derive(Parser)]
#[command(name = "jochona-beacon", version, about)]
struct Cli {
    /// Directory holding the SQLite database and (if not using a systemd
    /// credential) the fallback master key file.
    #[arg(
        long,
        env = "JOCHONA_BEACON_DATA_DIR",
        default_value = "/var/lib/jochona-beacon"
    )]
    data_dir: PathBuf,

    /// LAN-reachable mTLS HTTPS API listener (the wire contract surface).
    #[arg(long, env = "JOCHONA_BEACON_BIND", default_value = "0.0.0.0:47100")]
    bind: SocketAddr,

    /// Loopback-only administration interface.
    #[arg(
        long,
        env = "JOCHONA_BEACON_ADMIN_BIND",
        default_value = "127.0.0.1:47101"
    )]
    admin_bind: SocketAddr,

    /// Hostname advertised via mDNS as `<hostname>.local.`. Defaults to
    /// the machine's own hostname.
    #[arg(long, env = "JOCHONA_BEACON_HOSTNAME")]
    hostname: Option<String>,

    /// Seconds between `/serverinfo` observation polls of each enrolled Host.
    #[arg(
        long,
        env = "JOCHONA_BEACON_OBSERVER_INTERVAL_SECS",
        default_value_t = 30
    )]
    observer_interval_secs: u64,

    /// Seconds between sweeps for abandoned pairing windows.
    #[arg(
        long,
        env = "JOCHONA_BEACON_PAIRING_SWEEP_INTERVAL_SECS",
        default_value_t = 10
    )]
    pairing_sweep_interval_secs: u64,

    /// Seconds between retention-pruning sweeps of the event/observation logs.
    #[arg(
        long,
        env = "JOCHONA_BEACON_RETENTION_SWEEP_INTERVAL_SECS",
        default_value_t = 3600
    )]
    retention_sweep_interval_secs: u64,

    /// How many days of audit events to retain.
    #[arg(
        long,
        env = "JOCHONA_BEACON_EVENT_RETENTION_DAYS",
        default_value_t = 30
    )]
    event_retention_days: i64,

    /// How many days of Host online/offline observations to retain.
    #[arg(
        long,
        env = "JOCHONA_BEACON_OBSERVATION_RETENTION_DAYS",
        default_value_t = 30
    )]
    observation_retention_days: i64,

    /// Log output format.
    #[arg(long, env = "JOCHONA_BEACON_LOG_FORMAT", default_value = "pretty")]
    log_format: LogFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Pretty,
    Json,
}

fn default_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "jochona-beacon".to_string())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match format {
        LogFormat::Pretty => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(cli.log_format);

    let config = Config {
        data_dir: cli.data_dir,
        bind: cli.bind,
        admin_bind: cli.admin_bind,
        hostname: cli.hostname.unwrap_or_else(default_hostname),
        observer_poll_interval: Duration::from_secs(cli.observer_interval_secs),
        pairing_sweep_interval: Duration::from_secs(cli.pairing_sweep_interval_secs),
        retention_sweep_interval: Duration::from_secs(cli.retention_sweep_interval_secs),
        event_retention: time::Duration::days(cli.event_retention_days),
        observation_retention: time::Duration::days(cli.observation_retention_days),
    };

    if let Err(err) = app::run(config).await {
        tracing::error!(error = %err, "jochona-beacon exited with an error");
        std::process::exit(1);
    }
}
