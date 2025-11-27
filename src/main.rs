use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};

// Separate module for unsafe operations
#[allow(unsafe_code)]
mod nvme_ioctl {
    use std::os::unix::io::RawFd;

    const NVME_IOCTL_ADMIN_CMD: u64 = 0xC0484E41;

    #[repr(C)]
    #[derive(Default)]
    pub struct NvmeAdminCmd {
        pub opcode: u8,
        pub flags: u8,
        pub rsvd1: u16,
        pub nsid: u32,
        pub cdw2: u32,
        pub cdw3: u32,
        pub metadata: u64,
        pub addr: u64,
        pub metadata_len: u32,
        pub data_len: u32,
        pub cdw10: u32,
        pub cdw11: u32,
        pub cdw12: u32,
        pub cdw13: u32,
        pub cdw14: u32,
        pub cdw15: u32,
        pub timeout_ms: u32,
        pub result: u32,
    }

    pub fn ioctl_admin_cmd(fd: RawFd, cmd: &mut NvmeAdminCmd) -> std::io::Result<()> {
        unsafe {
            let ret = libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
            if ret < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

use nvme_ioctl::{NvmeAdminCmd, ioctl_admin_cmd};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct NvmeSmartLog {
    critical_warning: u8,
    temperature: [u8; 2],
    avail_spare: u8,
    spare_thresh: u8,
    percent_used: u8,
    rsvd6: [u8; 26],
    data_units_read: [u8; 16],
    data_units_written: [u8; 16],
    host_reads: [u8; 16],
    host_writes: [u8; 16],
    ctrl_busy_time: [u8; 16],
    power_cycles: [u8; 16],
    power_on_hours: [u8; 16],
    unsafe_shutdowns: [u8; 16],
    media_errors: [u8; 16],
    num_err_log_entries: [u8; 16],
    warning_temp_time: u32,
    critical_comp_time: u32,
    temp_sensor: [u16; 8],
    thermal_mgmt_temp1_trans_count: u32,
    thermal_mgmt_temp2_trans_count: u32,
    thermal_mgmt_temp1_total_time: u32,
    thermal_mgmt_temp2_total_time: u32,
    rsvd232: [u8; 280],
}

impl Default for NvmeSmartLog {
    fn default() -> Self {
        Self {
            critical_warning: 0,
            temperature: [0; 2],
            avail_spare: 0,
            spare_thresh: 0,
            percent_used: 0,
            rsvd6: [0; 26],
            data_units_read: [0; 16],
            data_units_written: [0; 16],
            host_reads: [0; 16],
            host_writes: [0; 16],
            ctrl_busy_time: [0; 16],
            power_cycles: [0; 16],
            power_on_hours: [0; 16],
            unsafe_shutdowns: [0; 16],
            media_errors: [0; 16],
            num_err_log_entries: [0; 16],
            warning_temp_time: 0,
            critical_comp_time: 0,
            temp_sensor: [0; 8],
            thermal_mgmt_temp1_trans_count: 0,
            thermal_mgmt_temp2_trans_count: 0,
            thermal_mgmt_temp1_total_time: 0,
            thermal_mgmt_temp2_total_time: 0,
            rsvd232: [0; 280],
        }
    }
}

// Simplified NVMe Identify Controller structure
// We only define the fields we need to avoid defining the entire 4096 byte structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct NvmeIdentifyController {
    vid: u16,         // PCI Vendor ID
    ssvid: u16,       // PCI Subsystem Vendor ID
    sn: [u8; 20],     // Serial Number
    mn: [u8; 40],     // Model Number
    fr: [u8; 8],      // Firmware Revision
    rab: u8,          // Recommended Arbitration Burst
    ieee: [u8; 3],    // IEEE OUI Identifier
    cmic: u8,         // Controller Multi-Path I/O and Namespace Sharing Capabilities
    mdts: u8,         // Maximum Data Transfer Size
    cntlid: u16,      // Controller ID
    ver: u32,         // Version
    rtd3r: u32,       // RTD3 Resume Latency
    rtd3e: u32,       // RTD3 Entry Latency
    oaes: u32,        // Optional Async Events Supported
    ctratt: u32,      // Controller Attributes
    rrls: u16,        // Read Recovery Levels Supported
    rsvd106: [u8; 9], // Reserved
    cntrltype: u8,    // Controller Type
    fguid: [u8; 16],  // FRU Globally Unique Identifier
    crdt1: u16,       // Command Retry Delay Time 1
    crdt2: u16,       // Command Retry Delay Time 2
    crdt3: u16,       // Command Retry Delay Time 3
    rsvd134: [u8; 122], // Reserved
                      // We stop here as we only need SN and MN which are at the beginning
                      // The full structure is 4096 bytes
}

// Full identify data structure (4096 bytes)
#[repr(C)]
struct NvmeIdentifyData {
    controller: NvmeIdentifyController,
    _padding: [u8; 3840], // 4096 - 256 = 3840
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(default = "default_check_interval")]
    check_interval_secs: u64,
    #[serde(default)]
    thresholds: Thresholds,
    #[serde(default)]
    email: Option<EmailConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Thresholds {
    #[serde(default = "default_temp_warning")]
    temp_warning: u16,
    #[serde(default = "default_temp_critical")]
    temp_critical: u16,
    #[serde(default = "default_wear_warning")]
    wear_warning: u8,
    #[serde(default = "default_wear_critical")]
    wear_critical: u8,
    #[serde(default = "default_spare_warning")]
    spare_warning: u8,
    #[serde(default = "default_error_threshold")]
    error_threshold: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct EmailConfig {
    smtp_server: String,
    smtp_port: u16,
    smtp_username: String,
    smtp_password_file: String,
    from: String,
    to: String,
    #[serde(default = "default_use_tls")]
    use_tls: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            check_interval_secs: default_check_interval(),
            thresholds: Default::default(),
            email: None,
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            temp_warning: default_temp_warning(),
            temp_critical: default_temp_critical(),
            wear_warning: default_wear_warning(),
            wear_critical: default_wear_critical(),
            spare_warning: default_spare_warning(),
            error_threshold: default_error_threshold(),
        }
    }
}

fn default_check_interval() -> u64 {
    3600
}
fn default_temp_warning() -> u16 {
    55
}
fn default_temp_critical() -> u16 {
    65
}
fn default_wear_warning() -> u8 {
    20
}
fn default_wear_critical() -> u8 {
    50
}
fn default_spare_warning() -> u8 {
    50
}
fn default_error_threshold() -> u64 {
    100
}
fn default_use_tls() -> bool {
    true
}

#[derive(Parser)]
#[command(name = "nvme-rs")]
#[command(about = "NVMe drive health monitoring tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check NVMe drives once and exit
    Check {
        /// Config file path
        #[arg(short, long)]
        config: Option<String>,
        /// Output format (text or json)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Run as a daemon
    Daemon {
        /// Config file path
        #[arg(short, long, required = true)]
        config: String,
    },
}

#[derive(Debug, Serialize)]
struct DriveInfo {
    model: String,
    serial_number: String,
}

#[derive(Debug, Serialize)]
struct DriveStatus {
    device: String,
    info: DriveInfo,
    temperature_c: u16,
    wear_percentage: u8,
    spare_percentage: u8,
    errors: u128,
    media_errors: u128,
    power_on_hours: u128,
    data_written_tb: f64,
    data_read_tb: f64,
    alerts: Vec<Alert>,
}

#[derive(Debug, Clone, Serialize)]
struct Alert {
    level: AlertLevel,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
enum AlertLevel {
    Warning,
    Critical,
}

impl AlertLevel {
    fn as_str(&self) -> &'static str {
        match self {
            AlertLevel::Critical => "CRITICAL",
            AlertLevel::Warning => "WARNING",
        }
    }

    fn as_css_class(&self) -> &'static str {
        match self {
            AlertLevel::Critical => "critical",
            AlertLevel::Warning => "warning",
        }
    }
}

fn u128_from_bytes(bytes: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*bytes)
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn get_identify_controller(device_path: &str) -> Result<NvmeIdentifyController> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)
        .with_context(|| format!("Failed to open device {device_path}"))?;

    let mut identify_data = NvmeIdentifyData {
        controller: NvmeIdentifyController {
            vid: 0,
            ssvid: 0,
            sn: [0; 20],
            mn: [0; 40],
            fr: [0; 8],
            rab: 0,
            ieee: [0; 3],
            cmic: 0,
            mdts: 0,
            cntlid: 0,
            ver: 0,
            rtd3r: 0,
            rtd3e: 0,
            oaes: 0,
            ctratt: 0,
            rrls: 0,
            rsvd106: [0; 9],
            cntrltype: 0,
            fguid: [0; 16],
            crdt1: 0,
            crdt2: 0,
            crdt3: 0,
            rsvd134: [0; 122],
        },
        _padding: [0; 3840],
    };

    let mut cmd = NvmeAdminCmd {
        opcode: 0x06, // Identify
        nsid: 0,
        addr: &mut identify_data as *mut _ as u64,
        data_len: 4096,
        cdw10: 0x01, // CNS = 0x01 for Identify Controller
        ..Default::default()
    };

    ioctl_admin_cmd(file.as_raw_fd(), &mut cmd)
        .map_err(|e| anyhow::anyhow!("Failed to get identify controller: {}", e))?;

    Ok(identify_data.controller)
}

fn get_smart_log(device_path: &str) -> Result<NvmeSmartLog> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device_path)
        .with_context(|| format!("Failed to open device {device_path}"))?;

    let mut smart_log = NvmeSmartLog::default();
    let mut cmd = NvmeAdminCmd {
        opcode: 0x02, // Get Log Page
        nsid: 0xffffffff,
        addr: &mut smart_log as *mut _ as u64,
        data_len: std::mem::size_of::<NvmeSmartLog>() as u32,
        cdw10: 0x02 | (((std::mem::size_of::<NvmeSmartLog>() / 4) - 1) << 16) as u32,
        ..Default::default()
    };

    ioctl_admin_cmd(file.as_raw_fd(), &mut cmd)
        .map_err(|e| anyhow::anyhow!("ioctl failed: {}", e))?;

    Ok(smart_log)
}

fn check_drive_health(
    device: &str,
    smart_log: &NvmeSmartLog,
    identify: &NvmeIdentifyController,
    thresholds: &Thresholds,
) -> DriveStatus {
    let mut alerts = Vec::new();

    let temp = u16::from_le_bytes(smart_log.temperature).saturating_sub(273);

    if temp >= thresholds.temp_critical {
        alerts.push(Alert {
            level: AlertLevel::Critical,
            message: format!(
                "Critical temperature: {}°C (threshold: {}°C)",
                temp, thresholds.temp_critical
            ),
        });
    } else if temp >= thresholds.temp_warning {
        alerts.push(Alert {
            level: AlertLevel::Warning,
            message: format!(
                "High temperature: {}°C (threshold: {}°C)",
                temp, thresholds.temp_warning
            ),
        });
    }

    if smart_log.percent_used >= thresholds.wear_critical {
        alerts.push(Alert {
            level: AlertLevel::Critical,
            message: format!(
                "Critical wear level: {}% (threshold: {}%)",
                smart_log.percent_used, thresholds.wear_critical
            ),
        });
    } else if smart_log.percent_used >= thresholds.wear_warning {
        alerts.push(Alert {
            level: AlertLevel::Warning,
            message: format!(
                "High wear level: {}% (threshold: {}%)",
                smart_log.percent_used, thresholds.wear_warning
            ),
        });
    }

    if smart_log.avail_spare < thresholds.spare_warning {
        alerts.push(Alert {
            level: AlertLevel::Warning,
            message: format!(
                "Low spare capacity: {}% (threshold: {}%)",
                smart_log.avail_spare, thresholds.spare_warning
            ),
        });
    }

    let errors = u128_from_bytes(&smart_log.num_err_log_entries);
    if errors > thresholds.error_threshold as u128 {
        alerts.push(Alert {
            level: AlertLevel::Warning,
            message: format!(
                "High error count: {} (threshold: {})",
                errors, thresholds.error_threshold
            ),
        });
    }

    let media_errors = u128_from_bytes(&smart_log.media_errors);
    if media_errors > 0 {
        alerts.push(Alert {
            level: AlertLevel::Critical,
            message: format!("Media errors detected: {media_errors}"),
        });
    }

    DriveStatus {
        device: device.to_string(),
        info: DriveInfo {
            model: bytes_to_string(&identify.mn),
            serial_number: bytes_to_string(&identify.sn),
        },
        temperature_c: temp,
        wear_percentage: smart_log.percent_used,
        spare_percentage: smart_log.avail_spare,
        errors,
        media_errors,
        power_on_hours: u128_from_bytes(&smart_log.power_on_hours),
        data_written_tb: u128_from_bytes(&smart_log.data_units_written) as f64 * 512000.0 / 1e12,
        data_read_tb: u128_from_bytes(&smart_log.data_units_read) as f64 * 512000.0 / 1e12,
        alerts,
    }
}

fn find_nvme_devices() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/dev") else {
        return Vec::new();
    };

    let mut devices: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;

            if name.starts_with("nvme") && name.contains('n') && !name.contains('p') {
                let suffix = &name[4..];
                if suffix.contains('n') {
                    return Some(path.to_string_lossy().into_owned());
                }
            }
            None
        })
        .collect();

    devices.sort();
    devices
}

fn send_email_alert(config: &EmailConfig, statuses: &[DriveStatus]) -> Result<()> {
    let alerts: Vec<_> = statuses
        .iter()
        .flat_map(|s| s.alerts.iter().map(move |a| (s, a)))
        .collect();

    if alerts.is_empty() {
        return Ok(());
    }

    let password = std::fs::read_to_string(&config.smtp_password_file)
        .with_context(|| {
            format!(
                "Failed to read password file: {}",
                config.smtp_password_file
            )
        })?
        .trim()
        .to_string();

    let mut html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    body {{ font-family: Arial, sans-serif; }}
    .critical {{ color: #d32f2f; font-weight: bold; }}
    .warning {{ color: #f57c00; font-weight: bold; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background-color: #f2f2f2; }}
</style>
</head>
<body>
<h2>NVMe Monitoring Report</h2>
<p>Date: {}</p>
<p>Host: {}</p>
<h3>Detected alerts:</h3>
<ul>"#,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        hostname::get().unwrap().to_string_lossy()
    );

    for (status, alert) in &alerts {
        html_body.push_str(&format!(
            r#"<li class="{}">[{} - {}] {}</li>"#,
            alert.level.as_css_class(),
            status.device,
            status.info.model,
            alert.message
        ));
    }

    html_body.push_str(
        r#"</ul>
<h3>Detailed drive status:</h3>
<table>
<tr>
    <th>Drive</th>
    <th>Model</th>
    <th>Serial Number</th>
    <th>Temperature</th>
    <th>Wear</th>
    <th>Spare</th>
    <th>Errors</th>
    <th>Hours</th>
    <th>Written (TB)</th>
    <th>Read (TB)</th>
</tr>"#,
    );

    for status in statuses {
        html_body.push_str(&format!(
            r#"<tr>
    <td>{}</td>
    <td>{}</td>
    <td>{}</td>
    <td>{}°C</td>
    <td>{}%</td>
    <td>{}%</td>
    <td>{}</td>
    <td>{}</td>
    <td>{:.2}</td>
    <td>{:.2}</td>
</tr>"#,
            status.device,
            status.info.model,
            status.info.serial_number,
            status.temperature_c,
            status.wear_percentage,
            status.spare_percentage,
            status.errors,
            status.power_on_hours,
            status.data_written_tb,
            status.data_read_tb
        ));
    }

    html_body.push_str("</table></body></html>");

    let email = Message::builder()
        .from(config.from.parse::<Mailbox>()?)
        .to(config.to.parse::<Mailbox>()?)
        .subject(format!(
            "[NVMe Monitor] Alert - {} issue(s) detected",
            alerts.len()
        ))
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(config.smtp_username.clone(), password);

    let mailer = if config.use_tls {
        SmtpTransport::starttls_relay(&config.smtp_server)?
            .port(config.smtp_port)
            .credentials(creds)
            .build()
    } else {
        SmtpTransport::builder_dangerous(&config.smtp_server)
            .port(config.smtp_port)
            .credentials(creds)
            .build()
    };

    mailer.send(&email)?;
    println!("Alert email sent to {}", config.to);

    Ok(())
}

fn check_all_drives(config: &Config) -> Result<Vec<DriveStatus>> {
    let devices = find_nvme_devices();
    if devices.is_empty() {
        return Err(anyhow::anyhow!("No NVMe devices found"));
    }

    let mut statuses = Vec::new();

    for device in devices {
        match (get_smart_log(&device), get_identify_controller(&device)) {
            (Ok(smart_log), Ok(identify)) => {
                let status = check_drive_health(&device, &smart_log, &identify, &config.thresholds);
                statuses.push(status);
            }
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("Error checking {device}: {e}");
            }
        }
    }

    Ok(statuses)
}

fn print_status_text(statuses: &[DriveStatus]) {
    for status in statuses {
        println!("\n=== {} ===", status.device);
        println!("Model: {}", status.info.model);
        println!("Serial Number: {}", status.info.serial_number);
        println!("Temperature: {}°C", status.temperature_c);
        println!("Wear Level: {}%", status.wear_percentage);
        println!("Available Spare: {}%", status.spare_percentage);
        println!("Error Count: {}", status.errors);
        println!("Media Errors: {}", status.media_errors);
        println!("Power On Hours: {}", status.power_on_hours);
        println!("Data Written: {:.2} TB", status.data_written_tb);
        println!("Data Read: {:.2} TB", status.data_read_tb);

        if status.alerts.is_empty() {
            println!("Status: OK");
        } else {
            println!("Alerts:");
            for alert in &status.alerts {
                println!("  [{}] {}", alert.level.as_str(), alert.message);
            }
        }
    }
}

fn format_log_message(message: &str) -> String {
    format!(
        "{}: {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        message
    )
}

fn run_daemon(config: Config) -> Result<()> {
    println!("Starting NVMe monitor daemon...");
    println!("Check interval: {} seconds", config.check_interval_secs);

    loop {
        match check_all_drives(&config) {
            Ok(statuses) => {
                let has_alerts = statuses.iter().any(|s| !s.alerts.is_empty());

                if has_alerts {
                    println!("{}", format_log_message("Alerts detected"));
                    for status in &statuses {
                        for alert in &status.alerts {
                            println!(
                                "  [{}] {} ({}): {}",
                                alert.level.as_str(),
                                status.device,
                                status.info.model,
                                alert.message
                            );
                        }
                    }

                    if let Some(ref email_config) = config.email
                        && let Err(e) = send_email_alert(email_config, &statuses)
                    {
                        eprintln!("Failed to send email alert: {e}");
                    }
                } else {
                    println!("{}", format_log_message("All drives healthy"));
                }
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    format_log_message(&format!("Error checking drives: {e}"))
                );
            }
        }

        thread::sleep(Duration::from_secs(config.check_interval_secs));
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            config: config_path,
            format,
        } => {
            let config = if let Some(path) = config_path {
                let config_str = std::fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read config file: {path}"))?;
                toml::from_str(&config_str)
                    .with_context(|| format!("Failed to parse config file: {path}"))?
            } else {
                Config::default()
            };

            let statuses = check_all_drives(&config)?;

            match format.as_str() {
                "json" => {
                    println!("{}", serde_json::to_string_pretty(&statuses)?);
                }
                _ => {
                    print_status_text(&statuses);
                }
            }

            std::process::exit(if statuses.iter().any(|s| !s.alerts.is_empty()) {
                1
            } else {
                0
            });
        }
        Commands::Daemon {
            config: config_path,
        } => {
            let config_str = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {config_path}"))?;
            let config: Config = toml::from_str(&config_str)
                .with_context(|| format!("Failed to parse config file: {config_path}"))?;

            run_daemon(config)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identify() -> NvmeIdentifyController {
        let mut identify = NvmeIdentifyController {
            vid: 0,
            ssvid: 0,
            sn: [0; 20],
            mn: [0; 40],
            fr: [0; 8],
            rab: 0,
            ieee: [0; 3],
            cmic: 0,
            mdts: 0,
            cntlid: 0,
            ver: 0,
            rtd3r: 0,
            rtd3e: 0,
            oaes: 0,
            ctratt: 0,
            rrls: 0,
            rsvd106: [0; 9],
            cntrltype: 0,
            fguid: [0; 16],
            crdt1: 0,
            crdt2: 0,
            crdt3: 0,
            rsvd134: [0; 122],
        };
        // Set a test model and serial
        let model = b"Test Model NVMe";
        let serial = b"TEST123456";
        identify.mn[..model.len()].copy_from_slice(model);
        identify.sn[..serial.len()].copy_from_slice(serial);
        identify
    }

    #[test]
    fn test_u128_from_bytes() {
        let bytes: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(u128_from_bytes(&bytes), 1);

        let bytes: [u8; 16] = [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];
        assert_eq!(u128_from_bytes(&bytes), u128::MAX);

        let bytes: [u8; 16] = [0; 16];
        assert_eq!(u128_from_bytes(&bytes), 0);
    }

    #[test]
    fn test_bytes_to_string() {
        let bytes = [72, 101, 108, 108, 111, 0, 0, 0]; // "Hello" with null padding
        assert_eq!(bytes_to_string(&bytes), "Hello");

        let bytes = [32, 84, 101, 115, 116, 32, 0, 0]; // " Test " with null padding
        assert_eq!(bytes_to_string(&bytes), "Test");

        let bytes = [0; 8]; // All nulls
        assert_eq!(bytes_to_string(&bytes), "");
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.thresholds.temp_warning, 55);
        assert_eq!(config.thresholds.temp_critical, 65);
        assert_eq!(config.thresholds.wear_warning, 20);
        assert_eq!(config.thresholds.wear_critical, 50);
        assert_eq!(config.thresholds.spare_warning, 50);
        assert_eq!(config.thresholds.error_threshold, 100);
        assert!(config.email.is_none());
    }

    #[test]
    fn test_config_parsing() {
        let config_content = r#"
check_interval_secs = 7200

[thresholds]
temp_warning = 60
temp_critical = 70
wear_warning = 25
wear_critical = 60
spare_warning = 40
error_threshold = 200

[email]
smtp_server = "smtp.test.com"
smtp_port = 465
smtp_username = "test@test.com"
smtp_password_file = "/tmp/password"
from = "monitor@test.com"
to = "admin@test.com"
use_tls = false
"#;

        let config: Config = toml::from_str(config_content).unwrap();
        assert_eq!(config.check_interval_secs, 7200);
        assert_eq!(config.thresholds.temp_warning, 60);
        assert_eq!(config.thresholds.temp_critical, 70);
        assert_eq!(config.thresholds.wear_warning, 25);
        assert_eq!(config.thresholds.wear_critical, 60);
        assert_eq!(config.thresholds.spare_warning, 40);
        assert_eq!(config.thresholds.error_threshold, 200);

        let email = config.email.unwrap();
        assert_eq!(email.smtp_server, "smtp.test.com");
        assert_eq!(email.smtp_port, 465);
        assert_eq!(email.smtp_username, "test@test.com");
        assert_eq!(email.smtp_password_file, "/tmp/password");
        assert_eq!(email.from, "monitor@test.com");
        assert_eq!(email.to, "admin@test.com");
        assert!(!email.use_tls);
    }

    #[test]
    fn test_partial_config_parsing() {
        let config_content = r#"
[thresholds]
temp_warning = 60
"#;

        let config: Config = toml::from_str(config_content).unwrap();
        assert_eq!(config.check_interval_secs, 3600);
        assert_eq!(config.thresholds.temp_warning, 60);
        assert_eq!(config.thresholds.temp_critical, 65);
    }

    #[test]
    fn test_alert_level_string_conversion() {
        assert_eq!(AlertLevel::Warning.as_str(), "WARNING");
        assert_eq!(AlertLevel::Critical.as_str(), "CRITICAL");
        assert_eq!(AlertLevel::Warning.as_css_class(), "warning");
        assert_eq!(AlertLevel::Critical.as_css_class(), "critical");
    }

    #[test]
    fn test_drive_info_serialization() {
        let info = DriveInfo {
            model: "Samsung SSD 970 EVO Plus".to_string(),
            serial_number: "S4EVNZ0N123456".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Samsung SSD 970 EVO Plus"));
        assert!(json.contains("S4EVNZ0N123456"));
    }

    #[test]
    fn test_check_drive_health_temperature_alerts() {
        let thresholds = Thresholds {
            temp_warning: 55,
            temp_critical: 65,
            ..Default::default()
        };

        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.temperature = (45u16 + 273).to_le_bytes();
        smart_log.avail_spare = 100;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert!(status.alerts.is_empty());
        assert_eq!(status.temperature_c, 45);

        smart_log.temperature = (60u16 + 273).to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Warning);
        assert!(status.alerts[0].message.contains("High temperature"));

        smart_log.temperature = (70u16 + 273).to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Critical);
        assert!(status.alerts[0].message.contains("Critical temperature"));
    }

    #[test]
    fn test_check_drive_health_wear_alerts() {
        let thresholds = Thresholds {
            wear_warning: 20,
            wear_critical: 50,
            ..Default::default()
        };

        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.avail_spare = 100;

        smart_log.percent_used = 10;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert!(status.alerts.is_empty());
        assert_eq!(status.wear_percentage, 10);

        smart_log.percent_used = 25;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Warning);
        assert!(status.alerts[0].message.contains("High wear level"));

        smart_log.percent_used = 60;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Critical);
        assert!(status.alerts[0].message.contains("Critical wear level"));
    }

    #[test]
    fn test_check_drive_health_spare_alerts() {
        let thresholds = Thresholds {
            spare_warning: 50,
            ..Default::default()
        };

        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.temperature = 273u16.to_le_bytes();

        smart_log.avail_spare = 100;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert!(status.alerts.is_empty());

        smart_log.avail_spare = 40;
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Warning);
        assert!(status.alerts[0].message.contains("Low spare capacity"));
    }

    #[test]
    fn test_check_drive_health_error_alerts() {
        let thresholds = Thresholds {
            error_threshold: 100,
            ..Default::default()
        };

        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.avail_spare = 100;

        smart_log.num_err_log_entries = 50u128.to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert!(status.alerts.is_empty());

        smart_log.num_err_log_entries = 150u128.to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Warning);
        assert!(status.alerts[0].message.contains("High error count"));
    }

    #[test]
    fn test_check_drive_health_media_errors() {
        let thresholds = Thresholds::default();
        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.avail_spare = 100;

        smart_log.media_errors = 0u128.to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert!(status.alerts.is_empty());

        smart_log.media_errors = 5u128.to_le_bytes();
        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 1);
        assert_eq!(status.alerts[0].level, AlertLevel::Critical);
        assert!(status.alerts[0].message.contains("Media errors detected"));
    }

    #[test]
    fn test_check_drive_health_multiple_alerts() {
        let thresholds = Thresholds {
            temp_warning: 55,
            wear_warning: 20,
            spare_warning: 50,
            error_threshold: 100,
            ..Default::default()
        };

        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.temperature = (60u16 + 273).to_le_bytes();
        smart_log.percent_used = 25;
        smart_log.avail_spare = 40;
        smart_log.num_err_log_entries = 150u128.to_le_bytes();
        smart_log.media_errors = 1u128.to_le_bytes();

        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.alerts.len(), 5);

        let warning_count = status
            .alerts
            .iter()
            .filter(|a| a.level == AlertLevel::Warning)
            .count();
        let critical_count = status
            .alerts
            .iter()
            .filter(|a| a.level == AlertLevel::Critical)
            .count();
        assert_eq!(warning_count, 4);
        assert_eq!(critical_count, 1);
    }

    #[test]
    fn test_check_drive_health_with_identify() {
        let thresholds = Thresholds::default();
        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.avail_spare = 100;

        let status = check_drive_health("/dev/test", &smart_log, &identify, &thresholds);
        assert_eq!(status.info.model, "Test Model NVMe");
        assert_eq!(status.info.serial_number, "TEST123456");
    }

    #[test]
    fn test_data_unit_conversion() {
        let identify = create_test_identify();
        let mut smart_log = NvmeSmartLog::default();
        smart_log.avail_spare = 100;
        smart_log.data_units_written = 1953125u128.to_le_bytes();
        smart_log.data_units_read = 3906250u128.to_le_bytes();

        let status = check_drive_health("/dev/test", &smart_log, &identify, &Thresholds::default());

        assert!((status.data_written_tb - 1.0).abs() < 0.01);
        assert!((status.data_read_tb - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_find_nvme_devices_pattern_matching() {
        let test_cases = vec![
            ("nvme0n1", true),
            ("nvme0n2", true),
            ("nvme1n1", true),
            ("nvme10n1", true),
            ("nvme0", false),
            ("nvme1", false),
            ("nvme0n1p1", false),
            ("nvme0n1p2", false),
            ("sda", false),
            ("sdb1", false),
        ];

        for (name, should_match) in test_cases {
            let matches = if name.starts_with("nvme") && name.contains('n') && !name.contains('p') {
                let suffix = &name[4..];
                suffix.contains('n')
            } else {
                false
            };
            assert_eq!(
                matches, should_match,
                "Pattern matching failed for: {}",
                name
            );
        }
    }

    #[test]
    fn test_format_log_message() {
        let message = "Test message";
        let formatted = format_log_message(message);
        assert!(formatted.contains(message));
        assert!(formatted.contains(":"));
    }

    #[test]
    fn test_drive_status_serialization() {
        let status = DriveStatus {
            device: "/dev/nvme0n1".to_string(),
            info: DriveInfo {
                model: "Samsung SSD 970 EVO Plus".to_string(),
                serial_number: "S4EVNZ0N123456".to_string(),
            },
            temperature_c: 45,
            wear_percentage: 10,
            spare_percentage: 100,
            errors: 0,
            media_errors: 0,
            power_on_hours: 1000,
            data_written_tb: 5.5,
            data_read_tb: 10.2,
            alerts: vec![Alert {
                level: AlertLevel::Warning,
                message: "Test warning".to_string(),
            }],
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("nvme0n1"));
        assert!(json.contains("Samsung SSD 970 EVO Plus"));
        assert!(json.contains("S4EVNZ0N123456"));
        assert!(json.contains("45"));
        assert!(json.contains("Test warning"));
        assert!(json.contains("Warning"));
    }
}
