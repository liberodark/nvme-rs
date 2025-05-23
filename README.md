# nvme-rs

A lightweight tool for monitoring NVMe drive health with email alerts.

[![Rust](https://github.com/liberodark/nvme-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/liberodark/nvme-rs/actions/workflows/rust.yml)

## Features

- Direct NVMe communication via ioctl (no external dependencies)
- Real-time health monitoring with configurable thresholds
- Email alerts for critical conditions
- Daemon mode for continuous monitoring
- JSON output support
- No dependency on nvme-cli

## Prerequisites

### Required System Tools

The tool requires root privileges to access NVMe devices via `/dev/nvmeX` interfaces.

### Installing Dependencies by Distribution

#### NixOS
```nix
environment.systemPackages = with pkgs; [
  nvme-rs
];
```

## Installation

### Via cargo
```bash
cargo install --path .
```

### Manual build
```bash
git clone https://github.com/liberodark/nvme-rs.git
cd nvme-rs
cargo build --release
sudo cp target/release/nvme-rs /usr/local/bin/
```

### Precompiled binaries
Precompiled binaries are available in the [Releases](https://github.com/liberodark/nvme-rs/releases) section.

## Usage

The tool requires root privileges:

### One-time check
```bash
# Basic check with default thresholds
sudo nvme-rs check

# Check with custom config
sudo nvme-rs check --config /etc/nvme-rs/config.toml

# JSON output
sudo nvme-rs check --format json
```

### Daemon mode
```bash
# Run as daemon (config required)
sudo nvme-rs daemon --config /etc/nvme-rs/config.toml
```

### Configuration

Create a `config.toml` file:

```toml
# Check interval in seconds (default: 3600 = 1 hour)
check_interval_secs = 3600

[thresholds]
temp_warning = 55
temp_critical = 65
wear_warning = 20
wear_critical = 50
spare_warning = 50
error_threshold = 100

# Email configuration (optional)
[email]
smtp_server = "smtp.gmail.com"
smtp_port = 587
smtp_username = "your-email@gmail.com"
smtp_password_file = "/run/secrets/smtp-password"
from = "NVMe Monitor <nvme-monitor@example.com>"
to = "admin@example.com"
use_tls = true
```

### Options

- `--config`: Path to configuration file
- `--format`: Output format (`text` or `json`)

## Systemd Service

Create `/etc/systemd/system/nvme-rs.service`:

```ini
[Unit]
Description=NVMe health monitoring
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nvme-rs daemon -c /etc/nvme-rs/config.toml
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable nvme-rs
sudo systemctl start nvme-rs
```

## NixOS Integration

A NixOS module is available to integrate nvme-rs directly into your configuration:

```nix
{ config, pkgs, ... }:

{
  imports = [
    ./path/to/module.nix
  ];

  services.nvme-rs = {
    enable = true;
    package = pkgs.nvme-rs;
    interval = 3600;

    thresholds = {
      temperatureWarning = 60;
      temperatureCritical = 70;
      wearWarning = 25;
      wearCritical = 60;
      errorThreshold = 150;
      spareWarning = 40;
    };

    email = {
      enable = true;
      from = "your-email@gmail.com";
      to = "admin@example.com";
      username = "your-email@gmail.com";
      passwordFile = "/run/secrets/smtp-password";
      smtp = {
        server = "smtp.gmail.com";
        port = 587;
        useTLS = true;
      };
    };
  };
}
```

See the [module.nix](./module.nix) file for more details.

## Monitored Metrics

- **Temperature**: Warning/critical thresholds in Celsius
- **Wear Level**: SSD usage percentage
- **Available Spare**: Remaining spare blocks
- **Error Count**: Number of errors logged
- **Media Errors**: Critical physical errors
- **Power On Hours**: Total operational time
- **Data Written/Read**: Total TB transferred

## Example Output

```
=== /dev/nvme0n1 ===
Temperature: 45°C
Wear Level: 0%
Available Spare: 100%
Error Count: 0
Media Errors: 0
Power On Hours: 4132
Data Written: 71.37 TB
Data Read: 79.51 TB
Status: OK

=== /dev/nvme1n1 ===
Temperature: 43°C
Wear Level: 10%
Available Spare: 100%
Error Count: 4679
Media Errors: 0
Power On Hours: 4241
Data Written: 248.29 TB
Data Read: 306.02 TB
Alerts:
  [WARNING] High error count: 4679 (threshold: 100)
```

## Troubleshooting

### Permission Denied
The tool must be run with root privileges. Use `sudo` or run as root.

### No NVMe Devices Found
- Verify NVMe devices exist: `ls /dev/nvme*`
- Check if NVMe kernel module is loaded: `lsmod | grep nvme`
- Ensure the devices are namespace devices (e.g., `/dev/nvme0n1`, not `/dev/nvme0`)

### Email Alerts Not Working
- Verify SMTP credentials and server settings
- For Gmail: Use app-specific password, not your regular password
- Check firewall rules for SMTP port (usually 587 or 465)
- Test with direct password first, then switch to password file

### High Error Count
Some NVMe drives report non-critical errors. Adjust `error_threshold` in config if needed.
