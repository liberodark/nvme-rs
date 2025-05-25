{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.nvme-rs;

  configFile = pkgs.writeText "nvme-rs.toml" ''
    check_interval_secs = ${toString cfg.interval}

    [thresholds]
    temp_warning = ${toString cfg.thresholds.temperatureWarning}
    temp_critical = ${toString cfg.thresholds.temperatureCritical}
    wear_warning = ${toString cfg.thresholds.wearWarning}
    wear_critical = ${toString cfg.thresholds.wearCritical}
    spare_warning = ${toString cfg.thresholds.spareWarning}
    error_threshold = ${toString cfg.thresholds.errorThreshold}

    ${lib.optionalString (cfg.email.enable) ''
      [email]
      smtp_server = "${cfg.email.smtp.server}"
      smtp_port = ${toString cfg.email.smtp.port}
      smtp_username = "${cfg.email.username}"
      smtp_password_file = "${cfg.email.passwordFile}"
      from = "${cfg.email.from}"
      to = "${cfg.email.to}"
      use_tls = ${lib.boolToString cfg.email.smtp.useTLS}
    ''}
  '';

in
{
  options.services.nvme-rs = {
    enable = lib.mkEnableOption "NVMe monitoring service";

    package = lib.mkPackageOption pkgs "nvme-rs" { };

    interval = lib.mkOption {
      type = lib.types.int;
      default = 3600;
      description = "Check interval in seconds";
      example = 1800;
    };

    thresholds = {
      temperatureWarning = lib.mkOption {
        type = lib.types.int;
        default = 55;
        description = "Temperature warning threshold (°C)";
      };

      temperatureCritical = lib.mkOption {
        type = lib.types.int;
        default = 65;
        description = "Temperature critical threshold (°C)";
      };

      wearWarning = lib.mkOption {
        type = lib.types.int;
        default = 20;
        description = "Wear warning threshold (%)";
      };

      wearCritical = lib.mkOption {
        type = lib.types.int;
        default = 50;
        description = "Wear critical threshold (%)";
      };

      errorThreshold = lib.mkOption {
        type = lib.types.int;
        default = 100;
        description = "Error count warning threshold";
      };

      spareWarning = lib.mkOption {
        type = lib.types.int;
        default = 50;
        description = "Available spare warning threshold (%)";
      };
    };

    email = {
      enable = lib.mkEnableOption "email alerts";

      from = lib.mkOption {
        type = lib.types.str;
        description = "Sender email address";
        example = "nvme-monitor@example.com";
      };

      to = lib.mkOption {
        type = lib.types.str;
        description = "Recipient email address";
        example = "admin@example.com";
      };

      username = lib.mkOption {
        type = lib.types.str;
        description = "SMTP username";
        example = "your-email@gmail.com";
      };

      passwordFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = "File containing SMTP password";
        example = "/run/secrets/smtp-password";
      };

      smtp = {
        server = lib.mkOption {
          type = lib.types.str;
          default = "smtp.gmail.com";
          description = "SMTP server";
        };

        port = lib.mkOption {
          type = lib.types.int;
          default = 587;
          description = "SMTP port";
        };

        useTLS = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = "Use TLS for SMTP connection";
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {

    systemd.services.nvme-rs = {
      description = "NVMe health monitoring service";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          "${lib.getExe cfg.package}"
          "daemon"
          "--config"
          "${configFile}"
        ];

        DynamicUser = true;
        SupplementaryGroups = [ "disk" ];
        CapabilityBoundingSet = [ "CAP_SYS_ADMIN" ];
        AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
        LimitCORE = 0;
        LimitNOFILE = 65535;
        LockPersonality = true;
        MemorySwapMax = 0;
        MemoryZSwapMax = 0;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        Restart = "on-failure";
        RestartSec = "10s";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "@resources"
          "~@privileged"
        ];
        NoNewPrivileges = true;
        UMask = "0077";
      };
    };

    environment.systemPackages = [ cfg.package ];
  };
}
