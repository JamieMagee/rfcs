---
feature: systemd-service-hardening
start-date: 2025-08-19
author: Jamie Magee
co-authors: (find a buddy later to help out with the RFC)
shepherd-team: (names, to be nominated and accepted by RFC steering committee)
shepherd-leader: (name to be appointed by RFC steering committee)
related-issues: (will contain links to implementation PRs)
---

## Summary
[summary]: #summary

This RFC proposes to add comprehensive systemd service hardening capabilities to NixOS through a standardized framework. The goal is to provide simple yet powerful options for securing systemd services by applying the principle of least privilege, while maintaining backward compatibility and ease of use.

## Motivation
[motivation]: #motivation

Currently, most systemd services in NixOS run with excessive privileges that they do not need for normal operation. Analysis with `systemd-analyze security` reveals that many critical services score as "UNSAFE". This poses significant security risks including larger attack surfaces, easier privilege escalation, and unnecessary data exposure.

The principle of least privilege dictates that each service should have access only to the resources it strictly requires. While systemd provides extensive sandboxing capabilities, they are complex and time-consuming to configure correctly for each service.

Standardizing on a systemd hardening framework will enable:

- Automatically securing new services with minimal configuration
- Migrating existing services to secure configurations incrementally
- Providing consistent security patterns across the NixOS ecosystem
- Enabling security-conscious deployments without expert knowledge

## Detailed design
[design]: #detailed-design

This RFC follows the principles established in [RFC 42 (config-option)][rfc-42] by providing a `settings` option that uses native systemd configuration names while adding a composable preset system for ease of use.

### Core Architecture

The design introduces a new `systemd.services.<name>.hardening` option set that provides composable hardening presets and RFC 42-style configuration options for systemd security features.

### Benefits of This Approach

- **Maintainability**: No custom abstractions to maintain - direct systemd compatibility
- **Composability**: Multiple presets can be layered together
- **Flexibility**: Any systemd option can be overridden using native names
- **Discoverability**: Users can reference systemd documentation directly
- **Future-proof**: Works with new systemd features automatically
- **Simplicity**: Streamlined implementation using standard library functions
- **Type safety**: Uses `types.attrsOf unitOption` for proper systemd option handling and merging

### Basic Interface

```nix
systemd.services.<name>.hardening = {
  enable = mkOption {
    type = types.bool;
    default = false;
    description = "Enable systemd service hardening";
  };

  presets = mkOption {
    type = types.listOf types.attrs;
    default = [];
    description = ''
      List of hardening presets to apply. Presets are applied in order,
      with later presets overriding earlier ones. Each preset must be
      an attribute set of systemd configuration options.
    '';
  };

  settings = mkOption {
    type = types.attrsOf systemdUtils.unitOptions.unitOption;
    default = {};
    description = ''
      Systemd service hardening configuration using native systemd option names.
      These settings override any preset configuration.
      See systemd.exec(5) for available options.
    '';
  };
};
```

### Hardening Presets

The framework provides a collection of composable hardening presets that can be mixed and matched. Each preset focuses on a specific aspect of security, allowing users to build custom hardening configurations.

#### Base Security Presets

```nix
# Built into systemd-hardening.nix module
{
  # Fundamental isolation preset - recommended for all services
  isolation = {
    PrivateTmp = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    NoNewPrivileges = true;
    RestrictSUIDSGID = true;
    RestrictRealtime = true;
    SystemCallArchitectures = "native";
  };

  # Process and user isolation
  processIsolation = {
    PrivateUsers = true;
    PrivateDevices = true;
    ProtectHome = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";
    LockPersonality = true;
    RemoveIPC = true;
  };

  # Comprehensive filesystem protection
  filesystemProtection = {
    ProtectSystem = "strict";
    NoExecPaths = [ "/" ];
    ExecPaths = [ "/nix/store" ];
    UMask = "0077";
    MemoryDenyWriteExecute = true;
  };

  # Network isolation (default: no network access)
  networkIsolation = {
    PrivateNetwork = true;
    RestrictAddressFamilies = [ "AF_UNIX" ];
    IPAddressDeny = [ "any" ];
  };

  # System protection against kernel modifications
  systemProtection = {
    ProtectKernelLogs = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
  };

  # Strict system call filtering
  systemCallRestriction = {
    SystemCallFilter = [ "@system-service" "~@privileged" ];
    SystemCallErrorNumber = "EPERM";
  };

  # Remove all capabilities by default
  noCapabilities = {
    CapabilityBoundingSet = [ "" ];
  };
}
```

#### Common Preset Combinations

```nix
# Predefined combinations for ease of use
{
  # Maximum security - all restrictions enabled
  strict = lib.mergeAttrsList [
    hardeningPresets.isolation
    hardeningPresets.processIsolation
    hardeningPresets.filesystemProtection
    hardeningPresets.networkIsolation
    hardeningPresets.systemProtection
    hardeningPresets.systemCallRestriction
    hardeningPresets.noCapabilities
  ];

  # Balanced security and compatibility
  moderate = lib.mergeAttrsList [
    hardeningPresets.isolation
    hardeningPresets.processIsolation
    hardeningPresets.systemProtection
    {
      # More permissive filesystem access
      ProtectSystem = "full";
      UMask = "0027";
      # Allow basic networking by default
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      # Basic system call filtering
      SystemCallFilter = [ "@system-service" ];
    }
  ];

  # Minimal hardening for maximum compatibility
  minimal = hardeningPresets.isolation;
}
```

#### Functional Presets

Presets can also be functions that accept parameters for customization:

```nix
{
  # Allow specific network access
  allowNetwork = {
    addressFamilies ? [ "AF_UNIX" "AF_INET" "AF_INET6" ],
    bindService ? false
  }: {
    PrivateNetwork = false;
    RestrictAddressFamilies = addressFamilies;
    IPAddressDeny = null;
  } // lib.optionalAttrs bindService {
    CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
  };

  # Allow access to specific devices
  allowDevices = { devices }: {
    PrivateDevices = false;
    DeviceAllow = devices;
  };

  # Allow access to specific paths
  allowPaths = { readWrite ? [], readOnly ? [], exec ? [] }: {
    ReadWritePaths = readWrite;
    BindReadOnlyPaths = readOnly;
    ExecPaths = [ "/nix/store" ] ++ exec;
  };

  # Allow specific capabilities
  allowCapabilities = { capabilities }: {
    CapabilityBoundingSet = capabilities;
  };

  # Allow additional system calls
  allowSyscalls = { syscalls }: {
    SystemCallFilter = [ "@system-service" ] ++ syscalls;
  };
}
```

**Note on Preset Evolution**: The specific presets and their contents are designed to evolve based on real-world testing, community feedback, and compatibility requirements. New presets can be added, and existing ones refined as we gain experience with their practical application.

### Composable Configuration

The framework allows combining presets with RFC 42-style overrides:

```nix
systemd.services.<name>.hardening = {
  enable = true;

  # Apply base security with network access
  presets = [
    hardeningPresets.strict
    (hardeningPresets.allowNetwork {
      addressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
      bindService = true;
    })
    (hardeningPresets.allowPaths {
      readWrite = [ "/var/lib/myservice" ];
      readOnly = [ "/etc/ssl" ];
    })
  ];

  # Override specific settings using systemd option names
  settings = {
    # Fine-tune system call filtering
    SystemCallFilter = [
      "@system-service"
      "@network-io"
      "~@privileged"
      "~@resources"
    ];

    # Allow specific capabilities beyond what presets provide
    CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_SETUID" ];

    # Custom file permissions
    UMask = "0022";

    # Service-specific device access
    DeviceAllow = [ "/dev/urandom r" ];
  };
};
```

### Implementation Strategy

The implementation extends the existing `systemd.services` option with a new `hardening` submodule that follows RFC 42 patterns:

```nix
{ lib, systemdUtils, ... }:
let
  inherit (lib) types;
  inherit (systemdUtils.lib) unitOption;

  # Hardening preset library
  hardeningPresets = {
    # Base presets (isolation, processIsolation, etc.)
    # Functional presets (allowNetwork, allowPaths, etc.)
    # Preset combinations (strict, moderate, minimal)
  };

in {
  # Export hardening presets for use in service configurations
  _module.args.hardeningPresets = hardeningPresets;

  options.systemd.services = lib.mkOption {
    type = types.attrsOf (types.submodule ({ name, config, ... }: {
      options.hardening = {
        enable = lib.mkOption {
          type = types.bool;
          default = false;
          description = "Enable systemd service hardening";
        };

        presets = lib.mkOption {
          type = types.listOf types.attrs;
          default = [];
          description = ''
            List of hardening presets to apply. Presets are applied in order,
            with later presets overriding earlier ones.
          '';
        };

        settings = lib.mkOption {
          type = types.attrsOf unitOption;
          default = {};
          description = ''
            Systemd service hardening configuration using native systemd option names.
            These settings override any preset configuration.
            See systemd.exec(5) for available options.
          '';
        };
      };

      config.serviceConfig = lib.optionalAttrs config.hardening.enable (
        let
          hardeningCfg = config.hardening;

          # Merge all presets and custom settings
          finalSettings = lib.filterAttrs (n: v: v != null) (
            lib.mergeAttrsList (hardeningCfg.presets ++ [ hardeningCfg.settings ])
          );
        in
        lib.mapAttrs (name: value: lib.mkDefault value) finalSettings
      );
    }));
  };
}
```

### Migration Path

- Phase 1: Framework Introduction

  - Add hardening framework to systemd module with preset library
  - No services enabled by default
  - Documentation, tests, and examples provided
  - RFC 42-style `settings` option for full systemd compatibility

- Phase 2: Preset Development and Refinement

  - Develop and test composable hardening presets
  - Create functional presets for common use cases
  - Gather community feedback on preset effectiveness and usability
  - Refine preset compositions based on real-world usage

- Phase 3: Existing Service Migration

  - Identify existing services with custom hardening
  - Migrate them to use appropriate preset combinations
  - Create service-specific presets where beneficial

- Phase 4: Broader Adoption

  - Enable hardening for additional services using preset combinations
  - Community contributions for new presets and preset refinements
  - Documentation of best practices and common patterns

- Phase 5: Default Hardening (Long-term)

  - Consider enabling basic hardening presets by default for new services
  - Opt-out rather than opt-in for fundamental protections

During all phases, the preset library and RFC 42-style settings will be actively refined based on real-world testing, compatibility feedback, and community input. The composable nature allows for incremental improvements without breaking existing configurations.

### Testing and Validation

Each hardening profile will be validated through integration tests, which test service functionality with hardening enabled. The tests will ensure that:

- Services start correctly with the applied hardening
- Security features are correctly applied (e.g., using `systemd-analyze security`)
- Service functionality remains intact (e.g., database connections, web service responses)

### Example Test Case

```nix
makeTest {
  name = "systemd-hardening-postgresql";

  machine = {
    services.postgresql = {
      enable = true;
    };

    systemd.services.postgresql.hardening = {
      enable = true;
      presets = [
        config.systemd.hardeningPresets.strict
        (config.systemd.hardeningPresets.allowNetwork { addressFamilies = [ "AF_UNIX" "AF_INET" ]; })
      ];
    };
  };

  testScript = ''
    # Test service starts correctly
    machine.wait_for_unit("postgresql.service")
    machine.succeed("systemctl status postgresql.service")

    # Test hardening is applied
    output = machine.succeed("systemd-analyze security postgresql.service")
    # Verify specific hardening measures are in place

    # Test functionality still works
    machine.succeed("sudo -u postgres createdb test")
    machine.succeed("sudo -u postgres psql -c 'SELECT 1;' test")
  '';
}
```

## Examples and Interactions
[examples-and-interactions]: #examples-and-interactions

### Basic Usage

Enable hardening for a simple service using predefined presets:

```nix
{ hardeningPresets, ... }:
{
  systemd.services.myapp = {
    enable = true;
    description = "My Application";
    serviceConfig.ExecStart = "${pkgs.myapp}/bin/myapp";

    hardening = {
      enable = true;
      presets = [ hardeningPresets.moderate ];
    };
  };
}
```

### Network Service

Configure a web service that needs network access and privilege binding:

```nix
{ hardeningPresets, ... }:
{
  systemd.services.webapp = {
    enable = true;
    description = "Web Application";
    serviceConfig.ExecStart = "${pkgs.webapp}/bin/webapp";

    hardening = {
      enable = true;
      presets = [
        hardeningPresets.strict
        (hardeningPresets.allowNetwork { bindService = true; })
        (hardeningPresets.allowPaths {
          readWrite = [ "/var/lib/webapp" ];
          readOnly = [ "/etc/ssl/certs" ];
        })
      ];
    };
  };
}
```

### Legacy Service Migration

For services that need extensive permissions, start minimal and add as needed:

```nix
{ hardeningPresets, ... }:
{
  systemd.services.legacy-daemon = {
    description = "Legacy System Daemon";
    serviceConfig.ExecStart = "${pkgs.legacy-daemon}/bin/daemon";

    hardening = {
      enable = true;
      presets = [ hardeningPresets.minimal ];

      settings = {
        # Legacy service needs broad access - override as needed
        ProtectHome = false;
        ProtectSystem = false;
        PrivateDevices = false;
      };
    };
  };
}
```

### Custom Preset Definition

Create reusable custom presets for module-specific requirements:

```nix
# In a custom module or configuration
{ hardeningPresets, ... }:
let
  myModulePresets = {
    webService = {
      # Common settings for all web services
      PrivateNetwork = false;
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      SystemCallFilter = [ "@system-service" "@network-io" ];
    };

    allowLogging = {
      # Allow access to logging infrastructure
      BindReadOnlyPaths = [ "/dev/log" ];
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
    };
  };
in {
  systemd.services.mywebapp = {
    hardening = {
      enable = true;
      presets = [
        hardeningPresets.isolation
        hardeningPresets.processIsolation
        myModulePresets.webService
        myModulePresets.allowLogging
      ];
    };
  };
}
```

### Fine-Tuned Service

Security-critical service with minimal attack surface:

```nix
{ hardeningPresets, ... }:
{
  systemd.services.crypto-service = {
    enable = true;
    description = "Cryptographic Service";
    serviceConfig.ExecStart = "${pkgs.crypto-service}/bin/crypto-service";

    hardening = {
      enable = true;
      presets = [
        hardeningPresets.isolation
        hardeningPresets.processIsolation
        hardeningPresets.filesystemProtection
        hardeningPresets.networkIsolation
        hardeningPresets.systemProtection
        hardeningPresets.noCapabilities
      ];

      settings = {
        # Only allow specific system calls needed for cryptography
        SystemCallFilter = [
          "@system-service"
          "getrandom"
          "~@privileged"
          "~@resources"
          "~@obsolete"
          "~@debug"
          "~@mount"
          "~@cpu-emulation"
          "~@raw-io"
          "~@reboot"
          "~@swap"
          "~@module"
        ];

        # Prevent any capability inheritance
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];

        # Maximum filesystem isolation
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;

        # Only allow access to specific paths
        ReadWritePaths = [ "/var/lib/crypto-service" ];
        InaccessiblePaths = [ "/home" "/root" "/opt" ];
      };
    };
  };
}
```

## Drawbacks
[drawbacks]: #drawbacks

1. **Complexity**: Adds another layer of configuration options
1. **Compatibility Risk**: Hardening may break services in unexpected ways
1. **Performance Impact**: Some restrictions may have performance overhead
1. **Maintenance Burden**: Requires ongoing testing and updates as systemd evolves and packages are updated

## Alternatives
[alternatives]: #alternatives

### What is the impact of not doing this?

Without a standardized hardening framework, NixOS will continue to have:

- Inconsistent security postures across services
- High barrier to entry for implementing service security
- Ongoing maintenance burden for individually hardened services
- Security vulnerabilities in services that lack proper restrictions

### Alternative Design: Manual Per-Service Hardening

Continue current approach of manually hardening each service individually.

**Pros**:

- Fine-grained control
- No new abstractions

**Cons**:

- Inconsistent implementation
- High maintenance burden
- Knowledge barrier for contributors

### Alternative Design: Global Hardening Defaults

Apply hardening globally to all services by default.

**Pros**:

- Comprehensive security improvement
- No per-service configuration needed

**Cons**:

- High risk of breaking existing deployments
- Difficult to debug issues
- Less flexibility

### Alternative Design: Systemd Upstream Integration

Work with systemd upstream to provide better hardening defaults.

**Pros**:

- Benefits all distributions
- Upstream maintenance

**Cons**:

- Long development cycle
- May not address NixOS-specific needs
- Still requires NixOS integration work

### Alternative Design: External Security Tools

Use tools like AppArmor, SELinux, or seccomp-bpf for service restriction.

**Pros**:

- Mature security frameworks
- Fine-grained control

**Cons**:

- Additional complexity
- Platform-specific
- Different security model

## Prior art
[prior-art]: #prior-art

### RFC 42 - Config Option Pattern

This RFC builds upon [RFC 42 (config-option)][rfc-42], which established the pattern of using structural `settings` options instead of stringly-typed `extraConfig` options. Our design follows RFC 42's guidance by:

- Providing a `settings` option that accepts structured Nix values
- Using native systemd option names rather than custom abstractions
- Enabling proper merging and inspection of configuration
- Supporting preset combinations as recommended for balancing option count

### Existing Implementations

- **Current NixOS Services**: Many services like PostgreSQL, Murmur, and Nginx already implement custom hardening
- **Security Profiles**: Some distributions provide security-focused service configurations

### Related Projects

- [**Systemd Hardening Helper (SHH)**][systemd-hardening-helper]: Tool for analyzing and suggesting systemd hardening options

### Systemd Documentation

- [**systemd.exec**][systemd-exec]: Documentation on service execution options
- [**systemd.directives**][systemd-directives]: Documentation on unit file directives
- [**systemd-analyze**][systemd-analyze]: Provides security scoring and recommendations

### Previous NixOS Discussions

- [Hardening systemd services - Development / Security - NixOS Discourse][nixos-discourse-hardening]
- [Pre-RFC: Systemd Hardening - Development / RFCs - NixOS Discourse][nixos-discourse-pre-rfc]
- [ft: add systemd hardening helpers by hauleth · Pull Request #288418 · NixOS/nixpkgs][nixos-pr-hardening]
- [Tracking: systemd hardening in NixOS · Issue #377827 · NixOS/nixpkgs][nixos-issue-hardening]

## Unresolved questions
[unresolved]: #unresolved-questions

- **Default Behavior**: Should basic hardening presets be enabled by default for new services?
- **Preset Evolution**: How should hardening presets evolve over time without breaking existing configurations?
- **Preset Discovery**: What's the best way to help users discover available presets and their purposes?
- **Service Dependencies**: How to handle services that depend on each other with different hardening requirements?
- **User Services**: Should this framework extend to user-level systemd services?
- **Debugging**: What tools and techniques should be provided for debugging hardening-related issues?
- **Preset Organization**: How should presets be organized and categorized as the library grows?

## Future work
[future]: #future-work

- **Dynamic Profiling**: Integration with tools like SHH for automatic hardening profile generation
- **Security Monitoring**: Integration with monitoring systems to detect hardening violations

[systemd-analyze]: https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html
[systemd-directives]: https://www.freedesktop.org/software/systemd/man/latest/systemd.directives.html
[systemd-exec]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[systemd-hardening-helper]: https://github.com/synacktiv/shh
[nixos-discourse-hardening]: https://discourse.nixos.org/t/hardening-systemd-services/17147
[nixos-discourse-pre-rfc]: https://discourse.nixos.org/t/pre-rfc-systemd-hardening/39772
[nixos-pr-hardening]: https://github.com/NixOS/nixpkgs/pull/288418
[nixos-issue-hardening]: https://github.com/NixOS/nixpkgs/issues/377827
[rfc-42]: https://github.com/NixOS/rfcs/blob/master/rfcs/0042-config-option.md
