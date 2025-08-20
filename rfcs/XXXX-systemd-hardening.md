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

## Core Architecture

The design introduces a new `systemd.services.<name>.harden` option set that provides both simple presets and granular control over systemd security features.

### Basic Interface

```nix
systemd.services.<name>.harden = {
  enable = mkOption {
    type = types.bool;
    default = false;
    description = "Enable basic service hardening";
  };

  profile = mkOption {
    type = types.enum [ "strict" "moderate" "minimal" ];
    default = "moderate";
    description = "Hardening profile to apply";
  };
};
```

### Hardening Profiles

The framework defines three hardening profiles with increasing levels of restriction:

#### Strict Profile

Maximum security with potential compatibility trade-offs:

```nix
strict = {
  # Process isolation
  PrivateUsers = true;
  PrivateDevices = true;
  PrivateTmp = true;
  PrivateNetwork = true;  # Most restrictive
  ProtectHome = true;
  ProtectProc = "invisible";
  ProcSubset = "pid";

  # System protection
  ProtectSystem = "strict";
  ProtectKernelTunables = true;
  ProtectKernelModules = true;
  ProtectKernelLogs = true;
  ProtectControlGroups = true;
  ProtectClock = true;
  ProtectHostname = true;

  # Capabilities and privileges
  NoNewPrivileges = true;
  CapabilityBoundingSet = [ "" ];  # No capabilities
  LockPersonality = true;
  RemoveIPC = true;
  RestrictSUIDSGID = true;

  # System calls
  SystemCallFilter = [ "@system-service" "~@privileged" ];
  SystemCallArchitectures = "native";
  SystemCallErrorNumber = "EPERM";

  # Network restrictions
  RestrictAddressFamilies = [ "AF_UNIX" ];  # Local only
  IPAddressDeny = [ "any" ];

  # Execution restrictions
  NoExecPaths = [ "/" ];
  ExecPaths = [ "/nix/store" ];
  MemoryDenyWriteExecute = true;

  # Namespace restrictions
  RestrictNamespaces = true;
  RestrictRealtime = true;

  # File system
  UMask = "0077";
}
```

#### Moderate Profile

Balanced security and compatibility:

```nix
moderate = {
  # Basic isolation
  PrivateDevices = true;
  PrivateTmp = true;
  ProtectHome = true;
  ProtectProc = "invisible";

  # System protection
  ProtectSystem = "full";
  ProtectKernelTunables = true;
  ProtectKernelModules = true;
  ProtectKernelLogs = true;
  ProtectControlGroups = true;
  ProtectClock = true;

  # Basic privilege restrictions
  NoNewPrivileges = true;
  LockPersonality = true;
  RestrictSUIDSGID = true;

  # System calls
  SystemCallFilter = [ "@system-service" ];
  SystemCallArchitectures = "native";

  # Network (less restrictive)
  RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];

  # Namespace restrictions
  RestrictNamespaces = true;
  RestrictRealtime = true;

  # File permissions
  UMask = "0027";
}
```

#### Minimal Profile

Light hardening with maximum compatibility:

```nix
minimal = {
  # Basic protections
  PrivateTmp = true;
  ProtectKernelTunables = true;
  ProtectKernelModules = true;
  ProtectControlGroups = true;

  # Basic restrictions
  NoNewPrivileges = true;
  RestrictSUIDSGID = true;
  RestrictRealtime = true;

  # System calls
  SystemCallArchitectures = "native";
}
```

**Note on Profile Evolution**: The specific settings within each hardening profile (strict, moderate, and minimal) are not set in stone. These profiles are designed to evolve and be refined during the implementation and rollout phases based on real-world testing, community feedback, and compatibility requirements. The profiles represent starting points that balance security and usability, but their contents may be adjusted to better serve the NixOS ecosystem as we gain experience with their practical application.

### Fine-Grained Control

For services requiring specific permissions:

```nix
systemd.services.<name>.harden = {
  enable = true;
  profile = "strict";

  # Override specific restrictions
  allowNetwork = true;           # Sets PrivateNetwork = false, appropriate RestrictAddressFamilies
  allowHome = true;              # Sets ProtectHome = false
  allowDevices = [ "/dev/tty" ]; # Sets DeviceAllow for specific devices

  # Additional capabilities when needed
  capabilities = [ "CAP_NET_BIND_SERVICE" ];

  # Custom paths
  execPaths = [ "/usr/bin" ];                # Allow execution from additional paths
  readWritePaths = [ "/var/lib/myservice" ]; # Additional writable directories

  # Service-specific syscalls
  additionalSyscalls = [ "@network-io" ];

  # Custom address families
  addressFamilies = [ "AF_NETLINK" ];
};
```

### Implementation Strategy

The implementation extends the existing `systemd.services` option with a new `harden` submodule:

```nix
{ lib, ... }:
let
  inherit (lib) types;

  # Hardening profile definitions
  hardeningProfiles = {
    strict = { /* comprehensive hardening settings */ };
    moderate = { /* balanced hardening settings */ };
    minimal = { /* basic hardening settings */ };
  };

in {
  options.systemd.services = lib.mkOption {
    type = types.attrsOf (types.submodule ({ name, config, ... }: {
      options.harden = {
        enable = lib.mkOption {
          type = types.bool;
          default = false;
          description = "Enable systemd service hardening";
        };

        profile = lib.mkOption {
          type = types.enum [ "strict" "moderate" "minimal" ];
          default = "moderate";
          description = "Hardening profile to apply";
        };

        allowNetwork = lib.mkOption {
          type = types.bool;
          default = false;
          description = "Allow network access by disabling PrivateNetwork";
        };

        # Other hardening options
      };

      config.serviceConfig = lib.optionalAttrs config.harden.enable (
        let
          hardenCfg = config.harden;
          baseProfile = hardeningProfiles.${hardenCfg.profile};

          # Apply conditional overrides based on harden options
          overrides = /* logic to override profile settings based on allow* options */;
        in
        # Merge base profile with conditional overrides
        lib.mapAttrs (name: value: lib.mkDefault value) baseProfile // overrides
      );
    }));
  };
}
```

### Migration Path

- Phase 1: Framework Introduction

  - Add hardening framework to systemd module
  - No services enabled by default
  - Documentation, tests, and examples provided

- Phase 2: Existing Hardened Services

  - Identify existing services with custom hardening
  - Migrate them to use the new framework

- Phase 3: Broader Adoption

  - Enable hardening for additional services
  - Community contributions for service-specific configurations

- Phase 4: Default Hardening (Long-term)

  - Consider enabling minimal hardening by default for new services
  - Opt-out rather than opt-in for basic protections

During Phases 1 and 2, the hardening profile definitions (strict, moderate, and minimal) will be actively refined based on real-world testing, compatibility feedback, and community input.

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
      harden = {
        enable = true;
        profile = "strict";
        allowNetwork = true;
      };
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

Enable hardening for a simple service:

```nix
systemd.services.myapp = {
  enable = true;
  description = "My Application";
  serviceConfig.ExecStart = "${pkgs.myapp}/bin/myapp";

  harden = {
    enable = true;
    profile = "moderate";
  };
};
```

### Network Service

Configure a web service that needs network access:

```nix
systemd.services.webapp = {
  enable = true;
  description = "Web Application";
  serviceConfig.ExecStart = "${pkgs.webapp}/bin/webapp";

  harden = {
    enable = true;
    profile = "strict";
    allowNetwork = true;
    capabilities = [ "CAP_NET_BIND_SERVICE" ];  # Bind to port 80/443
    readWritePaths = [ "/var/lib/webapp" ];
  };
};
```

### Database Service

The existing PostgreSQL service configuration may look like this when migrated to the new hardening framework:

```nix
systemd.services.postgresql = {
  harden = {
    enable = true;
    profile = "strict";
    allowNetwork = true;
  };
};
```

### Legacy Service Migration

For services that need extensive filesystem access:

```nix
systemd.services.legacy-daemon = {
  description = "Legacy System Daemon";
  serviceConfig.ExecStart = "${pkgs.legacy-daemon}/bin/daemon";

  harden = {
    enable = true;
    profile = "minimal";  # Start with light restrictions
    allowHome = true;     # Needs access to user directories
    allowDevices = [ "/dev/tty" "/dev/pts" ];
    execPaths = [ "/usr/bin" "/usr/local/bin" ];
  };
};
```

### Fine-Tuned Service

Advanced configuration for a security-critical service:

```nix
systemd.services.crypto-service = {
  enable = true;
  description = "Cryptographic Service";
  serviceConfig.ExecStart = "${pkgs.crypto-service}/bin/crypto-service";

  harden = {
    enable = true;
    profile = "strict";

    # Only allow specific system calls
    systemCallFilter = [
      "@system-service"
      "~@privileged"
      "~@resources"
      "~@obsolete"
    ];

    # Minimal capabilities
    capabilities = [ ];

    # Specific network restrictions
    addressFamilies = [ "AF_UNIX" ];
  };
};
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

- **Default Behavior**: Should hardening be enabled by default for new services?
- **Profile Evolution**: How should hardening profiles evolve over time without breaking existing configurations?
- **Service Dependencies**: How to handle services that depend on each other with different hardening requirements?
- **User Services**: Should this framework extend to user-level systemd services?
- **Debugging**: What tools and techniques should be provided for debugging hardening-related issues?

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
