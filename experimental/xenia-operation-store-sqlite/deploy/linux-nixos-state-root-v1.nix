# Reference NixOS fragment for ADR-012 / linux-systemd-state-root-v1.
#
# This is intentionally not wired into a production module yet. It demonstrates the
# static service identity and systemd-managed state-root assumptions that must be
# qualified before the SQLite operation store can gate privileged effects.
#
# The hardening settings are additive recommendations and must be checked against the
# complete xenia-peer daemon's other filesystem/device/network requirements.

{ ... }:
{
  users.groups.xenia = { };
  users.users.xenia = {
    isSystemUser = true;
    group = "xenia";
  };

  systemd.services.xenia-peer.serviceConfig = {
    User = "xenia";
    Group = "xenia";

    StateDirectory = "xenia/operation-store";
    StateDirectoryMode = "0700";
    UMask = "0077";

    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
  };
}
