# ASCIA OS — published artifacts

This repository holds **only published artifacts**: the version manifest ASCIA appliances read, and
the signed RAUC update bundles they install. There is no source here, and there never should be —
that is the point of it being separate and separately auditable.

| Path | What it is |
|---|---|
| `stable.manifest.json` | The version manifest for the `stable` channel. Names one validated tuple per release: OS version, bundle URL + digest, the upstream versions it was validated against, and the add-on set it ships. |
| Release assets | `ascia_<board>-<version>.raucb` — the signed bundles themselves, attached to a `os-<version>` release. |

## This host is untrusted, by design

Appliances do not trust this repository, and nothing here needs protecting from readers.

RAUC verifies **every** bundle against the ASCIA root CA already on the appliance before installing
it. So a hostile or compromised host can do exactly two things:

1. **advertise nothing** — denial of service, which is tolerable; or
2. **offer an older, genuinely ASCIA-signed build** — refused by the appliance's monotonic version
   floor.

It cannot cause foreign code to install. The `sha256` in the manifest is an integrity check on the
*download* — truncation, corruption — not a security boundary.

This is the same shape as Windows Update and macOS Software Update: public bytes, signature
verified on the device, CDN untrusted.

## Moving elsewhere

Nothing about this location is baked into an appliance. The feed address is a per-appliance option
(`os_update_feed_url`), and each release names its own bundle URL *inside* the manifest — so
hosting can move by publishing a manifest at a new address and changing one option. The only
constraint is keeping the old address alive until every appliance has reconciled once after the
switch.
