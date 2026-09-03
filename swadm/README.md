# SW(itch) ADM(in)

This is the management CLI for Oxide's rack switch.

## Testing

swadm is used across scripts and documentation. Breaking changes
should be documented and intentional.

This is definitionally a string-typed interface, so regressions are
easily missed. The integration tests module has infra for testing
commands, and adding a test before making swadm changes might
help prevent drift.

These tests are run in Linux CI but currently ignored in Illumos CI.
Illumos CI is blocked by tofino simulator support: https://github.com/oxidecomputer/tofino-sde/issues/21

