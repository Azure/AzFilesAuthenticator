# azfilesauth 1.0-13

- Validate Kerberos FILE credential-cache ownership, permissions, and file type
  before use.
- Create missing credential-cache files exclusively with mode `0600`.
- Add native credential-cache regression tests.

**Upgrade note:** Existing FILE caches must be regular files owned by the
configured user with mode `0600`; otherwise, `set` and `clear` refuse them.

# azfilesauth 1.0-12

- Use the Azure Identity SDK for managed and workload identity authentication.
- Support Azure Identity environment settings through YAML configuration.
- Expand unit, package, and managed-identity lifecycle tests.

**Upgrade note:** Requires Python 3.8+, `azure-identity`, `azure-core`, PyYAML,
and libyaml.
