# azfilesauth 1.0-14

- Use a per-identity Kerberos credential cache (`krb5cc_<cache_uid>`) when the
  caller supplies a non-zero cache uid, so multiple identities can mount the same
  storage account on one node, each with its own credential cache.
- `azfilesauthmanager set`/`list` accept `--cache-uid <uid>`; `azfilesrefresh`
  renews every per-identity cache and matches mounts by endpoint and `cruid`.
- Per-identity caches are owned by the cache uid with mode `0600`; if ownership
  cannot be set, the operation returns an error.

**Upgrade note:** ABI change for direct C/ctypes callers of `libazfilesauth`:
`extern_smb_set_credential_oauth_token` and `extern_smb_list_credential` take a
trailing `unsigned int cache_uid` and callers must pass it (`0` keeps the
previous behavior). `azfilesauthmanager` CLI users, including
azurefile-csi-driver, are unaffected; the bundled CLI is updated in this
package and an older caller that omits `--cache-uid` gets cache uid 0.

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
