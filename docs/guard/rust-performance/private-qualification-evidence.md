# Recoverable private qualification evidence

Qualification retains the original synthetic observation bytes for each CI attempt in an encrypted archive, alongside the existing public aggregates. A file called “private” or containing only numeric samples is still plaintext until encrypted. Only `qualification-evidence/private_samples` is an input to this archive; source trees, installed environments, keys, personal payloads and cloud metadata are outside its inventory.

The workflow runs the archive step after sampling, including when an earlier build or qualification step failed. It establishes the locked project dependencies with `uv sync --frozen --no-dev --no-install-project`, followed by `uv run --frozen --no-sync`; it does not assume that either installed wheel environment exists. This setup and encryption are outside every timed workload. An empty or missing sample directory produces a public `no_observations` receipt and no archive. An archive error is a separate failed step with a bounded reason; it neither invents observations nor replaces the original qualification failure. If dependency setup fails before the script starts, a standard-library fallback writes an `archive_environment_unavailable` receipt.

Three separate artifact classes are uploaded with `always()`:

| Artifact | Contents | Confidentiality |
| --- | --- | --- |
| Existing aggregate evidence | Sanitized aggregates and build metadata | Public |
| `native-performance-encrypted-{target}-{run_id}-{run_attempt}` | `encrypted/*.hge` only | Encrypted to the recovery recipient |
| `native-performance-archive-receipt-{target}-{run_id}-{run_attempt}` | Status, ciphertext size/hash, recipient ID, file count | Public |

Every rerun has a distinct attempt artifact name. Retention is 30 days; keep a copy of the encrypted artifact and public receipt before that expiry if longer retention is needed. Interrupted JSONL records, unsuccessful attempts, zero-byte files, and unfiltered numeric observations are preserved byte-for-byte. The archiver does not parse or repair the observation JSON. Filenames, individual file hashes, source/target context and run identifiers are inside the encrypted manifest. Ciphertext length and file count remain visible in the public receipt.

## Recipient and offline recovery

The committed `qualification-recipient.pem` contains **only** an RSA-3072 public key. Its SHA-256 identity is calculated over DER SubjectPublicKeyInfo, not the PEM formatting:

```
d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb
```

The private recovery key is retained separately from Git and CI. CI does not receive it through an environment variable, secret, service, or remote encryption endpoint. Tests generate independent ephemeral test keys.

On a trusted machine with the locked project dependencies and the separately retained private key, first compare the downloaded ciphertext SHA-256 with the public receipt from the intended CI run. Then run:

```sh
uv sync --frozen --no-dev --no-install-project
uv run --frozen --no-sync python -m scripts.native_slo_evidence_archive decrypt \
  --archive /absolute/path/observations.hge \
  --private-key /absolute/path/private-recovery-key.pem \
  --output /absolute/path/new-recovery-directory
```

The output directory must not already exist, and its parent must exist. On Unix the private key must be owned by the current user with no group/other permissions. On Windows it must satisfy Guard's protected owner/System DACL contract. Recovery creates an owner-private directory and files: `0700`/`0600` on Unix and protected private DACLs at creation on Windows. It never merges into or overwrites an existing directory. All AEAD authentication and all manifest names, sizes and hashes are verified before any plaintext directory is created. A later disk I/O failure may leave an incomplete private recovery directory; the command reports failure and does not recursively delete or repair existing paths. Retry into another new directory after resolving the I/O problem.

The successful recovery receipt reports the authenticated internal manifest hash for private audit. Do not upload recovered files or that private manifest as public aggregates. Possession of the public encryption key allows anyone to create a new valid archive: encryption provides confidentiality and ciphertext integrity, **not a CI authorship signature**. Use the trusted run/artifact provenance and its public ciphertext digest to select the intended evidence.

## Bounded format v1

The implementation uses [cryptography's AESGCM API](https://cryptography.io/en/latest/hazmat/primitives/aead/) and [RSA OAEP](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) from the existing locked dependency. Every archive generates a fresh 256-bit AES key, random 96-bit nonce and random 128-bit archive identifier. RSA-3072 OAEP with SHA-256 and MGF1-SHA-256 wraps only the AES key. Its label is `hol-guard.native-qualification-archive.v1` followed by NUL.

The binary envelope contains the eight-byte magic `HGQE 00 01 0d 0a`, a four-byte big-endian header length, the exact canonical JSON header, and AES-GCM ciphertext including its full 16-byte tag. Associated data is the domain label including NUL followed by the complete magic/length/header prefix. The exact header fields are `schema`, `suite`, `recipient_key_id`, `archive_id`, `nonce`, `wrapped_key` and `ciphertext_bytes`. Header JSON is ASCII, lexicographically sorted, compact, duplicate-free and canonical. The nonce and wrapped key use canonical standard Base64. Unknown fields, noncanonical encoding, trailing bytes and truncated envelopes are rejected.

The decrypted plaintext is a four-byte big-endian manifest length, canonical JSON manifest, and concatenated file bytes. The manifest has exactly `schema`, `context`, `files` and `total_bytes`. Each file entry has exactly `name`, `bytes` and `sha256`; order defines the concatenation. Context admits only a 40-character source SHA, one of the four qualified Rust target identifiers, and bounded positive run/attempt numbers. No external paths or arbitrary metadata are admitted.

| Bound | Maximum |
| --- | ---: |
| Flat files | 256 |
| One file | 32 MiB |
| All observation bytes | 128 MiB |
| Encrypted manifest | 96 KiB before encryption |
| Public header / receipt | 4 KiB each |
| PEM input | 16 KiB |

Names must be flat ASCII `.json`/`.jsonl` basenames. Separators, traversal, alternate streams, Windows reserved names, case-fold collisions, unexpected entries, symlinks, reparse points, hardlinks, nonregular files and size changes are rejected. The retained directory inventory is checked before and after bounded reads; each opened file is checked against its path before and after reading. Windows reads deny concurrent write/delete sharing. Source writers must be stopped before archival; the workflow archives after the sampling driver exits.

Atomic publication uses exclusive destinations and retained source identity. Windows publishes the written file through its still-open handle with replacement disabled, including in the dependency-free public receipt fallback. Unix output requires a current-user-owned parent without group/other write access and exclusive private temporary files, with identity checks around the atomic hard-link publication. These filesystem protections use the operating-system user boundary; they do not claim isolation from an attacker running as the same user or an administrator who can modify artifacts after publication. Temporary files are outside every upload glob. Existing destination bytes and permissions are never intentionally changed.

These archives retain evidence; their presence does not certify semantic correctness, latency SLOs, or qualification success. The existing qualification gates and unchanged PRD thresholds determine those results.
