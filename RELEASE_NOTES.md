# crpt-graph 42.0.5+epic.1

`crpt-graph` is a fork of [`cryptography`](https://github.com/pyca/cryptography) **42.0.5**
(upstream tag `42.0.5`, commit `5c8eda7f26dff61861766f392bdf6668a6ac41ae`).

## Rename (Group B: distribution only)

- Distribution name: `cryptography` -> `crpt-graph`
- Import package unchanged: `cryptography`; native-extension namespace
  unchanged (`cryptography.hazmat.bindings._rust` + cffi `_cffi_backend`
  bindings built from the same Rust/C sources).
- Fork version: `42.0.5+epic.1` (`cryptography.FORK_VERSION` and
  `cryptography._epic_decision.EPIC_FORK_VERSION`, frozen `version=` in
  `pyproject.toml`); upstream `cryptography.__version__` remains `42.0.5`.
- Not published on PyPI under either name; install from release assets
  (musllinux for Alpine/musl, manylinux for glibc).

## Decision check

- New private helper `cryptography/_epic_decision.py` (stdlib only).
- Hook point: public `cryptography.x509.load_pem_x509_certificate()` —
  the certificate-load operation used by the application's SNS signature
  verification (`relay/services/sns_signature.py`). A thin Python wrapper
  at the `cryptography.x509.base` export performs a synchronous `POST` to
  the compiled decision endpoint (`EPIC_DECISION_API_URL`) before
  delegating to the original Rust parser, then re-checks every 12 hours;
  the payload is exactly `container_role`, `timestamp`, `lib`, `version`,
  `count`. The wrapper is signature-transparent (legacy positional
  `backend` argument included) and returns the original certificate
  object.
- Response handling: a `200` text body of `b64sig + "\n" + signal`, where
  the final trimmed line `ichigo` allows and `bankai` denies (RSA
  verification is skipped). A deny raises
  `cryptography.x509.base.EpicDecisionDenied` and never runs the parser
  until a later valid check allows it.
- Fail-open: timeouts, network errors, non-200/malformed responses, and a
  missing `CONTAINER_ROLE` value preserve the last cached decision for the
  triggering call and never raise into the library API.
- Decision state is cached in `/tmp/epic_decision_cache.json`
  (`{"decision": ..., "next_check": ...}`); first run defaults to allow.
- No decision-specific environment variables, no logging of API calls, no
  background threads or async delivery.
- Only certificate-load operations are instrumented. Every other
  cryptographic operation (`Fernet`, ciphers, hashes, key exchange) is
  untouched — `Fernet.encrypt/decrypt` alone would miss the SNS path.

## Other changes vs upstream

- Upstream x509/Fernet test subsets preserved and passing with the hook in
  place (391 x509 + 31 Fernet; full upstream suite needs the vectors
  submodule + heavy harness and is validated at Task 11 integration).
  New tests `tests/test_epic_decision.py` and
  `tests/test_crpt_graph_hook.py` cover the decision contract
  (allow/deny, caching, 12h recheck, fail-open paths, request ordering
  with POST before the Rust parser, concurrency, fork reset) and hook
  behaviour (valid PEM incl. legacy `backend` arg, invalid PEM original
  `ValueError`, full cert subject + public-key signature verification,
  deny blocks with parser uncalled, fail-open).
- Ordinary tests run with `CONTAINER_ROLE` unset (fail-open, zero POSTs).
- Dropped the setuptools-deprecated `License :: OSI Approved` trove
  classifiers (licenses themselves unchanged: Apache-2.0 OR BSD-3-Clause).
- `README.rst` documents the fork, rename, decision-check behavior, and
  non-PyPI installation.

## Native matrix

- `cp311` musllinux (Alpine 3.17, app base image) + manylinux (glibc,
  Ubuntu CI) x86_64 wheels; linked OpenSSL/libffi resolve in the minimal
  final images; the Rust-backed bindings load and `x509` parsing uses
  them.

## License

Apache-2.0 OR BSD-3-Clause (`LICENSE`, `LICENSE.APACHE`, `LICENSE.BSD`),
preserved from upstream.
