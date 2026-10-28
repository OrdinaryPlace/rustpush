# Building the Linux messaging worker

Run these commands from the protocol fork root on Linux/amd64, with `rustup`
installed. The worker uses the vendored NAC source described in [PROVENANCE.md](PROVENANCE.md).
The build does not require an Apple binary, account export, hardware key, or Mac.

For a fresh Debian 12 build container, install the build tools:

```sh
apt-get update
apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkg-config libclang-dev \
  protobuf-compiler perl python3 git ca-certificates
rustup toolchain install 1.99.1 --profile minimal
```

Initialize the required pinned public submodules. This per-command HTTPS rewrite
also covers nested public submodules whose recorded URLs use GitHub SSH:

```sh
git -c 'url.https://github.com/.insteadOf=git@github.com:' \
  submodule update --init --recursive -- \
  third_party/apple-private-apis third_party/quinn third_party/rtc \
  third_party/rustls third_party/rustls-platform-verifier
```

Materialize the ten ignored FairPlay certificate/key include pairs from the
checked-in public `certs/legacy-fairplay` files using the retained Corten rule:

```sh
python3 third_party/open-absinthe-linux/tools/prepare_compile_inputs.py
```

This command only prepares compile inputs. It neither downloads runtime resources
nor provisions an account. These legacy includes do not establish support for
fresh APNs activation. The worker requires an existing registered APNs key pair,
token, Madrid registration and matching software keystore before connecting; it
rejects missing state rather than creating a replacement identity. That path
skips the library's fresh APNs activation branch.

Choose an absolute build directory outside the checkout, then use the committed
standalone worker lockfile:

```sh
export CARGO_TARGET_DIR=/absolute/path/to/buddy-worker-target
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0
cargo build --locked --manifest-path tools/buddy-imessage/Cargo.toml
cargo test --locked --manifest-path tools/buddy-imessage/Cargo.toml
```

The executable is `$CARGO_TARGET_DIR/debug/buddy-imessage`. Add `--offline` to
Cargo commands once public crate/git dependencies are cached. The worker tests
use synthetic inputs and require no account state. For a network-isolated test,
disable networking on the disposable build container after public dependency
setup. Do not run `rustfmt`; see the repository's `AGENTS.md`.

The reviewed build used Rust 1.99.1, OpenSSL crate 0.10.73, Linux/amd64 and debug
information disabled. The 56 MiB executable links only `libm`, `libgcc_s`, `libc`
and the Linux ELF loader. Compilation and offline tests do not establish Apple
account activation, message delivery or native iPhone rendering.

## Filtered protocol tests

Root library tests are separate from the worker build. The inherited `cfg(test)`
TLS proxy helper requires ignored `certs/proxy/push_certificate_chain.pem` and
`push_key.pem`. The investigation generated a disposable self-signed
`buddy-offline-test.invalid` fixture solely for those compile-time includes;
the filtered native poll tests do not invoke the proxy helper. For the same
test setup, with the `openssl` command installed:

```sh
export CARGO_TARGET_DIR=/absolute/path/to/buddy-protocol-tests-target
mkdir -p certs/proxy
umask 077
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/proxy/push_key.pem \
  -out certs/proxy/push_certificate_chain.pem \
  -days 1 -subj /CN=buddy-offline-test.invalid
cargo test --locked --lib native_poll_tests --no-default-features \
  --features macos-validation-data,remote-anisette-v3
cargo test --locked --lib balloon_wire::tests --no-default-features \
  --features macos-validation-data,remote-anisette-v3
```

The production worker does not need either proxy file. Select `--lib` for these
checks: the inherited manual `rustpush-test` login utility has stale authentication
API calls and is not part of the messaging worker or these filtered tests.

Use a separate target directory for root library tests, for example
`CARGO_TARGET_DIR=/absolute/path/to/buddy-protocol-tests-target`. The vendored
platform verifier emits an unhashed `rlib` alongside its `cdylib`; sharing one
target directory between the root library and standalone worker workspaces can
overwrite it with the other workspace's Rustls dependency identity.

At runtime, registration refresh can need the separately fetched, checksum-verified
`IMDAppleServices` resource. Follow [PROVENANCE.md](PROVENANCE.md) and set
`OPEN_ABSINTHE_BINARY` to that read-only resource. Keep private registered state in
a separate owner-only worker directory, as described in the
[worker README](../../tools/buddy-imessage/README.md).
