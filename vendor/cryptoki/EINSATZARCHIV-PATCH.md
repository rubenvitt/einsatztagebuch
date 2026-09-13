# Scoped patch of cryptoki 0.12.0

Source: crates.io cryptoki 0.12.0, upstream tag `cryptoki-0.12.0` in
https://github.com/parallaxsecond/rust-cryptoki. The original Apache-2.0
license, README, `Cargo.toml.orig`, and all source files are retained.
Upstream examples/tests are omitted from this dependency-only copy and their
manifest targets/dev dependencies removed. `auto* = false` is preserved.

The only source changes are the three scratch-buffer declarations/allocations
inside `Session::get_attributes` in `src/session/object_management.rs`:
`Vec<Vec<u8>>` becomes `Vec<zeroize::Zeroizing<Vec<u8>>>`, and both initial
buffers are wrapped in `Zeroizing`. A pinned `zeroize = 1.9.0` dependency
with `alloc` is added. No FFI, mechanism, attribute conversion, or error
semantics change.

Upstream copies `C_GetAttributeValue` scratch buffers into returned attributes
and frees the scratch allocation without wiping it. The application cannot
wipe that hidden copy after receiving a derived DH value. The wrapper now
wipes those scratch allocations on success and every early-return path.
The application separately wipes returned derived values and destroys the
ephemeral token object. Long-term private `CKA_VALUE` is never queried.

The root Cargo patch pins this copy. ADR 0007 records the integration decision;
the explicit SoftHSM product-provider gate verifies the native behavior.
Upgrade by comparing all upstream source files and reapplying/removing this
three-line change. Do not silently replace this copy with the registry crate.
