# Releasing CipherScope

1. Choose an unused version after checking crates.io and GitHub releases. Account
   for public API and CLI compatibility changes; for this pre-1.0 crate, use a new
   minor version for incompatible changes.
2. Update the package version in `Cargo.toml` and refresh the local package entry
   in `Cargo.lock` with `cargo check`. Add release notes at
   `docs/releases/v<VERSION>.md`, including upgrade requirements.
3. Run formatting, warnings-denied Clippy for all targets under both all and
   minimal features, all-feature/minimal tests, the dependency audit, and
   actionlint. Commit the release preparation, verify it with
   `cargo publish --locked --dry-run`, and get the commit onto main with green CI.
4. Create an annotated `v<VERSION>` tag on that main commit and push the tag.
   `.github/workflows/release.yml` builds four binary archives, publishes the crate
   using the repository's `CARGO_REGISTRY_TOKEN` secret, then creates a GitHub
   release using the committed release notes.
5. Monitor the Release workflow. Verify the crates.io version, all four GitHub
   assets, and the reported version of a downloaded binary. Do not move a tag or
   republish an already published crate version to recover from a failed release.

Crates.io publication and the GitHub release are separate workflow steps. If
publication succeeds but a later step fails, preserve the published version and
complete only the remaining GitHub release/asset work.
