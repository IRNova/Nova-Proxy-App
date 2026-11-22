# Licensing provenance

## Current state

This document records the 2026-11-21 source comparison and the 2026-11-22 notice restoration. It does not grant new rights to the whole project or certify legal compliance. No exact original SniShaper import archive or acquisition commit has been identified.

## Source revisions examined

- Publication base: Nova-Proxy-App `1fc7a6d37e5ec105d0bbe3955ef0c93495d8415b`. Its full file tree is identical to the earlier audited `ceb62fbc8ff8686b3f81bada354ace4bbff70dde` snapshot.
- May MIT SniShaper snapshot: `a6a600f3b50b7c3c5f00273eebd93f62148493d3`.
- Last MIT SniShaper revision before root-license replacement: `7de0ec0c8746708a4f56ee93da0b0d0b2041d286`.
- MIT-to-AGPL transition: `edc681b76ead158d9c967a4d90b4ce51c640905d`, dated August 11, 2026.
- Standalone snishaper-core extraction: `a3fe3277654e1e2d566ad473a3d3cc01ad2adfa4`, dated October 18, 2026.

All 33 current Go files have the same Git blob hashes as Nova's May 22 code-changing commit `960e285840283adebac487f2c128245e5924e4c7`. The [comparison to current main](https://github.com/IRNova/Nova-Proxy-App/compare/960e285840283adebac487f2c128245e5924e4c7...ceb62fbc8ff8686b3f81bada354ace4bbff70dde) contains later documentation, funding and artwork changes.

The first visible addition of `proxy/tls_fragment.go` is the May 2 commit `4fbacb4efbee1b3fed2e1803857fb95b17ea6cfe`, whose message is only `new`. It does not record an original upstream revision. This is the earliest visible file addition, not proof of the actual source acquisition.

## Exact file evidence

The following current Go files are byte-identical to the examined May MIT SniShaper snapshot:

- `cert/exec_windows.go`
- `core_client_other.go`
- `core_client_windows.go`
- `core_markers.go`
- `proxy/cert_verify.go`
- `proxy/gfwlist.go`
- `proxy/tls_fragment_oob_unix.go`
- `proxy/tls_fragment_oob_windows.go`
- `proxy/tun_flow.go`

The `proxy/tls_fragment.go` differences against that snapshot are a small bounds check and an error-method spelling correction. Its substantial parser and fragmentation bodies already appear in the historical source.

A Go standard-library parser comparison, excluding tests and vendored utls, finds 149 of 409 Nova function bodies containing at least 40 tokens identical to the May snapshot after removal of comments and formatting. This measures syntactic overlap, not ownership, copying direction, or a percentage of the entire app.

## Claimant clarification and original notice

In [the detailed issue reply](https://github.com/IRNova/NovaWorker/issues/174#issuecomment-7073383173), the claimant accepted the historical MIT timing and withdrew the AGPL claim for the identified files. The remaining request is original MIT notice restoration and corrected backend attribution. The GSA engine was excluded from that claim.

The cited March MIT-added revision `c8c3c6d40cc49d52ed33a4b1e5e8f759683bf887` and April source revision `a53a718e4705932c7fa531588e8790421115545c` both carry license text byte-identical to the notice restored here. The exact originally acquired revision remains unknown.

## Unresolved source and release questions

- Identify the actual original import archive/revision and the license notices that accompanied it.
- Verify permissions and provenance for modifications beyond the compared MIT snapshot and any private or unreleased builds.
- The v1.2 release tag points to `d79e1ae7152ee207ee95af5e24cfc4c83e5bcaad`; 15 current Go paths differ from that tag.
- The published v1.2 executable has SHA-256 `3ee2f6958ae25b49fb0751b0fefa94fd299f4eab9a98a2be264efd2b9251f0c3`. Its embedded Go metadata names `novaproxy` but has no VCS revision. Absence of a module dependency does not exclude copied source.
- Public source references local `utls` and `v2ray-core-master` replacements that are absent from this tree; the app entrypoint and frontend source are also absent. Complete binary-to-source correspondence remains unverified.
- Preserve third-party notices with source and binary distributions as described in [DISTRIBUTION.md](DISTRIBUTION.md). Source notice restoration alone does not update past downloads, alter existing binaries, or supply missing build sources.

## Scope

This record concerns Nova-Proxy-App. Nova-Proxy, NovaWorker and NovaInstall require their own source and license analysis. No project-wide license replacement is made by this document. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
