# Third-party notices

This file preserves notices for identified upstream material. It is not a new license grant for all Nova-authored code, a complete dependency inventory, or a statement that every past distribution is compliant.

## Historical SniShaper material

Nova-Proxy-App shares frontend and backend code with historical SniShaper source. Examined backend overlap includes certificate verification, TLS fragmentation and out-of-band helpers, TUN flow, DNS resolution, and routing helpers. Nine examined Go files are byte-identical to the May MIT snapshot. The comparison does not determine copying direction, authorship of every line, or the exact revision originally imported.

Preserved historical notices:

- [MIT notice, copyright 2026 SniShaper](LICENSES/SniShaper-MIT-2026-05-04.txt), copied verbatim from [a6a600f3b50b7c3c5f00273eebd93f62148493d3](https://github.com/SnishaperTeam/SniShaper/blob/a6a600f3b50b7c3c5f00273eebd93f62148493d3/LICENSE).
- [MIT notice, copyright 2026 SniShaper and JetCPPTeam](LICENSES/SniShaper-JetCPPTeam-MIT-2026-06-30.txt), copied verbatim from [dccd6aeee7c82296c859e799fca0e042e510f8ee](https://github.com/SnishaperTeam/SniShaper/blob/dccd6aeee7c82296c859e799fca0e042e510f8ee/LICENSE).

Both observed historical notices are retained because the exact import revision is not documented. Their inclusion does not establish that every contribution has the same ownership or license. Existing file-specific notices and dependency licenses must also be preserved.

SniShaper later changed its root license to AGPLv3 at [edc681b76ead158d9c967a4d90b4ce51c640905d](https://github.com/SnishaperTeam/SniShaper/commit/edc681b76ead158d9c967a4d90b4ce51c640905d). Later additions must be assessed against the terms applicable to those additions; the historical MIT notices do not license later AGPL-only material.

## Credited GSA upstream: mhr-cfw-go

The README credits [denuitt1/mhr-cfw-go](https://github.com/denuitt1/mhr-cfw-go) as the starting point for GSA relay work. Its [MIT notice](LICENSES/mhr-cfw-go-MIT.txt) is reproduced verbatim from [revision 673fb50733ccf193761da45c328a692c7779aa57](https://github.com/denuitt1/mhr-cfw-go/blob/673fb50733ccf193761da45c328a692c7779aa57/LICENSE). The original imported revision remains unidentified; this is a preserved upstream notice, not a claim that this precise revision was used.

## Other dependencies and distribution

Dependencies retain their respective licenses. This targeted notice restoration is not an exhaustive audit of the Go module graph, local dependency replacements, bundled frontend assets, or release binaries. The missing original import record and binary-to-source correspondence are recorded in [LICENSING-PROVENANCE.md](LICENSING-PROVENANCE.md).

## Covered source scope

The following files contain material shared with the examined historical
SniShaper source. Their file-level notices reproduce the original SniShaper
copyright and MIT permission text for that material. This scope does not assign
ownership of Nova modifications to SniShaper or relicense unrelated code.

- `cert/cert.go`
- `cert/exec_windows.go`
- `core_api.go`
- `core_client.go`
- `core_client_other.go`
- `core_client_windows.go`
- `core_markers.go`
- `core_runtime.go`
- `proxy/auto_routing.go`
- `proxy/cert_verify.go`
- `proxy/cf_pool.go`
- `proxy/config.go`
- `proxy/doh.go`
- `proxy/error_page.go`
- `proxy/gfwlist.go`
- `proxy/port_manager.go`
- `proxy/proxy.go`
- `proxy/tls_fragment.go`
- `proxy/tls_fragment_oob_unix.go`
- `proxy/tls_fragment_oob_windows.go`
- `proxy/tun_flow.go`
- `sysproxy/exec_windows.go`
- `sysproxy/sysproxy_windows.go`

The same original MIT notice is discoverable in [LICENSE](LICENSE). Complete
source distributions must retain the notices. Binary distributions must carry
the notice files alongside the application; see [DISTRIBUTION.md](DISTRIBUTION.md).
