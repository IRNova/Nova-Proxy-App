# Distributing notice-accompanied copies

## Source

Keep the original MIT notice in LICENSE, the applicable file-level notices,
THIRD_PARTY_NOTICES.md and the LICENSES directory with complete source copies.
When copying a covered source file separately, preserve its full notice header.
This correction concerns identified historical SniShaper material; unrelated
dependencies and Nova-authored material retain their own applicable terms.

## Binary packages

Publish an archive containing the unmodified application and the notice files:

```text
NovaProxy/
  NovaProxy.exe
  LICENSE
  THIRD_PARTY_NOTICES.md
  LICENSES/
    SniShaper-MIT-2026-05-04.txt
    SniShaper-JetCPPTeam-MIT-2026-06-30.txt
    mhr-cfw-go-MIT.txt
```

Preserve all other dependency notices already shipped with the application.
If an existing release is a ZIP, retain its members and existing notices and
add the missing notice files without overwriting them. If the release is a raw
executable, distribute a notice-accompanied archive as the normal download.
Do not claim that a source notice commit changes bytes in old executables.

## Existing releases

For each published release, a maintainer must:

1. Add the original copyright and MIT permission notice to the release's
   accompanying files and publish a notice-accompanied application archive.
2. Update the release page to identify the notice-accompanied download and
   link the original notice and corrected attribution.
3. Verify that each executable and existing package member is byte-identical
   to the original release unless a separate rebuild is intended and documented.
4. Tell downstream redistributors to include the notice files with their copies.
5. Check any remaining raw executable download paths and prior distribution
   channels; do not describe them as updated merely because source notices exist.

These maintainer actions are required for release coverage and are separate
from merging the source documentation correction. This pull request does not
modify published release assets or certify that every prior copy is corrected.
The exact source-to-binary correspondence and missing local dependency sources
remain documented in LICENSING-PROVENANCE.md.
