# GeoSite RU Light v11.5 — weekly approval queue

The existing Monday 00:00 UTC scheduled build compares the validated
candidate with the checksum-verified release DAT. It uses the same approval
manifest as production. A schedule run with unapproved RU additions and no
blocking regression takes the review path instead of publishing.

| Semantic gate | Weekly schedule | PR, main push or manual build |
| --- | --- | --- |
| Pass | Existing release path | Existing behavior |
| Unapproved RU additions only, with existing approval and BLOCK checks passing | Keep the published DAT, retain the candidate artifact, update the weekly draft | Fail the build, never publish the candidate |
| Coverage regression, BLOCK change, invalid input, or release-reference error | Fail the build and retain available diagnostics, no draft update | Fail the build |

The writer runs as a separate job with repository contents and pull request
write permissions, only on a scheduled run on `main`. It creates or updates
one Draft PR from `auto/weekly-ru-candidates`. Its commit changes only
`reviews/weekly-ru-candidates.md`, with the semantic comparison in the PR
description and links to the complete report and workflow artifact.
The artifact also contains the candidate DAT, checksum and provenance.
Updates retain branch history without force-pushing and stop if the draft
is no longer automation-managed or the branch has a human commit.

The Draft PR itself **does not approve rules**. Review each new effective RU
rule and submit accepted entries to `data/v11-approved-effective-ru.txt`
in a separate PR. If needed, also pin the corresponding rule in
`local/ru.txt`. Keep rejected entries out of the manifest. The v11.4
corporate discovery remains report-only and is not an input to this gate.

GitHub must allow Actions to create pull requests in **Settings → Actions →
General → Workflow permissions**. If creation is denied, the writer fails
visibly and the unchanged release and review artifact are still available.
The workflow does not approve or merge pull requests. Workflows triggered
by a GitHub Actions token may await manual approval. Review and close
obsolete drafts normally. The job does not close drafts automatically on
no-change weeks.
