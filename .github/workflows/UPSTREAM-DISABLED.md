# Disable these upstream workflows in GH UI on the fork

policy-controller fork (github.com/coldzerofear/...) inherits all upstream
GitHub Actions workflows. Most of them assume sigstore-project GCP
credentials or push to gcr.io/projectsigstore — they will fail red on
every tag/push to a fork that doesn't have those secrets.

**One-time operation per fork**: open the Actions tab on the fork's GitHub
page, click each workflow in the left sidebar, then the `…` menu in the
top-right → **Disable workflow**. Cannot be done from git because GH
stores workflow enable/disable state in the repo's GH database, not in
the workflow file itself.

## MUST disable (will block fork-specific workflows otherwise)

| Workflow file | Sidebar name | Why disable |
| --- | --- | --- |
| `release.yaml` | **Cut Release** | Triggered on `v*` tag (same as our `release.yml`). Needs GCP workload identity. Will fail on every tag push. |
| `build.yaml` | **CI-Container-Build** | Triggered on push main. Needs GCP for gcr.io. Will fail on every commit to main. |

## Recommended to disable (CI resource savings, kind e2e tested locally instead)

| Workflow file | Sidebar name | Why disable |
| --- | --- | --- |
| `kind-cluster-image-policy*.yaml` (4 files) | **Test policy-controller with ...** | Kind cluster end-to-end tests. Slow (~15 min each). Upstream-maintained; our fork hasn't changed the kind-cluster pieces. Test locally via `make test` against a kind cluster. |
| `kind-e2e-cosigned.yaml` | **Policy Controller KinD E2E** | Same reason. |
| `kind-e2e-trustroot-crd.yaml` | **TrustRoot CRD KinD E2E** | Same reason. |
| `verify-codegen.yaml` | **Codegen** | Verifies generated code is up to date. We regenerate by hand when changing types — see deepcopy update notes in zjrcu-gm commits. |
| `verify-docs.yaml` | **API Docs Generator** | Verifies API docs are regenerated. Same logic. |
| `policy-tester-examples.yml` | **CI-Tests** | Examples tests. Mostly upstream-flavored. |
| `release-snapshot.yaml` | **snapshot** | Snapshot releases to gcr.io. We don't snapshot. |

## Keep enabled (fork-specific or universal)

| Workflow file | Sidebar name | Why keep |
| --- | --- | --- |
| `ci-fork.yml` | **CI (fork)** | Our PR + push CI (go vet + test + ko build). |
| `release.yml` | **Release** | Our tag-triggered release (ghcr.io + GH Release). |
| `codeql-analysis.yml` | **CodeQL** | GitHub Code Scanning, runs on fork fine. |
| `depsreview.yml` | **Dependency Review** | Same. |
| `scorecard_action.yml` | **Scorecards supply-chain security** | Same. |
| `style.yaml` | **Code Style** | Static checks. |
| `lint.yaml` | **golangci-lint** | Static lint. |
| `donotsubmit.yaml` | **Do Not Submit** | Marker check. |
| `milestone.yaml` | **Milestone** | Cosmetic, no external deps. |
| `tests.yaml` | **CI-Tests** | If it duplicates ci-fork.yml's tests, can disable. Otherwise leave. |

## Re-enable any of these

Same path: Actions tab → click workflow → `…` → **Enable workflow**.

## Why not just delete the files?

- Editing/deleting upstream workflow files creates conflicts every rebase.
- Disable-via-UI is per-repo state; the file stays intact in git.
- When syncing from upstream, our disable state persists.
