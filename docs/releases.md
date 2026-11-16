# Release CVEdb

CVEdb supports Python 3.11–3.15. The release workflow runs only when you publish
a GitHub Release. Creating or pushing a tag alone does not publish to PyPI.

## Configure publishing

Before the first automated release, configure these settings with the relevant
GitHub repository and PyPI project administrators:

1. Create a GitHub environment named `pypi`. Require maintainer approval and limit
   deployment to release tags matching `v*`. Configure tag rules so only release
   maintainers can create or update those tags. Referencing the environment in
   the workflow does not configure these protections.
2. In the existing `cvedb` PyPI project's publishing settings, add a GitHub trusted
   publisher with owner `trailofbits`, repository `cvedb`, workflow filename
   `release.yml`, and environment `pypi`.

The workflow uses short-lived OIDC authentication and the publishing action's
default digital attestations. It needs no PyPI password or API token.

See [GitHub environment protection][environments], [PyPI publisher registration][publisher],
and [PyPI trusted publishing][publishing] for the account setup steps.

## Prepare a release

1. Update `[project].version` in `pyproject.toml` on a feature branch and run
   `uv lock`. Use a version that has not already been published on PyPI.
2. Run the local checks with uv 0.13.7:

   ```sh
   uv lock --check
   uv sync --frozen --python 3.13
   uv run --frozen prek run --all-files
   uv run --frozen python -m scripts.audit_dependencies
   uv run --frozen python -m scripts.check_dist
   ```

3. Submit the version change through a PR and merge it after the supported Python
   matrix and quality checks pass.
4. Create and push an annotated tag named exactly `v` followed by the package
   version, pointing to the tested commit on the default branch. For example,
   package version `0.0.6` requires tag `v0.0.6`.
5. Publish a GitHub Release for that existing tag. The [published release event][release-event]
   starts `.github/workflows/release.yml`.

## Verify and approve publication

The guard requires a published, non-draft release. The package version, event tag
reference, event SHA, checked-out commit, and peeled tag commit must agree. The
commit must be contained in the fetched default branch. Both annotated and
lightweight tags pass these identity checks; use annotated tags for releases.

The workflow reruns the complete reusable test workflow at the event commit,
including the Python 3.11–3.15 tests, locked dependency audits, and quality checks.
It then builds an sdist and its wheel, checks metadata, license files, entry
points, the typing marker, and all bundled snapshots, and tests a clean installed
wheel with network access disabled.

Only after every check passes does the build retain the two verified archives
and upload them as one immutable Actions artifact. The publication job downloads
that artifact by its exact ID from the same workflow run and fails on an artifact
digest mismatch. It has no checkout, build, or package-install steps. Only this
job receives `id-token: write` and uses the protected `pypi` environment.

Review the tag, commit, validation results, and built artifacts before approving
the `pypi` deployment. Confirm the new version and attestations on PyPI after
the publication job succeeds. For transient service failures, resolve the cause
and rerun the failed workflow; PyPI does not permit replacing an uploaded file.

For local inspection, retain verified archives in a new directory:

```sh
uv run --frozen python -m scripts.check_dist --out-dir dist
```

The directory must not already exist. Without `--out-dir`, verification uses and
removes a temporary directory. Neither local command publishes anything.

[environments]: https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments
[publisher]: https://docs.pypi.org/trusted-publishers/adding-a-publisher/
[publishing]: https://docs.pypi.org/trusted-publishers/using-a-publisher/
[release-event]: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#release
