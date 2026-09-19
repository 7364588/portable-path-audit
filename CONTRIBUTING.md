# Contributing

Use Python 3.11 or later. The runtime and test suite use only the standard
library. Package builds use setuptools.

Run the tests from the repository root:

```sh
python -m unittest discover -s tests -v
```

Tests add the local `src` directory to the import path. Installation is not
required for development or testing. See the README for running the CLI from
a checkout.

For bug reports, include the Python version, operating system, expected result,
actual result, and a minimal set of example filenames. Use synthetic names and
remove private paths. Content from the affected files is unnecessary.

Changes should keep these properties:

- Never open, modify, rename, or delete target file contents.
- Keep output ordering deterministic and all report paths relative.
- Preserve exit status 2 for incomplete scans, even when findings also exist.
- Explain platform-specific behavior and use mocked directory entries for
  filenames that a test host cannot create.
- Add a regression test for a bug fix, update the README when behavior changes,
  and describe user-visible changes in the changelog.

Please avoid mandatory runtime or test dependencies. Public API and JSON schema
changes should be called out explicitly in review. Contributions are distributed
under the project's MIT license.
