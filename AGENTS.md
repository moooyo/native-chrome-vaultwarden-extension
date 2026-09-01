# Repository Instructions

## Verification Environment

- Do not run tests, validation suites, builds, smoke tests, runtime probes, or browser-extension
  verification on the local machine unless the user explicitly authorizes local verification in the
  current task.
- Without current-task authorization for local verification, connect with `ssh test-env` and run all
  verification there.
- If `test-env` is unavailable and local verification has not been authorized, report verification as
  blocked. Do not silently fall back to the local machine.
- Treat Chrome/Edge extension loading, Playwright runs, local test servers, and direct backend probes
  as local verification under this rule.
- Honor any narrower authorization in the current task. For example, if the user permits local builds
  but requires backend data to come from `test-env`, all integration and end-to-end verification must
  use the `test-env` backend.
