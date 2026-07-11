# GitHub Release Pipeline and Installation Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, verify, and publish an installable Chromium extension ZIP plus SHA-256 checksum from an immutable matching Git tag, and replace the README with complete user installation and maintenance instructions.

**Architecture:** A testable Node module owns tag/version validation, deterministic ZIP creation, extracted-package inspection, and checksums. A thin CLI exposes that module to GitHub Actions, while the workflow performs quality gates and idempotent GitHub Release publication for an existing tag. The README documents the exact resulting artifact and its manual installation lifecycle.

**Tech Stack:** Node.js 22, ECMAScript modules, `fflate`, Vitest, esbuild, GitHub Actions, GitHub CLI, Manifest V3, PowerShell documentation commands.

## Global Constraints

- Git tags are the only version and release trigger.
- A release tag must use strict Semantic Versioning with a leading `v`, such as `v0.2.0` or `v0.2.0-beta.1`.
- Manual dispatch may rerun an existing tag, but it must never create, move, or reinterpret a tag.
- `package.json`, `src/manifest.json`, `dist/manifest.json`, and the tag base version must agree with no override.
- The release archive must be named `vaultwarden-extension-<tag>.zip` and contain `manifest.json` at its root.
- Every release contains the versioned ZIP and `SHA256SUMS.txt`.
- All third-party GitHub Actions remain pinned to immutable commit SHAs.
- All code, code comments, and documentation are written in English.
- Commands intended for local Windows use are valid PowerShell commands.

---

## File Structure

- `tools/release-lib.mjs`: pure release metadata, file collection, ZIP creation, archive inspection, and checksum functions.
- `tools/release.mjs`: CLI that prepares release assets and writes GitHub Actions outputs.
- `tools/release-lib.test.mjs`: focused unit and package-contract tests.
- `vitest.config.ts`: includes tool tests in the normal `npm test` gate.
- `package.json` / `package-lock.json`: add `fflate` as a development-only packaging dependency and expose a local release verification command.
- `.github/workflows/release.yml`: exact-tag checkout, full gates, package preparation, artifact upload, and idempotent GitHub Release publication.
- `README.md`: user-first installation, update, verification, troubleshooting, removal, development, and release instructions.

### Task 1: Release metadata and archive contract

**Files:**
- Create: `tools/release-lib.test.mjs`
- Create: `tools/release-lib.mjs`
- Modify: `vitest.config.ts`
- Modify: `package.json`
- Modify: `package-lock.json`

**Interfaces:**
- Produces: `resolveReleaseMetadata(tag, versions)`, `createReleaseArchive(options)`, `verifyReleaseArchive(options)`, and `sha256File(path)`.
- Produces: metadata `{ tag, version, archiveName, prerelease }`.

- [ ] **Step 1: Add `fflate` as a development dependency**

Run:

```powershell
npm.cmd install --save-dev fflate@latest
```

Expected: `package.json` and `package-lock.json` record `fflate`; production extension dependencies are unchanged.

- [ ] **Step 2: Include release tests in Vitest**

Update `vitest.config.ts` to include tool tests:

```ts
include: ['test/**/*.test.ts', 'src/**/*.test.ts', 'tools/**/*.test.mjs'],
```

- [ ] **Step 3: Write failing metadata tests**

Create `tools/release-lib.test.mjs` with assertions equivalent to:

```js
expect(resolveReleaseMetadata('v1.2.3', matchingVersions)).toEqual({
  tag: 'v1.2.3',
  version: '1.2.3',
  archiveName: 'vaultwarden-extension-v1.2.3.zip',
  prerelease: false,
});
expect(resolveReleaseMetadata('v1.2.3-beta.1', matchingVersions).prerelease).toBe(true);
expect(() => resolveReleaseMetadata('release-1.2.3', matchingVersions)).toThrow(/valid release tag/);
expect(() => resolveReleaseMetadata('v1.2.3', { ...matchingVersions, package: '1.2.4' })).toThrow(/package.json/);
expect(() => resolveReleaseMetadata('v1.2.3', { ...matchingVersions, sourceManifest: '1.2.4' })).toThrow(/src\/manifest.json/);
expect(() => resolveReleaseMetadata('v1.2.3', { ...matchingVersions, builtManifest: '1.2.4' })).toThrow(/dist\/manifest.json/);
```

- [ ] **Step 4: Run metadata tests and confirm failure**

Run:

```powershell
npm.cmd test -- tools/release-lib.test.mjs
```

Expected: FAIL because `tools/release-lib.mjs` does not exist.

- [ ] **Step 5: Implement strict metadata validation**

Create `tools/release-lib.mjs` using the strict pattern below and explicit source labels in mismatch errors:

```js
const TAG_PATTERN = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

export function resolveReleaseMetadata(tag, versions) {
  const match = TAG_PATTERN.exec(tag);
  if (!match) throw new Error(`"${tag}" is not a valid release tag`);
  const version = `${match[1]}.${match[2]}.${match[3]}`;
  for (const [source, actual] of Object.entries(versions)) {
    if (actual !== version) throw new Error(`${source} version ${actual} does not match tag version ${version}`);
  }
  return {
    tag,
    version,
    archiveName: `vaultwarden-extension-${tag}.zip`,
    prerelease: Boolean(match[4]),
  };
}
```

- [ ] **Step 6: Write failing package-contract tests**

Use temporary directories to create a minimal valid `dist` tree. Test that archive creation is byte-for-byte deterministic and verification accepts it. Mutate fixtures to assert rejection of:

```js
['extension/manifest.json', 'background.js.map', 'package.json', 'node_modules/example.js']
```

Also assert rejection of a missing `background.js`, a mismatched manifest version, absolute or parent-relative paths, duplicate normalized entries, and symbolic links.

- [ ] **Step 7: Run package tests and confirm failure**

Run:

```powershell
npm.cmd test -- tools/release-lib.test.mjs
```

Expected: metadata tests pass and archive tests fail because archive functions are missing.

- [ ] **Step 8: Implement deterministic packaging and archive verification**

Implement recursive collection with normalized `/` paths, sorted entries, fixed ZIP timestamps, regular-file-only input, and `fflate.zipSync`. Implement `verifyReleaseArchive` with `fflate.unzipSync`, JSON parsing, version checking, and these required paths:

```js
const REQUIRED_FILES = [
  'manifest.json',
  'background.js',
  'offscreen.html',
  'offscreen.js',
  'content/autofill.js',
  'content/page-webauthn.js',
  'content/webauthn-bridge.js',
  'ui/popup/popup.html',
  'ui/popup/popup.js',
  'ui/popup/popup.css',
  'ui/options/options.html',
  'ui/options/options.js',
  'ui/options/options.css',
  'ui/receive/receive.html',
  'ui/receive/receive.js',
  'ui/receive/receive.css',
  'icons/icon16.png',
  'icons/icon32.png',
  'icons/icon48.png',
  'icons/icon128.png',
];
```

Reject `.map` files, dotfiles, `node_modules/`, `src/`, `test/`, `tools/`, `docs/`, package manifests, lockfiles, and invalid archive paths. Implement streaming SHA-256 with `node:crypto`.

- [ ] **Step 9: Run focused and full tests**

Run:

```powershell
npm.cmd test -- tools/release-lib.test.mjs
npm.cmd test
npm.cmd run lint
```

Expected: all commands exit 0.

- [ ] **Step 10: Commit release contract module**

```powershell
git add -- package.json package-lock.json vitest.config.ts tools/release-lib.mjs tools/release-lib.test.mjs
git commit -m "build: add tested release package contract"
```

### Task 2: Release CLI and GitHub Actions workflow

**Files:**
- Create: `tools/release.mjs`
- Modify: `package.json`
- Replace: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: Task 1 release library functions.
- Produces: `npm run release:prepare -- --tag <tag> --out-dir <dir>` and GitHub outputs `tag`, `version`, `archive`, `archive_path`, `checksum_path`, and `prerelease`.

- [ ] **Step 1: Add failing CLI integration tests**

Extend `tools/release-lib.test.mjs` to invoke the CLI in a temporary fixture and assert that it creates the versioned ZIP and `SHA256SUMS.txt`, verifies the ZIP, and writes exact `key=value` lines to a temporary `GITHUB_OUTPUT` file. Add failure cases for a missing `--tag`, missing build directory, and mismatched versions.

- [ ] **Step 2: Run the CLI tests and confirm failure**

Run:

```powershell
npm.cmd test -- tools/release-lib.test.mjs
```

Expected: FAIL because `tools/release.mjs` does not exist.

- [ ] **Step 3: Implement the release CLI**

Implement argument parsing for `--tag`, `--dist-dir` (default `dist`), and `--out-dir` (default `release`). Read JSON with `JSON.parse`, call all Task 1 functions, recreate the output directory, write this checksum format, and append GitHub outputs only when `GITHUB_OUTPUT` exists:

```text
<lowercase sha256>  vaultwarden-extension-v1.2.3.zip
```

Print a human-readable asset summary without secrets. Add this package script:

```json
"release:prepare": "node tools/release.mjs"
```

- [ ] **Step 4: Run CLI and project gates locally**

Run against the current `0.1.0` build:

```powershell
npm.cmd run build:prod
npm.cmd run release:prepare -- --tag v0.1.0
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
```

Expected: `release/vaultwarden-extension-v0.1.0.zip` and `release/SHA256SUMS.txt` exist; all gates exit 0.

- [ ] **Step 5: Replace the release workflow**

Implement these workflow rules:

```yaml
on:
  push:
    tags: ['v[0-9]+.[0-9]+.[0-9]+', 'v[0-9]+.[0-9]+.[0-9]+-*']
  workflow_dispatch:
    inputs:
      tag:
        description: Existing release tag to rebuild and publish
        required: true
        type: string
permissions:
  contents: write
concurrency:
  group: release-${{ github.event_name == 'workflow_dispatch' && inputs.tag || github.ref_name }}
  cancel-in-progress: false
```

Set job `ref` from the tag push or dispatch input, check out that exact ref with `fetch-depth: 0`, and verify both `refs/tags/<tag>` existence and `git rev-parse HEAD` equality with `git rev-list -n 1 <tag>`. Run `npm ci`, lint, typecheck, tests, production build, and `release:prepare`. Upload the two release assets as a short-retention Actions artifact.

Publish idempotently with `gh`: verify an existing release's tag commit still equals `HEAD`, edit its title/prerelease state and upload assets with `--clobber`; otherwise create it with `--verify-tag`, `--target "$GITHUB_SHA"`, generated notes, and the prerelease flag. Pass all inputs through environment variables rather than interpolating them into shell source.

- [ ] **Step 6: Validate workflow syntax and behavior statically**

Parse `.github/workflows/release.yml` with a YAML parser and assert the exact triggers, permissions, checkout `ref`, quality gates, release preparation, artifact names, and publication commands. Search for removed bypasses:

```powershell
rg -n "allow_version_mismatch|git tag|git push" .github/workflows/release.yml
```

Expected: no matches.

- [ ] **Step 7: Commit CLI and workflow**

```powershell
git add -- tools/release.mjs tools/release-lib.test.mjs package.json package-lock.json .github/workflows/release.yml
git commit -m "ci: rebuild GitHub Release pipeline"
```

### Task 3: User-first README

**Files:**
- Replace: `README.md`

**Interfaces:**
- Consumes: the final asset names and behavior from Tasks 1 and 2.
- Produces: complete Chrome/Edge installation and maintenance documentation.

- [ ] **Step 1: Replace the README structure and copy**

Write the README in English with these sections and concrete content:

```text
# Native Vaultwarden Browser Extension
Unofficial status and short product description
Security/compatibility notice
## Features
## Requirements
## Install from GitHub Releases
### Verify the download on Windows
### Google Chrome
### Microsoft Edge
## First-time setup
## Update
## Troubleshooting
## Remove the extension
## Build from source
## Development
## Release for maintainers
## Security
## License
```

Link Releases to `https://github.com/moooyo/native-chrome-vaultwarden-extension/releases/latest`. Name `vaultwarden-extension-vX.Y.Z.zip` and `SHA256SUMS.txt` exactly. State that users must extract into a permanent folder, cannot drag the ZIP into the browser, must load that folder from `chrome://extensions` or `edge://extensions`, and receive no automatic updates.

Document Windows verification with:

```powershell
$expected = (Get-Content .\SHA256SUMS.txt).Split()[0]
$actual = (Get-FileHash .\vaultwarden-extension-vX.Y.Z.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 checksum mismatch" }
```

Document updating by replacing extracted files only after closing extension popups, then clicking Reload on the extension management page. Document first-time server URL setup, host permission approval, sign-in, and sync. Keep concise feature scope and known limitations, source build commands, and all release gates.

- [ ] **Step 2: Audit README against the actual package**

Verify every filename, browser URL, command, version source, and workflow behavior against Tasks 1 and 2. Search for stale milestone framing and unsupported claims:

```powershell
rg -n "M1-M3|M4 adds|Chrome Web Store|auto-update|drag" README.md
```

Expected: no milestone-led documentation; store, auto-update, and drag statements are accurate limitations rather than installation claims.

- [ ] **Step 3: Commit README**

```powershell
git add -- README.md
git commit -m "docs: rewrite installation and release guide"
```

### Task 4: End-to-end verification and completion audit

**Files:**
- Verify: all files changed by Tasks 1-3

**Interfaces:**
- Consumes: completed pipeline, package tool, tests, and README.
- Produces: authoritative evidence for every acceptance criterion.

- [ ] **Step 1: Run the complete repository gates**

```powershell
npm.cmd ci
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run build:prod
npm.cmd run release:prepare -- --tag v0.1.0
npm.cmd run test:ui
```

Expected: every command exits 0.

- [ ] **Step 2: Inspect the exact release assets**

```powershell
Get-FileHash .\release\vaultwarden-extension-v0.1.0.zip -Algorithm SHA256
Get-Content .\release\SHA256SUMS.txt
tar.exe -tf .\release\vaultwarden-extension-v0.1.0.zip
```

Expected: hashes agree; `manifest.json` is at archive root; all required runtime files exist; no `.map`, source, tests, tools, docs, package manifests, or wrapper directory appears.

- [ ] **Step 3: Audit workflow and documentation requirements**

Confirm from current files that tag push and existing-tag dispatch are the only release paths, tag movement is impossible, all gates precede publication, stable/prerelease handling is explicit, reruns clobber only assets on the same tag commit, and README covers Chrome, Edge, verification, setup, update, troubleshooting, removal, development, and maintainer release instructions.

- [ ] **Step 4: Check repository state and diff quality**

```powershell
git diff --check HEAD~3..HEAD
git status --short
git log -4 --oneline
```

Expected: no whitespace errors, no untracked release artifacts, and only intentional commits are present.
