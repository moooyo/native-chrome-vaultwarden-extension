# GitHub Release Pipeline and Installation Documentation Design

## Status

Approved by the user on 2026-07-11.

## Goal

Provide a fail-closed release process that builds the browser extension from an
immutable semantic-version tag, verifies the exact package users will install,
and publishes that package with a SHA-256 checksum to GitHub Releases. Replace
the development-first README with user-first installation, update, verification,
and maintenance instructions.

## Release Contract

Git tags are the only version and release trigger. A release tag must use strict
Semantic Versioning with a leading `v`, such as `v0.2.0` or
`v0.2.0-beta.1`. A tag push starts a release. Manual dispatch may rerun an
existing tag, but it must never create, move, or reinterpret a tag.

The release commit must contain the same numeric version in `package.json` and
`src/manifest.json`. That version must equal the release tag without its leading
`v` and without any prerelease suffix because Chrome extension manifest versions
cannot contain Semantic Versioning prerelease identifiers. Version mismatches
are fatal and cannot be overridden.

The workflow grants only `contents: write`, uses a per-tag concurrency group,
and never cancels a release already in progress. All third-party actions are
pinned to immutable commit SHAs.

## Build and Package Flow

The release job checks out the exact tag commit and then:

1. installs dependencies with `npm ci` on Node.js 22;
2. runs lint, TypeScript checks, and the complete Vitest suite;
3. runs the production build and existing shipped-shape assertions;
4. validates tag, package version, source manifest version, and built manifest
   version before packaging;
5. creates `vaultwarden-extension-<tag>.zip` with `manifest.json` at the archive
   root and excludes source maps;
6. extracts the archive into a clean directory and validates the extracted
   manifest, required runtime files, version, archive root shape, and absence of
   source maps or development-only content;
7. creates `SHA256SUMS.txt` containing the archive checksum;
8. publishes both files to the GitHub Release for the exact existing tag.

Stable tags create normal releases. Tags with a prerelease suffix create GitHub
prereleases. GitHub-generated release notes describe changes between tags. A
rerun must update the existing release assets instead of failing because the
release already exists, while preserving the immutable tag target.

## Verification Boundary

A repository script owns release metadata and package verification so the same
checks can run locally and in GitHub Actions. It accepts an explicit tag and
archive path, uses structured JSON and ZIP APIs, and produces machine-readable
metadata for the workflow. It fails on malformed tags, version disagreement,
missing runtime files, an extra top-level wrapper directory, source maps,
development files, or unexpected symlinks.

Focused automated tests cover stable and prerelease tags, invalid tags, every
version mismatch, valid archives, wrapped archives, missing files, and forbidden
files. The release workflow remains orchestration rather than embedding complex
validation in shell strings.

## README Information Architecture

The README starts with what the extension is, its unofficial status, supported
Chromium browsers, and security/compatibility limitations. The primary path is
installation from GitHub Releases:

1. download the versioned ZIP and optionally `SHA256SUMS.txt`;
2. verify SHA-256 on Windows;
3. extract the ZIP to a permanent folder;
4. open the extension management page in Chrome or Edge;
5. enable Developer mode and load the extracted folder;
6. configure the Vaultwarden server URL and approve host access;
7. sign in and perform an initial sync.

The README explicitly states that the ZIP cannot be installed by dragging it
into the browser, the unpacked folder must not be deleted, the extension is not
store-signed, and GitHub-installed unpacked extensions do not auto-update.

Separate sections explain manual updates, troubleshooting, removal, source
builds, development commands, project scope, security reporting, and the
maintainer release procedure. The release procedure requires updating both
version files, passing all gates, committing, and pushing an annotated matching
tag.

## Error Handling

Every validation error identifies the conflicting values or offending archive
entry and exits before a release is created or modified. Publishing occurs only
after all quality and package verification gates pass. A failed rerun leaves an
existing release untouched until asset replacement begins.

## Acceptance Criteria

1. Pushing a valid matching `vMAJOR.MINOR.PATCH[-PRERELEASE]` tag publishes a
   GitHub Release for that exact tag.
2. Manual dispatch accepts only an existing tag and cannot create or move tags.
3. Package, source manifest, built manifest, and tag versions must agree with no
   bypass.
4. Lint, typecheck, unit tests, production build, and package verification pass
   before publication.
5. The Release contains a root-manifest installation ZIP and
   `SHA256SUMS.txt`.
6. The exact extracted ZIP is checked for runtime completeness and forbidden
   content.
7. Prerelease tags are marked as GitHub prereleases, and reruns safely replace
   release assets for the same immutable tag.
8. README installation steps are complete for Chrome and Edge and clearly cover
   extraction, Developer mode, initial configuration, updates, verification,
   removal, and lack of automatic updates.
9. README retains concise project scope, source-build, test, and maintainer
   release instructions without presenting milestone history as the primary
   user documentation.
