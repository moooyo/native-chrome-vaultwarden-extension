import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { unzipSync, zipSync } from 'fflate';

const TAG_PATTERN = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

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

const FIXED_ZIP_DATE = new Date('2000-01-01T00:00:00.000Z');
const FORBIDDEN_ROOTS = new Set(['node_modules', 'src', 'test', 'tools', 'docs']);
const FORBIDDEN_FILES = new Set(['package.json', 'package-lock.json', 'npm-shrinkwrap.json']);

export function resolveReleaseMetadata(tag, versions) {
  const match = TAG_PATTERN.exec(tag);
  if (!match) {
    throw new Error(`"${tag}" is not a valid release tag`);
  }

  const version = `${match[1]}.${match[2]}.${match[3]}`;
  for (const [source, actual] of Object.entries(versions)) {
    if (actual !== version) {
      throw new Error(`${source} version ${actual} does not match tag version ${version}`);
    }
  }

  return {
    tag,
    version,
    archiveName: `vaultwarden-extension-${tag}.zip`,
    prerelease: Boolean(match[4]),
  };
}

function normalizedArchivePath(path) {
  const normalized = path.replaceAll('\\', '/');
  if (
    normalized.startsWith('/') ||
    /^[A-Za-z]:\//.test(normalized) ||
    normalized.split('/').some((segment) => segment === '..' || segment === '')
  ) {
    throw new Error(`invalid archive path: ${path}`);
  }
  return normalized;
}

function assertAllowedArchivePath(path) {
  const firstSegment = path.split('/')[0];
  if (
    path.endsWith('.map') ||
    path.split('/').some((segment) => segment.startsWith('.')) ||
    FORBIDDEN_ROOTS.has(firstSegment) ||
    FORBIDDEN_FILES.has(path)
  ) {
    throw new Error(`forbidden file in release archive: ${path}`);
  }
}

async function collectFiles(root, relativeDirectory = '') {
  const absoluteDirectory = relativeDirectory ? join(root, ...relativeDirectory.split('/')) : root;
  const directoryEntries = await readdir(absoluteDirectory, { withFileTypes: true });
  const files = [];

  for (const entry of directoryEntries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relativePath = relativeDirectory ? `${relativeDirectory}/${entry.name}` : entry.name;
    const absolutePath = join(root, ...relativePath.split('/'));
    const stats = await lstat(absolutePath);
    if (stats.isSymbolicLink()) {
      throw new Error(`symbolic links are not allowed in release input: ${relativePath}`);
    }
    if (stats.isDirectory()) {
      files.push(...(await collectFiles(root, relativePath)));
      continue;
    }
    if (!stats.isFile()) {
      throw new Error(`only regular files are allowed in release input: ${relativePath}`);
    }
    assertAllowedArchivePath(relativePath);
    files.push(relativePath);
  }

  return files;
}

export async function createReleaseArchive({ sourceDir, archivePath }) {
  const files = await collectFiles(sourceDir);
  const archiveEntries = {};
  for (const path of files.sort()) {
    archiveEntries[path] = [await readFile(join(sourceDir, ...path.split('/'))), { mtime: FIXED_ZIP_DATE }];
  }

  await mkdir(dirname(archivePath), { recursive: true });
  await writeFile(archivePath, zipSync(archiveEntries, { level: 9 }));
}

export async function verifyReleaseArchive({ archivePath, expectedVersion }) {
  const rawEntries = unzipSync(await readFile(archivePath));
  const entries = new Map();

  for (const [rawPath, contents] of Object.entries(rawEntries)) {
    const path = normalizedArchivePath(rawPath);
    if (entries.has(path)) {
      throw new Error(`duplicate archive path after normalization: ${path}`);
    }
    assertAllowedArchivePath(path);
    entries.set(path, contents);
  }

  if (!entries.has('manifest.json')) {
    throw new Error('manifest.json must be at the archive root');
  }

  for (const path of REQUIRED_FILES) {
    if (!entries.has(path)) {
      throw new Error(`missing required file: ${path}`);
    }
  }

  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(entries.get('manifest.json')));
  } catch (error) {
    throw new Error('archive manifest.json is not valid JSON', { cause: error });
  }
  if (manifest.version !== expectedVersion) {
    throw new Error(
      `archive manifest version ${String(manifest.version)} does not match release version ${expectedVersion}`,
    );
  }

  return { version: manifest.version, files: entries.size };
}

export async function sha256File(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest('hex');
}
