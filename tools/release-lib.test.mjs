import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';

import {
  createReleaseArchive,
  resolveReleaseMetadata,
  sha256File,
  verifyReleaseArchive,
} from './release-lib.mjs';

const matchingVersions = {
  'package.json': '1.2.3',
  'src/manifest.json': '1.2.3',
  'dist/manifest.json': '1.2.3',
};
const execFileAsync = promisify(execFile);

const requiredFiles = [
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

async function createRuntimeTree(root, version = '1.2.3') {
  await rm(root, { recursive: true, force: true });
  for (const path of requiredFiles) {
    const absolutePath = join(root, ...path.split('/'));
    await mkdir(join(absolutePath, '..'), { recursive: true });
    const content = path === 'manifest.json' ? JSON.stringify({ manifest_version: 3, version }) : path;
    await writeFile(absolutePath, content);
  }
}

async function createZip(path, entries) {
  await mkdir(join(path, '..'), { recursive: true });
  const archive = zipSync(
    Object.fromEntries(Object.entries(entries).map(([name, value]) => [name, new TextEncoder().encode(value)])),
  );
  await writeFile(path, archive);
}

async function createReleaseProject(root, version = '1.2.3') {
  await rm(root, { recursive: true, force: true });
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'package.json'), JSON.stringify({ version }));
  await writeFile(join(root, 'src', 'manifest.json'), JSON.stringify({ version }));
  await createRuntimeTree(join(root, 'dist'), version);
}

describe('resolveReleaseMetadata', () => {
  it('resolves a stable release tag', () => {
    expect(resolveReleaseMetadata('v1.2.3', matchingVersions)).toEqual({
      tag: 'v1.2.3',
      version: '1.2.3',
      archiveName: 'vaultwarden-extension-v1.2.3.zip',
      prerelease: false,
    });
  });

  it('marks a valid prerelease tag', () => {
    expect(resolveReleaseMetadata('v1.2.3-beta.1', matchingVersions)).toEqual({
      tag: 'v1.2.3-beta.1',
      version: '1.2.3',
      archiveName: 'vaultwarden-extension-v1.2.3-beta.1.zip',
      prerelease: true,
    });
  });

  it.each([
    '',
    '1.2.3',
    'release-1.2.3',
    'v1.2',
    'v01.2.3',
    'v1.02.3',
    'v1.2.03',
    'v1.2.3+build',
    'v1.2.3-',
    'v1.2.3-beta..1',
  ])('rejects invalid tag %j', (tag) => {
    expect(() => resolveReleaseMetadata(tag, matchingVersions)).toThrow('valid release tag');
  });

  it.each(Object.keys(matchingVersions))('rejects a mismatch in %s', (source) => {
    expect(() =>
      resolveReleaseMetadata('v1.2.3', {
        ...matchingVersions,
        [source]: '1.2.4',
      }),
    ).toThrow(`${source} version 1.2.4 does not match tag version 1.2.3`);
  });
});

describe('release archive contract', () => {
  it('creates a deterministic root-manifest archive and verifies every runtime file', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-valid');
    const distDir = join(root, 'dist');
    const firstArchive = join(root, 'first.zip');
    const secondArchive = join(root, 'second.zip');
    await createRuntimeTree(distDir);

    await createReleaseArchive({ sourceDir: distDir, archivePath: firstArchive });
    await createReleaseArchive({ sourceDir: distDir, archivePath: secondArchive });

    expect(await readFile(firstArchive)).toEqual(await readFile(secondArchive));
    expect(await verifyReleaseArchive({ archivePath: firstArchive, expectedVersion: '1.2.3' })).toEqual({
      version: '1.2.3',
      files: requiredFiles.length,
    });
  });

  it('computes the SHA-256 digest of the archive', async () => {
    const path = join(import.meta.dirname, '..', 'test-results', 'release-sha.txt');
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, 'release bytes');

    expect(await sha256File(path)).toBe(createHash('sha256').update('release bytes').digest('hex'));
  });

  it.each([
    ['wrapped archive', { 'extension/manifest.json': '{}' }, /manifest.json must be at the archive root/],
    ['source map', { 'manifest.json': '{"version":"1.2.3"}', 'background.js.map': '{}' }, /forbidden file/],
    ['package manifest', { 'manifest.json': '{"version":"1.2.3"}', 'package.json': '{}' }, /forbidden file/],
    ['development dependency', { 'manifest.json': '{"version":"1.2.3"}', 'node_modules/example.js': '' }, /forbidden file/],
    ['parent path', { 'manifest.json': '{"version":"1.2.3"}', '../escape.js': '' }, /invalid archive path/],
    ['absolute path', { 'manifest.json': '{"version":"1.2.3"}', '/escape.js': '' }, /invalid archive path/],
    ['duplicate normalized path', { 'manifest.json': '{"version":"1.2.3"}', 'icons\\icon16.png': '', 'icons/icon16.png': '' }, /duplicate archive path/],
  ])('rejects a %s', async (_name, entries, error) => {
    const path = join(import.meta.dirname, '..', 'test-results', `release-invalid-${_name.replaceAll(' ', '-')}.zip`);
    await mkdir(join(path, '..'), { recursive: true });
    await createZip(path, entries);

    await expect(verifyReleaseArchive({ archivePath: path, expectedVersion: '1.2.3' })).rejects.toThrow(error);
  });

  it('rejects a missing required runtime file', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-missing');
    const archivePath = join(root, 'missing.zip');
    await createZip(archivePath, { 'manifest.json': '{"version":"1.2.3"}' });

    await expect(verifyReleaseArchive({ archivePath, expectedVersion: '1.2.3' })).rejects.toThrow(
      'missing required file: background.js',
    );
  });

  it('rejects a built manifest version mismatch', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-version');
    const distDir = join(root, 'dist');
    const archivePath = join(root, 'version.zip');
    await createRuntimeTree(distDir, '1.2.4');
    await createReleaseArchive({ sourceDir: distDir, archivePath });

    await expect(verifyReleaseArchive({ archivePath, expectedVersion: '1.2.3' })).rejects.toThrow(
      'archive manifest version 1.2.4 does not match release version 1.2.3',
    );
  });

  it('rejects symbolic links in the source tree', async (context) => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-symlink');
    const distDir = join(root, 'dist');
    await createRuntimeTree(distDir);
    try {
      await symlink(join(distDir, 'background.js'), join(distDir, 'linked.js'));
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'EPERM') {
        context.skip();
        return;
      }
      throw error;
    }

    await expect(
      createReleaseArchive({ sourceDir: distDir, archivePath: join(root, 'symlink.zip') }),
    ).rejects.toThrow('symbolic links are not allowed');
  });
});

describe('release CLI', () => {
  const cliPath = join(import.meta.dirname, 'release.mjs');

  it('creates verified assets and writes GitHub outputs', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-cli-valid');
    const outputPath = join(root, 'github-output.txt');
    await createReleaseProject(root);

    await execFileAsync(
      process.execPath,
      [cliPath, '--tag', 'v1.2.3', '--dist-dir', 'dist', '--out-dir', 'release'],
      { cwd: root, env: { ...process.env, GITHUB_OUTPUT: outputPath } },
    );

    const archivePath = join(root, 'release', 'vaultwarden-extension-v1.2.3.zip');
    const checksumPath = join(root, 'release', 'SHA256SUMS.txt');
    expect(await verifyReleaseArchive({ archivePath, expectedVersion: '1.2.3' })).toEqual({
      version: '1.2.3',
      files: requiredFiles.length,
    });
    expect(await readFile(checksumPath, 'utf8')).toBe(`${await sha256File(archivePath)}  vaultwarden-extension-v1.2.3.zip\n`);
    expect((await readFile(outputPath, 'utf8')).trim().split(/\r?\n/)).toEqual([
      'tag=v1.2.3',
      'version=1.2.3',
      'archive=vaultwarden-extension-v1.2.3.zip',
      `archive_path=${archivePath.replaceAll('\\', '/')}`,
      `checksum_path=${checksumPath.replaceAll('\\', '/')}`,
      'prerelease=false',
    ]);
  });

  it('fails when --tag is missing', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-cli-no-tag');
    await createReleaseProject(root);

    await expect(execFileAsync(process.execPath, [cliPath], { cwd: root })).rejects.toMatchObject({
      stderr: expect.stringContaining('Missing required --tag'),
    });
  });

  it('fails when the build directory is missing', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-cli-no-dist');
    await createReleaseProject(root);
    await rm(join(root, 'dist'), { recursive: true });

    await expect(execFileAsync(process.execPath, [cliPath, '--tag', 'v1.2.3'], { cwd: root })).rejects.toMatchObject({
      stderr: expect.stringContaining('dist'),
    });
  });

  it('fails when source versions do not match the tag', async () => {
    const root = join(import.meta.dirname, '..', 'test-results', 'release-cli-version');
    await createReleaseProject(root);
    await writeFile(join(root, 'src', 'manifest.json'), JSON.stringify({ version: '1.2.4' }));

    await expect(execFileAsync(process.execPath, [cliPath, '--tag', 'v1.2.3'], { cwd: root })).rejects.toMatchObject({
      stderr: expect.stringContaining('src/manifest.json version 1.2.4 does not match tag version 1.2.3'),
    });
  });
});
