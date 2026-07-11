import { appendFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';

import {
  createReleaseArchive,
  resolveReleaseMetadata,
  sha256File,
  verifyReleaseArchive,
} from './release-lib.mjs';

function parseArguments(args) {
  const options = { distDir: 'dist', outDir: 'release' };
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    const value = args[index + 1];
    if (!['--tag', '--dist-dir', '--out-dir'].includes(name) || value === undefined || value.startsWith('--')) {
      throw new Error(`Unknown or incomplete argument: ${name}`);
    }
    if (name === '--tag') options.tag = value;
    if (name === '--dist-dir') options.distDir = value;
    if (name === '--out-dir') options.outDir = value;
    index += 1;
  }
  if (!options.tag) throw new Error('Missing required --tag');
  return options;
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

function absolutePath(path) {
  return (isAbsolute(path) ? path : resolve(path)).replaceAll('\\', '/');
}

async function prepareRelease() {
  const options = parseArguments(process.argv.slice(2));
  const distDir = resolve(options.distDir);
  const outDir = resolve(options.outDir);
  const packageJson = await readJson(resolve('package.json'));
  const sourceManifest = await readJson(resolve('src', 'manifest.json'));
  const builtManifest = await readJson(join(distDir, 'manifest.json'));
  const metadata = resolveReleaseMetadata(options.tag, {
    'package.json': packageJson.version,
    'src/manifest.json': sourceManifest.version,
    'dist/manifest.json': builtManifest.version,
  });

  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });
  const archivePath = join(outDir, metadata.archiveName);
  const checksumPath = join(outDir, 'SHA256SUMS.txt');
  await createReleaseArchive({ sourceDir: distDir, archivePath });
  const packageSummary = await verifyReleaseArchive({ archivePath, expectedVersion: metadata.version });
  const sha256 = await sha256File(archivePath);
  await writeFile(checksumPath, `${sha256}  ${metadata.archiveName}\n`);

  const outputs = {
    tag: metadata.tag,
    version: metadata.version,
    archive: metadata.archiveName,
    archive_path: absolutePath(archivePath),
    checksum_path: absolutePath(checksumPath),
    prerelease: String(metadata.prerelease),
  };
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `${Object.entries(outputs).map(([key, value]) => `${key}=${value}`).join('\n')}\n`);
  }

  console.log(`Prepared ${metadata.archiveName}`);
  console.log(`Version: ${packageSummary.version}`);
  console.log(`Files: ${packageSummary.files}`);
  console.log(`SHA-256: ${sha256}`);
}

prepareRelease().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
