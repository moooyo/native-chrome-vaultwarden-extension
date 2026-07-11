import { readFile } from 'node:fs/promises';

import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';

const workflowPath = new URL('../.github/workflows/release.yml', import.meta.url);

async function loadWorkflow() {
  const source = await readFile(workflowPath, 'utf8');
  return { source, workflow: parse(source) };
}

describe('release workflow', () => {
  it('only releases pushed tags or an explicitly selected existing tag', async () => {
    const { workflow } = await loadWorkflow();

    expect(workflow.on).toEqual({
      push: { tags: ['v[0-9]*.[0-9]*.[0-9]*'] },
      workflow_dispatch: {
        inputs: {
          tag: {
            description: 'Existing release tag to rebuild and publish',
            required: true,
            type: 'string',
          },
        },
      },
    });
    expect(workflow.permissions).toEqual({ contents: 'write' });
    expect(workflow.concurrency['cancel-in-progress']).toBe(false);
  });

  it('checks out the exact tag and runs every gate before preparing assets', async () => {
    const { workflow } = await loadWorkflow();
    const steps = workflow.jobs.release.steps;
    const checkout = steps.find((step) => step.name === 'Checkout release tag');
    const commands = steps.filter((step) => step.run).map((step) => step.run);

    expect(workflow.jobs.release.env.RELEASE_TAG).toContain('inputs.tag');
    expect(checkout.with).toMatchObject({
      ref: "${{ format('refs/tags/{0}', env.RELEASE_TAG) }}",
      'fetch-depth': 0,
    });
    expect(commands).toEqual(
      expect.arrayContaining([
        'npm ci',
        'npm run lint',
        'npm run typecheck',
        'npm test',
        'npm run build:prod',
        'npm run release:prepare -- --tag "$RELEASE_TAG"',
      ]),
    );
    const prepareIndex = steps.findIndex((step) => step.id === 'release');
    for (const gate of ['Lint', 'Type-check', 'Test', 'Build production extension']) {
      expect(steps.findIndex((step) => step.name === gate)).toBeLessThan(prepareIndex);
    }
  });

  it('uploads the verified assets and publishes idempotently without moving tags', async () => {
    const { source, workflow } = await loadWorkflow();
    const steps = workflow.jobs.release.steps;
    const artifact = steps.find((step) => step.name === 'Upload verified release assets');
    const publish = steps.find((step) => step.name === 'Publish GitHub Release');

    expect(artifact.with.path).toContain('${{ steps.release.outputs.archive_path }}');
    expect(artifact.with.path).toContain('${{ steps.release.outputs.checksum_path }}');
    expect(publish.run).toContain('gh release upload');
    expect(publish.run).toContain('--clobber');
    expect(publish.run).toContain('gh release create');
    expect(publish.run).toContain('--verify-tag');
    expect(publish.run).toContain('--generate-notes');
    expect(publish.run).toContain('PRERELEASE');
    expect(source).not.toMatch(/allow_version_mismatch/);
    expect(source).not.toMatch(/\bgit\s+(tag|push)\b/);
  });
});
