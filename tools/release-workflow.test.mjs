import { readFile } from 'node:fs/promises';

import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';

const releaseWorkflowPath = new URL('../.github/workflows/release.yml', import.meta.url);
const ciWorkflowPath = new URL('../.github/workflows/ci.yml', import.meta.url);

async function loadWorkflow(path) {
  const source = await readFile(path, 'utf8');
  return { source, workflow: parse(source) };
}

describe('release workflow', () => {
  it('only releases pushed tags or an explicitly selected existing tag', async () => {
    const { workflow } = await loadWorkflow(releaseWorkflowPath);

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
    expect(workflow.permissions).toEqual({ contents: 'read' });
    expect(workflow.concurrency['cancel-in-progress']).toBe(false);
  });

  it('checks out the exact tag without credentials and runs every gate in a read-only job', async () => {
    const { workflow } = await loadWorkflow(releaseWorkflowPath);
    const verify = workflow.jobs.verify;
    const steps = verify.steps;
    const checkout = steps.find((step) => step.name === 'Checkout release tag');
    const commands = steps.filter((step) => step.run).map((step) => step.run);

    expect(verify.permissions).toEqual({ contents: 'read' });
    expect(verify.env.RELEASE_TAG).toContain('inputs.tag');
    expect(checkout.with).toMatchObject({
      ref: "${{ format('refs/tags/{0}', env.RELEASE_TAG) }}",
      'fetch-depth': 0,
      'persist-credentials': false,
    });
    expect(commands).toEqual(
      expect.arrayContaining([
        'npm ci',
        'npx playwright install --with-deps chromium',
        'sudo apt-get install --no-install-recommends --yes xauth',
        'npm run lint',
        'npm run typecheck',
        'npm test',
        'npm run build:prod',
        'xvfb-run --auto-servernum npm run verify:render',
        'xvfb-run --auto-servernum npm run verify:binary-transport-browser',
        'npm run release:prepare -- --tag "$RELEASE_TAG"',
      ]),
    );
    const prepareIndex = steps.findIndex((step) => step.id === 'release');
    for (const gate of ['Lint', 'Type-check', 'Test', 'Build production extension', 'Chromium render smoke', 'Chromium binary transport gate']) {
      expect(steps.findIndex((step) => step.name === gate)).toBeLessThan(prepareIndex);
    }
  });

  it('publishes in a separate write-only job without a checkout or npm execution', async () => {
    const { workflow } = await loadWorkflow(releaseWorkflowPath);
    const publish = workflow.jobs.publish;
    const actionNames = publish.steps.filter((step) => step.uses).map((step) => step.uses);
    const commands = publish.steps.filter((step) => step.run).map((step) => step.run);

    expect(publish.needs).toBe('verify');
    expect(publish.permissions).toEqual({ contents: 'write' });
    expect(actionNames.some((name) => name.startsWith('actions/download-artifact@'))).toBe(true);
    expect(actionNames.some((name) => name.startsWith('actions/checkout@'))).toBe(false);
    expect(actionNames.some((name) => name.startsWith('actions/setup-node@'))).toBe(false);
    expect(commands.join('\n')).not.toMatch(/\bnpm\b/);
  });

  it('treats an existing release as immutable and only accepts an exact match', async () => {
    const { source, workflow } = await loadWorkflow(releaseWorkflowPath);
    const verifySteps = workflow.jobs.verify.steps;
    const upload = verifySteps.find((step) => step.name === 'Upload verified release assets');
    const publish = workflow.jobs.publish.steps.find((step) => step.name === 'Publish immutable GitHub Release');

    expect(upload.with.path).toContain('${{ steps.release.outputs.archive_path }}');
    expect(upload.with.path).toContain('${{ steps.release.outputs.checksum_path }}');
    expect(publish.run).toContain('repos/$GITHUB_REPOSITORY/commits/$TAG');
    expect(publish.run).toContain('repos/$GITHUB_REPOSITORY/releases/tags/$TAG');
    expect(publish.run).toContain("jq -r .tag_name");
    expect(publish.run).toContain("jq -r .prerelease");
    expect(publish.run).toContain("jq -r '.assets[].name'");
    expect(publish.run).toContain('remote_digest');
    expect(publish.run).toContain('local_digest');
    expect(publish.run).toContain('nothing to publish');
    expect(publish.run.match(/--repo "\$GITHUB_REPOSITORY"/g)).toHaveLength(2);
    expect(publish.run).toContain('gh release create');
    expect(publish.run).toContain('--verify-tag');
    expect(publish.run).toContain('--generate-notes');
    expect(source).not.toContain('--clobber');
    expect(source).not.toContain('gh release edit');
    expect(source).not.toContain('gh release upload');
    expect(source).not.toMatch(/allow_version_mismatch/);
    expect(source).not.toMatch(/\bgit\s+(tag|push)\b/);
  });
});

describe('CI workflow', () => {
  it('smokes the production build in Chromium without persisting checkout credentials', async () => {
    const { workflow } = await loadWorkflow(ciWorkflowPath);
    const steps = workflow.jobs.verify.steps;
    const checkout = steps.find((step) => step.name === 'Checkout');
    const buildIndex = steps.findIndex((step) => step.name === 'Build (production)');
    const smokeIndex = steps.findIndex((step) => step.name === 'Chromium render smoke');

    expect(workflow.permissions).toEqual({ contents: 'read' });
    expect(checkout.with['persist-credentials']).toBe(false);
    expect(steps.find((step) => step.name === 'Install Chromium').run).toBe(
      'npx playwright install --with-deps chromium',
    );
    expect(steps.find((step) => step.name === 'Install Xvfb authentication helper').run).toBe(
      'sudo apt-get install --no-install-recommends --yes xauth',
    );
    expect(steps[smokeIndex].run).toBe('xvfb-run --auto-servernum npm run verify:render');
    expect(smokeIndex).toBeGreaterThan(buildIndex);
  });
});
