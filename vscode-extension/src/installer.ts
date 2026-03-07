import * as fs from 'fs/promises';
import * as https from 'https';
import * as path from 'path';
import { Progress } from 'vscode';
import { Manifest, blobSha } from './manifest';
import { Platform, Skill, REPO_RAW } from './skills';

// ── Low-level helpers ──────────────────────────────────────────────────────

function downloadText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          const loc = res.headers.location;
          if (loc) {
            downloadText(loc).then(resolve).catch(reject);
          } else {
            reject(new Error(`Redirect with no location: ${url}`));
          }
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for: ${url}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

async function writeFile(filePath: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, 'utf8');
}

// ── Platform-specific installers ──────────────────────────────────────────

async function installClaude(
  target: string,
  skills: Skill[],
  shas: Record<string, string>,
  report: (msg: string) => void
): Promise<void> {
  const essentials = await downloadText(
    `${REPO_RAW}/.claude/rules/security-essentials.md`
  );
  await writeFile(
    path.join(target, '.claude', 'rules', 'security-essentials.md'),
    essentials
  );
  report('Claude: rules/security-essentials.md');

  for (const skill of skills) {
    const [skillMd, rulesMd] = await Promise.all([
      downloadText(`${REPO_RAW}/.claude/skills/${skill.key}/SKILL.md`),
      downloadText(`${REPO_RAW}/.claude/skills/${skill.key}/rules.md`),
    ]);
    const dir = path.join(target, '.claude', 'skills', skill.key);
    await Promise.all([
      writeFile(path.join(dir, 'SKILL.md'), skillMd),
      writeFile(path.join(dir, 'rules.md'), rulesMd),
    ]);
    // Track SHA for update detection (rules.md is canonical — same content across platforms)
    shas[skill.key] = blobSha(rulesMd);
    report(`Claude: skills/${skill.key}/`);
  }
}

async function installAgent(
  target: string,
  skills: Skill[],
  shas: Record<string, string>,
  report: (msg: string) => void
): Promise<void> {
  const essentials = await downloadText(
    `${REPO_RAW}/.agent/rules/security-essentials.md`
  );
  await writeFile(
    path.join(target, '.agent', 'rules', 'security-essentials.md'),
    essentials
  );
  report('Gemini: rules/security-essentials.md');

  for (const skill of skills) {
    const [skillMd, rulesMd] = await Promise.all([
      downloadText(`${REPO_RAW}/.agent/skills/${skill.key}/SKILL.md`),
      downloadText(`${REPO_RAW}/.agent/skills/${skill.key}/rules.md`),
    ]);
    const dir = path.join(target, '.agent', 'skills', skill.key);
    await Promise.all([
      writeFile(path.join(dir, 'SKILL.md'), skillMd),
      writeFile(path.join(dir, 'rules.md'), rulesMd),
    ]);
    if (!shas[skill.key]) {
      shas[skill.key] = blobSha(rulesMd);
    }
    report(`Gemini: skills/${skill.key}/`);
  }
}

async function installCursor(
  target: string,
  skills: Skill[],
  report: (msg: string) => void
): Promise<void> {
  const essentials = await downloadText(
    `${REPO_RAW}/.cursor/rules/security-essentials.mdc`
  );
  await writeFile(
    path.join(target, '.cursor', 'rules', 'security-essentials.mdc'),
    essentials
  );
  report('Cursor: rules/security-essentials.mdc');

  const FRONTMATTER = '---\nalwaysApply: true\n---\n';
  for (const skill of skills) {
    const content = await downloadText(`${REPO_RAW}/standards/${skill.stdFile}`);
    const mdcName = skill.stdFile.replace(/\.md$/, '.mdc');
    await writeFile(
      path.join(target, '.cursor', 'rules', mdcName),
      FRONTMATTER + content
    );
    report(`Cursor: rules/${mdcName}`);
  }
}

async function installCodex(
  target: string,
  report: (msg: string) => void
): Promise<void> {
  const content = await downloadText(`${REPO_RAW}/AGENTS.md`);
  await writeFile(path.join(target, 'AGENTS.md'), content);
  report('Codex: AGENTS.md');
}

// ── Public: install ────────────────────────────────────────────────────────

export async function install(
  platforms: Platform[],
  skills: Skill[],
  targetDir: string,
  progress: Progress<{ message?: string }>,
  existingManifest: Manifest | null
): Promise<Manifest> {
  const report = (msg: string): void => progress.report({ message: msg });
  const shas: Record<string, string> = { ...(existingManifest?.skillShas ?? {}) };

  for (const platform of platforms) {
    switch (platform) {
      case 'claude':
        await installClaude(targetDir, skills, shas, report);
        break;
      case 'agent':
        await installAgent(targetDir, skills, shas, report);
        break;
      case 'cursor':
        await installCursor(targetDir, skills, report);
        break;
      case 'codex':
        await installCodex(targetDir, report);
        break;
    }
  }

  // Merge installed platforms into manifest
  const prevPlatforms = existingManifest?.platforms ?? [];
  const allPlatforms = [...new Set([...prevPlatforms, ...platforms])] as Platform[];

  return {
    version: '1',
    platforms: allPlatforms,
    skillShas: shas,
  };
}

// ── Public: remove ─────────────────────────────────────────────────────────

export async function removeSkills(
  skills: Skill[],
  targetDir: string,
  progress: Progress<{ message?: string }>,
  existingManifest: Manifest | null
): Promise<Manifest> {
  const report = (msg: string): void => progress.report({ message: msg });
  const shas = { ...(existingManifest?.skillShas ?? {}) };

  for (const skill of skills) {
    // Remove from Claude
    const claudeDir = path.join(targetDir, '.claude', 'skills', skill.key);
    try {
      await fs.rm(claudeDir, { recursive: true, force: true });
      report(`Removed: .claude/skills/${skill.key}/`);
    } catch {
      // Directory may not exist — ignore
    }

    // Remove from Agent
    const agentDir = path.join(targetDir, '.agent', 'skills', skill.key);
    try {
      await fs.rm(agentDir, { recursive: true, force: true });
      report(`Removed: .agent/skills/${skill.key}/`);
    } catch {
      // Directory may not exist — ignore
    }

    // Remove from Cursor (.mdc file)
    const mdcFile = path.join(
      targetDir,
      '.cursor',
      'rules',
      skill.stdFile.replace(/\.md$/, '.mdc')
    );
    try {
      await fs.rm(mdcFile, { force: true });
      report(`Removed: .cursor/rules/${skill.stdFile.replace(/\.md$/, '.mdc')}`);
    } catch {
      // File may not exist — ignore
    }

    delete shas[skill.key];
  }

  return {
    version: '1',
    platforms: existingManifest?.platforms ?? [],
    skillShas: shas,
  };
}
