import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as https from 'https';
import * as path from 'path';
import { ALL_SKILLS, Platform, Skill } from './skills';

export const MANIFEST_FILENAME = '.ai-secure-rules.json';

const GITHUB_API_HOST = 'api.github.com';
const REPO = 'PanTechie/ai-secure-coding-rules';

// ── Types ──────────────────────────────────────────────────────────────────

export interface Manifest {
  version: '1';
  /** Platforms that have been installed */
  platforms: Platform[];
  /** skillKey → git blob SHA of rules.md (for update detection) */
  skillShas: Record<string, string>;
}

export type SkillStatus =
  | 'up-to-date'
  | 'outdated'
  | 'installed-unknown' // installed without manifest (e.g. via shell script)
  | 'not-installed';

export interface SkillInfo {
  skill: Skill;
  status: SkillStatus;
}

// ── Git blob SHA ───────────────────────────────────────────────────────────

/**
 * Compute the git blob SHA for a file's content string.
 * This matches what GitHub stores and returns from its API.
 */
export function blobSha(content: string): string {
  const buf = Buffer.from(content, 'utf8');
  const hash = crypto.createHash('sha1');
  hash.update(`blob ${buf.length}\0`);
  hash.update(buf);
  return hash.digest('hex');
}

// ── Manifest I/O ───────────────────────────────────────────────────────────

export async function readManifest(root: string): Promise<Manifest | null> {
  try {
    const raw = await fs.readFile(path.join(root, MANIFEST_FILENAME), 'utf8');
    return JSON.parse(raw) as Manifest;
  } catch {
    return null;
  }
}

export async function writeManifest(root: string, manifest: Manifest): Promise<void> {
  await fs.writeFile(
    path.join(root, MANIFEST_FILENAME),
    JSON.stringify(manifest, null, 2) + '\n',
    'utf8'
  );
}

// ── GitHub API ─────────────────────────────────────────────────────────────

interface GitTreeResponse {
  tree: Array<{ path: string; sha: string; type: string }>;
  truncated?: boolean;
}

function apiGet<T>(apiPath: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      {
        hostname: GITHUB_API_HOST,
        path: apiPath,
        headers: {
          'User-Agent': 'ai-secure-coding-rules-vscode/1.0',
          Accept: 'application/vnd.github.v3+json',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as T);
          } catch (e) {
            reject(e);
          }
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
  });
}

/**
 * Fetch all file paths and their git blob SHAs from the repo in a single API call.
 * GitHub rate limit: 60 unauthenticated requests/hour — this uses just one.
 */
export async function fetchRemoteShas(): Promise<Map<string, string>> {
  const data = await apiGet<GitTreeResponse>(
    `/repos/${REPO}/git/trees/main?recursive=1`
  );
  const map = new Map<string, string>();
  for (const item of data.tree) {
    if (item.type === 'blob') {
      map.set(item.path, item.sha);
    }
  }
  return map;
}

// ── Status checking ────────────────────────────────────────────────────────

async function directoryExists(dirPath: string): Promise<boolean> {
  try {
    await fs.access(dirPath);
    return true;
  } catch {
    return false;
  }
}

async function skillInstalledOnFilesystem(root: string, key: string): Promise<boolean> {
  // Check any platform that uses per-skill directories
  return (
    (await directoryExists(path.join(root, '.claude', 'skills', key))) ||
    (await directoryExists(path.join(root, '.agent', 'skills', key)))
  );
}

export async function getSkillStatuses(
  root: string,
  manifest: Manifest | null,
  remoteShas: Map<string, string>
): Promise<SkillInfo[]> {
  return Promise.all(
    ALL_SKILLS.map(async (skill): Promise<SkillInfo> => {
      const remoteSha = remoteShas.get(`.claude/skills/${skill.key}/rules.md`);

      if (manifest) {
        // Manifest is the authoritative source
        const localSha = manifest.skillShas[skill.key];
        if (!localSha) {
          return { skill, status: 'not-installed' };
        }
        if (!remoteSha || localSha === remoteSha) {
          return { skill, status: 'up-to-date' };
        }
        return { skill, status: 'outdated' };
      }

      // No manifest — fall back to filesystem check (installed via shell script)
      const exists = await skillInstalledOnFilesystem(root, skill.key);
      return { skill, status: exists ? 'installed-unknown' : 'not-installed' };
    })
  );
}
