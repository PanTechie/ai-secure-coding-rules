import * as vscode from 'vscode';
import { ALL_SKILLS, PLATFORM_ITEMS, PlatformItem, Platform, Skill } from './skills';
import { install, removeSkills } from './installer';
import {
  Manifest,
  SkillInfo,
  SkillStatus,
  readManifest,
  writeManifest,
  fetchRemoteShas,
  getSkillStatuses,
} from './manifest';

// ── Shared helpers ──────────────────────────────────────────────────────────

const ALL_SKILLS_ITEM: vscode.QuickPickItem = {
  label: '$(check-all) All skills',
  description: `all ${ALL_SKILLS.length} skill files`,
  detail: 'API, ASVS, CWE, IaC, JS/TS, LLM, Mobile, PHP, Privacy, Python3, SbD, Secrets, Web, C#, JVM, Clojure, Ruby',
  alwaysShow: true,
};

const NONE_ITEM: vscode.QuickPickItem = {
  label: '$(circle-slash) None — essentials only',
  description: 'skip all skills',
  detail: 'Only security-essentials.md will be installed',
  alwaysShow: true,
};

function skillToItem(skill: Skill): vscode.QuickPickItem {
  return {
    label: skill.label,
    description: skill.key,
    detail: skill.detail,
  };
}

function statusIcon(status: SkillStatus): string {
  switch (status) {
    case 'up-to-date':        return '$(check)';
    case 'outdated':          return '$(arrow-up)';
    case 'installed-unknown': return '$(question)';
    case 'not-installed':     return '$(circle-slash)';
  }
}

function statusLabel(status: SkillStatus): string {
  switch (status) {
    case 'up-to-date':        return 'Up-to-date';
    case 'outdated':          return 'Update available';
    case 'installed-unknown': return 'Installed (version unknown)';
    case 'not-installed':     return 'Not installed';
  }
}

interface SkillPickItem extends vscode.QuickPickItem {
  skillInfo: SkillInfo;
}

function skillInfoToItem(info: SkillInfo): SkillPickItem {
  return {
    label: `${statusIcon(info.status)} ${info.skill.label}`,
    description: info.skill.key,
    detail: `${statusLabel(info.status)} — ${info.skill.detail}`,
    skillInfo: info,
  };
}

function platformLabel(id: Platform): string {
  return PLATFORM_ITEMS.find((i) => i.id === id)?.label.replace(/\$\(\w+\)\s*/, '') ?? id;
}

function getWorkspaceDir(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showErrorMessage('AI Secure Coding Rules: Open a workspace folder first.');
    return undefined;
  }
  return folders[0].uri.fsPath;
}

// ── Command: Install ────────────────────────────────────────────────────────

async function runInstallCommand(targetDir: string): Promise<void> {
  // Step 1: Platform selection
  const platformPicks = await vscode.window.showQuickPick(PLATFORM_ITEMS, {
    title: 'AI Secure Coding Rules — Step 1 of 2: Select platforms',
    placeHolder: 'Select one or more AI assistant platforms',
    canPickMany: true,
    ignoreFocusOut: true,
  });

  if (!platformPicks || platformPicks.length === 0) return;

  const platforms = (platformPicks as PlatformItem[]).map((p) => p.id as Platform);

  // Step 2: Skill selection
  const skillItems: vscode.QuickPickItem[] = [
    ALL_SKILLS_ITEM,
    NONE_ITEM,
    { label: '', kind: vscode.QuickPickItemKind.Separator },
    ...ALL_SKILLS.map(skillToItem),
  ];

  const skillPicks = await vscode.window.showQuickPick(skillItems, {
    title: 'AI Secure Coding Rules — Step 2 of 2: Select skills',
    placeHolder: 'security-essentials is always included',
    canPickMany: true,
    ignoreFocusOut: true,
  });

  if (skillPicks === undefined) return;

  let selectedSkills: Skill[];
  if (skillPicks.length === 0 || skillPicks.some((p) => p === NONE_ITEM)) {
    selectedSkills = [];
  } else if (skillPicks.some((p) => p === ALL_SKILLS_ITEM)) {
    selectedSkills = ALL_SKILLS;
  } else {
    const pickedKeys = new Set(skillPicks.map((p) => p.description));
    selectedSkills = ALL_SKILLS.filter((s) => pickedKeys.has(s.key));
  }

  // Step 3: Download, install, and write manifest
  const existingManifest = await readManifest(targetDir);

  const updatedManifest = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Installing AI Secure Coding Rules…',
      cancellable: false,
    },
    (progress) => install(platforms, selectedSkills, targetDir, progress, existingManifest)
  );

  await writeManifest(targetDir, updatedManifest);

  const labels = platforms.map(platformLabel).join(', ');
  vscode.window.showInformationMessage(
    `Security rules installed for: ${labels}. Remember to commit: git add .claude/ .agent/ .cursor/ AGENTS.md`
  );
}

// ── Command: Manage ─────────────────────────────────────────────────────────

async function runManageCommand(targetDir: string): Promise<void> {
  // Step 1: Load manifest and fetch remote SHAs
  let manifest: Manifest | null;
  let skillInfos: SkillInfo[];

  try {
    [manifest, skillInfos] = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'AI Secure Coding Rules: Checking status…',
        cancellable: false,
      },
      async (progress) => {
        progress.report({ message: 'Reading local manifest…' });
        const m = await readManifest(targetDir);
        progress.report({ message: 'Fetching remote SHAs from GitHub…' });
        const remoteShas = await fetchRemoteShas();
        progress.report({ message: 'Computing skill statuses…' });
        const infos = await getSkillStatuses(targetDir, m, remoteShas);
        return [m, infos] as [Manifest | null, SkillInfo[]];
      }
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    vscode.window.showErrorMessage(
      `AI Secure Coding Rules: Failed to fetch status — ${message}`
    );
    return;
  }

  // Step 2: Show skill list with status, pre-selecting outdated skills
  const outdatedCount = skillInfos.filter((i) => i.status === 'outdated').length;
  const notInstalledCount = skillInfos.filter((i) => i.status === 'not-installed').length;
  const upToDateCount = skillInfos.filter(
    (i) => i.status === 'up-to-date' || i.status === 'installed-unknown'
  ).length;

  const summary = `${outdatedCount} outdated · ${notInstalledCount} not installed · ${upToDateCount} up-to-date`;

  const allItems: SkillPickItem[] = skillInfos.map(skillInfoToItem);
  const preSelectedKeys = new Set(
    skillInfos.filter((i) => i.status === 'outdated').map((i) => i.skill.key)
  );

  const qp = vscode.window.createQuickPick<SkillPickItem>();
  qp.title = `AI Secure Coding Rules — Manage Skills (${summary})`;
  qp.placeholder = 'Select skills to install, update, or remove';
  qp.canSelectMany = true;
  qp.ignoreFocusOut = true;
  qp.items = allItems;
  qp.selectedItems = allItems.filter((item) => preSelectedKeys.has(item.skillInfo.skill.key));
  qp.show();

  const selectedItems = await new Promise<SkillPickItem[] | undefined>((resolve) => {
    qp.onDidAccept(() => {
      resolve([...qp.selectedItems]);
      qp.hide();
    });
    qp.onDidHide(() => resolve(undefined));
  });
  qp.dispose();

  if (!selectedItems || selectedItems.length === 0) return;

  const selectedInfos = selectedItems.map((i) => i.skillInfo);
  const selectedSkills = selectedInfos.map((i) => i.skill);

  // Step 3: Choose action
  const installCount = selectedInfos.filter((i) => i.status !== 'up-to-date').length;
  const removeCount = selectedInfos.filter((i) => i.status !== 'not-installed').length;

  const actionItems: vscode.QuickPickItem[] = [];
  if (installCount > 0) {
    actionItems.push({
      label: '$(cloud-download) Install / Update selected',
      description: `${installCount} skill(s)`,
      detail: 'Download and install the latest version from GitHub',
    });
  }
  if (removeCount > 0) {
    actionItems.push({
      label: '$(trash) Remove selected',
      description: `${removeCount} skill(s)`,
      detail: 'Delete skill files from the workspace',
    });
  }
  if (actionItems.length === 0) return;

  const actionPick = await vscode.window.showQuickPick(actionItems, {
    title: `AI Secure Coding Rules — Choose action for ${selectedInfos.length} skill(s)`,
    ignoreFocusOut: true,
  });
  if (!actionPick) return;

  if (actionPick.label.startsWith('$(cloud-download)')) {
    // Step 4a: Platform selection for install/update
    const platformPicks = await vscode.window.showQuickPick(PLATFORM_ITEMS, {
      title: 'AI Secure Coding Rules — Select platforms',
      placeHolder: 'Which platforms should receive these skills?',
      canPickMany: true,
      ignoreFocusOut: true,
    });
    if (!platformPicks || platformPicks.length === 0) return;

    const platforms = (platformPicks as PlatformItem[]).map((p) => p.id as Platform);

    try {
      const updatedManifest = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'AI Secure Coding Rules: Installing…',
          cancellable: false,
        },
        (progress) => install(platforms, selectedSkills, targetDir, progress, manifest)
      );
      await writeManifest(targetDir, updatedManifest);
      vscode.window.showInformationMessage(
        `$(check) ${selectedSkills.length} skill(s) installed/updated. Remember to commit the changes.`
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      vscode.window.showErrorMessage(`AI Secure Coding Rules: Install failed — ${message}`);
    }
  } else {
    // Step 4b: Remove
    try {
      const updatedManifest = await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'AI Secure Coding Rules: Removing…',
          cancellable: false,
        },
        (progress) => removeSkills(selectedSkills, targetDir, progress, manifest)
      );
      await writeManifest(targetDir, updatedManifest);
      vscode.window.showInformationMessage(
        `$(trash) ${selectedSkills.length} skill(s) removed.`
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      vscode.window.showErrorMessage(`AI Secure Coding Rules: Remove failed — ${message}`);
    }
  }
}

// ── Extension entry points ──────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('aiSecureRules.install', async () => {
      const targetDir = getWorkspaceDir();
      if (!targetDir) return;
      try {
        await runInstallCommand(targetDir);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        vscode.window.showErrorMessage(`AI Secure Coding Rules: ${message}`);
      }
    }),

    vscode.commands.registerCommand('aiSecureRules.manage', async () => {
      const targetDir = getWorkspaceDir();
      if (!targetDir) return;
      await runManageCommand(targetDir);
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up
}
