/**
 * migrate-session-ownership.js — D6 one-shot migration script
 *
 * Migrates legacy sessions.json (root) and logs/chat/*.jsonl to partitioned
 * layout: users/<admin_user_id>/sessions.json and
 * logs/chat/users/<admin_user_id>/<agentName>/<sessionId>.jsonl
 *
 * Prerequisites (enforced at run time):
 *   - ADMIN_USER_ID env var set (resolved by server.js from SQL verification)
 *   - Legacy layout detected: storageDir/sessions.json exists, users/ absent
 *
 * Idempotent: second run detects users/ dir exists and exits cleanly.
 *
 * Usage (from server.js loadPersistedSessions auto-migration):
 *   const { migrate } = require('./scripts/migrate-session-ownership');
 *   await migrate({ storageDir, adminUserId, logsRoot });
 *
 * Usage (standalone, for testing):
 *   ADMIN_USER_ID=1 node scripts/migrate-session-ownership.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

async function migrate({ storageDir, adminUserId, logsRoot }) {
  if (!adminUserId) {
    throw new Error('[migrate] adminUserId is required');
  }

  const adminId = String(adminUserId);
  const legacySessionsFile = path.join(storageDir, 'sessions.json');
  const usersDir = path.join(storageDir, 'users');

  console.log(`[migrate] Starting session ownership migration (adminUserId=${adminId})`);
  const startTime = Date.now();

  // Idempotency check: if users/ already exists, skip
  if (fs.existsSync(usersDir)) {
    console.log(`[migrate] users/ dir already exists — migration already completed. Skipping.`);
    return { skipped: true };
  }

  // --- Backup legacy files ---
  const ts = Date.now();
  let legacySessionsData = null;

  if (fs.existsSync(legacySessionsFile)) {
    const bakPath = `${legacySessionsFile}.bak-pre-migration-${ts}`;
    fs.copyFileSync(legacySessionsFile, bakPath);
    console.log(`[migrate] Backed up ${legacySessionsFile} → ${bakPath}`);
    legacySessionsData = JSON.parse(fs.readFileSync(legacySessionsFile, 'utf8'));
  } else {
    console.log(`[migrate] No legacy sessions.json found — nothing to migrate`);
    legacySessionsData = { sessions: [] };
  }

  // --- Migrate sessions ---
  const userDir = path.join(usersDir, adminId);
  fs.mkdirSync(userDir, { recursive: true });

  const sessions = Array.isArray(legacySessionsData.sessions) ? legacySessionsData.sessions : [];
  const migratedSessions = sessions.map(session => ({
    ...session,
    ownerUserId: session.ownerUserId || adminId,
  }));

  const newSessionsFile = path.join(userDir, 'sessions.json');
  const newData = {
    version: '2.0',
    ownerUserId: adminId,
    savedAt: new Date().toISOString(),
    sessions: migratedSessions,
  };
  fs.writeFileSync(newSessionsFile, JSON.stringify(newData, null, 2));
  console.log(`[migrate] Wrote ${migratedSessions.length} sessions to ${newSessionsFile}`);

  // --- Migrate JSONL chat logs ---
  let movedLogs = 0;
  let skippedLogs = 0;

  if (logsRoot && fs.existsSync(logsRoot)) {
    // Backup entire logs/chat dir
    const logsBakDir = `${logsRoot}.bak-pre-migration-${ts}`;
    _copyDirSync(logsRoot, logsBakDir);
    console.log(`[migrate] Backed up ${logsRoot} → ${logsBakDir}`);

    // Move *.jsonl files from flat root (legacy layout) to users/<id>/<agent>/
    const entries = fs.readdirSync(logsRoot, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith('.jsonl')) continue;
      const src = path.join(logsRoot, entry.name);

      // Parse legacy filename: <agentName>_<shortId>.jsonl
      const match = entry.name.match(/^(.+)_([a-f0-9]{8})\.jsonl$/);
      const agentName = match ? match[1] : 'unknown';

      const destDir = path.join(logsRoot, 'users', adminId, agentName);
      fs.mkdirSync(destDir, { recursive: true });
      const dest = path.join(destDir, entry.name);

      if (fs.existsSync(dest)) {
        console.log(`[migrate] Skipping ${entry.name} — destination already exists`);
        skippedLogs++;
        continue;
      }

      fs.renameSync(src, dest);
      movedLogs++;
    }
    console.log(`[migrate] Moved ${movedLogs} JSONL files, skipped ${skippedLogs}`);
  }

  const elapsed = Date.now() - startTime;
  if (elapsed > 600000) {
    console.error(`[migrate] WARNING: migration took ${elapsed}ms (> 600s). Escalate to admin.`);
  }

  console.log(`[migrate] Completed in ${elapsed}ms. Sessions: ${migratedSessions.length}, JSONL moved: ${movedLogs}`);
  return {
    skipped: false,
    sessionsCount: migratedSessions.length,
    logsMoved: movedLogs,
    logsSkipped: skippedLogs,
    elapsedMs: elapsed,
  };
}

function _copyDirSync(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      _copyDirSync(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Standalone execution
if (require.main === module) {
  const adminUserId = process.env.ADMIN_USER_ID;
  if (!adminUserId) {
    console.error('Usage: ADMIN_USER_ID=1 node scripts/migrate-session-ownership.js');
    process.exit(1);
  }

  const storageDir = process.env.STORAGE_DIR || path.join(os.homedir(), '.claude-code-web');
  const logsRoot = process.env.LOGS_ROOT || path.join(process.cwd(), 'workspace', 'ADWs', 'logs', 'chat');

  migrate({ storageDir, adminUserId, logsRoot })
    .then(result => {
      console.log('[migrate] Result:', JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch(err => {
      console.error('[migrate] Fatal error:', err.message);
      process.exit(1);
    });
}

module.exports = { migrate };
