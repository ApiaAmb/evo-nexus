/**
 * ChatLogger — append-only JSONL logs for chat conversations.
 *
 * D5: Stores chat messages partitioned by user:
 *   workspace/ADWs/logs/chat/users/<ownerUserId>/<agentName>/<sessionId>.jsonl
 *
 * Each line is a JSON object: { role, text?, blocks?, files?, ts, uuid? }
 *
 * Special event lines:
 *   { type: "rewind", at: <uuid>, ts }  — marks a rewind point; messages after
 *     the referenced uuid are considered dropped. The reader applies all rewind
 *     markers before returning results (append-only, no destructive truncation).
 *
 * This is the durable source of truth for chat history.
 * sessions.json is a fast-access cache; JSONL survives restarts and cleanups.
 *
 * IMPORTANT: ownerUserId is required for all operations. Missing ownerUserId
 * throws — no silent default to avoid cross-user data access.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class ChatLogger {
  constructor(workspaceRoot) {
    this.logsRoot = path.join(workspaceRoot || process.cwd(), 'workspace', 'ADWs', 'logs', 'chat');
    this._ensureDir(this.logsRoot);
  }

  _ensureDir(dir) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch {}
  }

  // D5: partitioned path — logs/chat/users/<id>/<agentName>/<sessionId>.jsonl
  _logPath(ownerUserId, agentName, sessionId) {
    if (!ownerUserId) {
      throw new Error(`[chat-logger] ownerUserId is required — refusing to read/write without owner`);
    }
    const safe = (agentName || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '_');
    const shortId = sessionId.slice(0, 8);
    const dir = path.join(this.logsRoot, 'users', String(ownerUserId), safe);
    this._ensureDir(dir);
    return path.join(dir, `${safe}_${shortId}.jsonl`);
  }

  /**
   * Append a message to the chat log.
   * Assigns a uuid if the message doesn't already have one.
   * Returns the (possibly assigned) uuid.
   *
   * @param {string|number} ownerUserId - Required. Owner of the session.
   * @param {string} agentName
   * @param {string} sessionId
   * @param {object} message
   */
  append(ownerUserId, agentName, sessionId, message) {
    try {
      if (!message.uuid) {
        message.uuid = crypto.randomUUID();
      }
      const logPath = this._logPath(ownerUserId, agentName, sessionId);
      const line = JSON.stringify(message) + '\n';
      fs.appendFileSync(logPath, line, 'utf8');
      return message.uuid;
    } catch (err) {
      console.error(`[chat-logger] Failed to append: ${err.message}`);
      return null;
    }
  }

  /**
   * Append a rewind marker to the JSONL log.
   *
   * @param {string|number} ownerUserId - Required.
   * @param {string} agentName
   * @param {string} sessionId
   * @param {string} atUuid
   */
  appendRewindMarker(ownerUserId, agentName, sessionId, atUuid) {
    try {
      const marker = { type: 'rewind', at: atUuid, ts: Date.now() };
      const logPath = this._logPath(ownerUserId, agentName, sessionId);
      fs.appendFileSync(logPath, JSON.stringify(marker) + '\n', 'utf8');
    } catch (err) {
      console.error(`[chat-logger] Failed to append rewind marker: ${err.message}`);
    }
  }

  /**
   * Read full chat history from JSONL log, applying rewind markers.
   * Returns array of messages, or empty array if not found.
   *
   * @param {string|number} ownerUserId - Required.
   * @param {string} agentName
   * @param {string} sessionId
   */
  read(ownerUserId, agentName, sessionId) {
    try {
      const logPath = this._logPath(ownerUserId, agentName, sessionId);
      if (!fs.existsSync(logPath)) return [];

      const content = fs.readFileSync(logPath, 'utf8').trim();
      if (!content) return [];

      const rawLines = [];
      for (const line of content.split('\n')) {
        if (!line.trim()) continue;
        try {
          rawLines.push(JSON.parse(line));
        } catch {
          // Skip malformed lines
        }
      }

      // First pass: assign synthesized uuids to legacy messages (no uuid, not a marker)
      let idx = 0;
      for (const entry of rawLines) {
        if (entry.type !== 'rewind' && !entry.uuid) {
          entry.uuid = `legacy-${sessionId}-${idx}`;
        }
        if (entry.type !== 'rewind') idx++;
      }

      // Second pass: play forward, applying rewind markers
      const messages = [];
      for (const entry of rawLines) {
        if (entry.type === 'rewind') {
          const cutIdx = messages.findIndex(m => m.uuid === entry.at);
          if (cutIdx !== -1) {
            messages.splice(cutIdx);
          }
        } else {
          messages.push(entry);
        }
      }

      return messages;
    } catch (err) {
      console.error(`[chat-logger] Failed to read: ${err.message}`);
      return [];
    }
  }

  /**
   * Check if a log exists for a session.
   *
   * @param {string|number} ownerUserId - Required.
   * @param {string} agentName
   * @param {string} sessionId
   */
  exists(ownerUserId, agentName, sessionId) {
    try {
      return fs.existsSync(this._logPath(ownerUserId, agentName, sessionId));
    } catch {
      return false;
    }
  }
}

module.exports = ChatLogger;
