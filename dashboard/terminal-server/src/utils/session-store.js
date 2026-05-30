const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const os = require('os');

class SessionStore {
    constructor(options = {}) {
        // Base storage directory
        this.storageDir = options.storageDir || path.join(os.homedir(), '.claude-code-web');
        this.sessionTtlMs = options.sessionTtlMs ?? (24 * 60 * 60 * 1000);
        this.maxFileAgeDays = options.maxFileAgeDays ?? 7;
        fsSync.mkdirSync(this.storageDir, { recursive: true });
        this.initializeStorage();
    }

    // D5: partitioned path — users/<id>/sessions.json
    _userDir(ownerUserId) {
        return path.join(this.storageDir, 'users', String(ownerUserId));
    }

    _sessionsFilePath(ownerUserId) {
        return path.join(this._userDir(ownerUserId), 'sessions.json');
    }

    // Legacy path — used only during migration detection
    get sessionsFile() {
        return path.join(this.storageDir, 'sessions.json');
    }

    async initializeStorage() {
        try {
            await fs.mkdir(this.storageDir, { recursive: true });
        } catch (error) {
            console.error('Failed to create storage directory:', error);
        }
    }

    /**
     * Save all sessions to disk, partitioned by ownerUserId (D5).
     * Sessions without ownerUserId are skipped with a warning (not silently defaulted).
     */
    async saveSessions(sessions) {
        // Group sessions by ownerUserId
        const byOwner = new Map();
        for (const [id, session] of sessions.entries()) {
            const ownerId = session.ownerUserId;
            if (!ownerId) {
                // D5: throw on missing owner — no silent default
                console.error(`[session-store] Session ${id} has no ownerUserId — skipping save for this session`);
                continue;
            }
            if (!byOwner.has(String(ownerId))) {
                byOwner.set(String(ownerId), []);
            }
            byOwner.get(String(ownerId)).push([id, session]);
        }

        const now = Date.now();
        const results = [];
        for (const [ownerId, entries] of byOwner.entries()) {
            try {
                const userDir = this._userDir(ownerId);
                await fs.mkdir(userDir, { recursive: true });

                const sessionsArray = entries
                    .filter(([, session]) => !this.isSessionStale(session, now))
                    .map(([id, session]) => ({
                        id,
                        name: session.name || 'Unnamed Session',
                        created: session.created || new Date(),
                        lastActivity: session.lastActivity || new Date(),
                        workingDir: session.workingDir || process.cwd(),
                        agentName: session.agentName || null,
                        ownerUserId: session.ownerUserId,
                        active: false,
                        outputBuffer: Array.isArray(session.outputBuffer) ? session.outputBuffer.slice(-100) : [],
                        connections: [],
                        lastAccessed: session.lastAccessed || Date.now(),
                        mode: session.mode || null,
                        chatHistory: Array.isArray(session.chatHistory) ? session.chatHistory.slice(-50) : [],
                        sdkSessionId: session.sdkSessionId || null,
                        ticketId: session.ticketId || null,
                        archived: session.archived || false,
                        systemPromptExtras: session.systemPromptExtras || null,
                        sessionStartTime: session.sessionStartTime || null,
                        sessionUsage: session.sessionUsage || {
                            requests: 0, inputTokens: 0, outputTokens: 0,
                            cacheTokens: 0, totalCost: 0, models: {}
                        }
                    }));

                const data = {
                    version: '2.0',
                    ownerUserId: ownerId,
                    savedAt: new Date().toISOString(),
                    sessions: sessionsArray
                };

                const sessionsFile = this._sessionsFilePath(ownerId);
                const tempFile = `${sessionsFile}.tmp`;
                await fs.writeFile(tempFile, JSON.stringify(data, null, 2));
                await fs.mkdir(userDir, { recursive: true });
                await fs.rename(tempFile, sessionsFile);
                results.push(true);
            } catch (error) {
                console.error(`[session-store] Failed to save sessions for owner ${ownerId}:`, error.message);
                results.push(false);
            }
        }
        return results.every(Boolean);
    }

    /**
     * Load all sessions from disk across all user partitions (D5).
     * ownerUserId param is optional — if given, only loads that user's sessions.
     */
    async loadSessions(ownerUserId) {
        try {
            if (ownerUserId !== undefined) {
                // Load a specific user's sessions
                return await this._loadUserSessions(String(ownerUserId));
            }

            // Load all users' sessions
            const usersDir = path.join(this.storageDir, 'users');
            let userDirs = [];
            try {
                const entries = await fs.readdir(usersDir, { withFileTypes: true });
                userDirs = entries.filter(e => e.isDirectory()).map(e => e.name);
            } catch (err) {
                if (err.code !== 'ENOENT') throw err;
                // No users dir yet — return empty (fresh install or pre-migration)
            }

            const allSessions = new Map();
            for (const uid of userDirs) {
                const userSessions = await this._loadUserSessions(uid);
                for (const [id, session] of userSessions.entries()) {
                    allSessions.set(id, session);
                }
            }
            return allSessions;
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error('[session-store] Failed to load sessions:', error.message);
            }
            return new Map();
        }
    }

    async _loadUserSessions(ownerId) {
        const sessionsFile = this._sessionsFilePath(ownerId);
        try {
            await fs.access(sessionsFile);
            const data = await fs.readFile(sessionsFile, 'utf8');
            if (!data || !data.trim()) return new Map();

            let parsed;
            try {
                parsed = JSON.parse(data);
            } catch (parseError) {
                console.error(`[session-store] Sessions file corrupted for owner ${ownerId}, starting fresh:`, parseError.message);
                try {
                    await fs.rename(sessionsFile, `${sessionsFile}.corrupted.${Date.now()}`);
                } catch {}
                return new Map();
            }

            if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.sessions)) {
                console.log(`[session-store] Invalid sessions format for owner ${ownerId}, starting fresh`);
                return new Map();
            }

            if (parsed.savedAt) {
                const savedAt = new Date(parsed.savedAt);
                const daysSinceSave = (Date.now() - savedAt) / (1000 * 60 * 60 * 24);
                if (daysSinceSave > this.maxFileAgeDays) {
                    console.log(`[session-store] Sessions too old for owner ${ownerId}, starting fresh`);
                    return new Map();
                }
            }

            const sessions = new Map();
            let droppedStale = 0;
            for (const session of parsed.sessions) {
                if (!session || !session.id) continue;
                if (this.isSessionStale(session, Date.now(), parsed.savedAt)) {
                    droppedStale += 1;
                    continue;
                }

                // Synthesize uuids for legacy chatHistory entries that lack them
                const chatHistory = (session.chatHistory || []).map((msg, i) => {
                    if (!msg.uuid) {
                        return { ...msg, uuid: `legacy-${session.id}-${i}` };
                    }
                    return msg;
                });

                sessions.set(session.id, {
                    ...session,
                    ownerUserId: session.ownerUserId || ownerId, // backfill from dir name
                    created: session.created ? new Date(session.created) : new Date(),
                    lastActivity: session.lastActivity ? new Date(session.lastActivity) : new Date(),
                    active: false,
                    connections: new Set(),
                    outputBuffer: session.outputBuffer || [],
                    maxBufferSize: 1000,
                    chatHistory,
                    sdkSessionId: session.sdkSessionId || null,
                    mode: session.mode || null,
                    usageData: session.usageData || null
                });
            }

            if (droppedStale > 0) {
                console.log(`[session-store] Dropped ${droppedStale} stale sessions for owner ${ownerId}`);
            }
            console.log(`[session-store] Restored ${sessions.size} sessions for owner ${ownerId}`);
            return sessions;
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error(`[session-store] Failed to load sessions for owner ${ownerId}:`, error.message);
            }
            return new Map();
        }
    }

    async clearOldSessions() {
        try {
            await fs.unlink(this.sessionsFile);
            console.log('Cleared old sessions');
            return true;
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error('Failed to clear sessions:', error);
            }
            return false;
        }
    }

    async getSessionMetadata() {
        try {
            await fs.access(this.sessionsFile);
            const stats = await fs.stat(this.sessionsFile);
            const data = await fs.readFile(this.sessionsFile, 'utf8');
            const parsed = JSON.parse(data);

            return {
                exists: true,
                savedAt: parsed.savedAt,
                sessionCount: parsed.sessions ? parsed.sessions.length : 0,
                fileSize: stats.size,
                version: parsed.version
            };
        } catch (error) {
            return {
                exists: false,
                error: error.message
            };
        }
    }

    /**
     * Detect legacy layout: root sessions.json exists AND users/ dir is absent.
     * Used by loadPersistedSessions in server.js to trigger auto-migration.
     */
    async needsMigration() {
        const legacyFile = this.sessionsFile;
        const usersDir = path.join(this.storageDir, 'users');
        try {
            await fs.access(legacyFile);
            // Legacy file exists — check if users/ dir also exists
            try {
                await fs.access(usersDir);
                return false; // Migration already done
            } catch {
                return true; // Legacy exists, users/ absent → needs migration
            }
        } catch {
            return false; // No legacy file → fresh install
        }
    }

    _sessionTouchTimestamp(session, fallbackSavedAt = null) {
        const candidates = [
            session?.lastActivity,
            session?.lastAccessed,
            session?.created,
            fallbackSavedAt,
        ];
        for (const candidate of candidates) {
            if (candidate === null || candidate === undefined || candidate === '') continue;
            const value = candidate instanceof Date ? candidate.getTime() : new Date(candidate).getTime();
            if (Number.isFinite(value)) return value;
        }
        return null;
    }

    isSessionStale(session, now = Date.now(), fallbackSavedAt = null) {
        if (!session || session.archived || session.active) return false;
        if (session.connections instanceof Set ? session.connections.size > 0 : Array.isArray(session.connections) && session.connections.length > 0) {
            return false;
        }
        const lastTouch = this._sessionTouchTimestamp(session, fallbackSavedAt);
        if (lastTouch === null) return false;
        return (now - lastTouch) > this.sessionTtlMs;
    }
}

module.exports = SessionStore;
