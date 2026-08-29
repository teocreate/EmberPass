/**
 * In-memory repository with the same surface as the PostgreSQL one.
 * Used when DATABASE_URL is not set, so the app can be run and demoed without a
 * database. Everything is lost on restart.
 */
export function createMemoryStore() {
  const users = new Map(); // id -> user
  const usersByEmail = new Map(); // email -> id
  const passes = new Map(); // id -> pass
  const sessions = new Map(); // token hash (hex) -> session
  const scans = [];
  const seen = new Set(); // jti values already recorded
  let userSeq = 0;
  let passSeq = 0;
  let scanSeq = 0;

  const clone = (value) => (value ? { ...value } : null);
  const key = (tokenHash) => Buffer.from(tokenHash).toString('hex');

  const decorate = (scan) => ({
    ...scan,
    holderName: users.get(scan.userId)?.fullName ?? null,
    staffName: users.get(scan.staffId)?.fullName ?? null,
    passSerial: passes.get(scan.passId)?.serial ?? null,
  });

  return {
    kind: 'memory',

    async close() {},

    async createUser({ email, passwordHash = null, fullName, role = 'user', authSource = 'local', oidcSub = null }) {
      if (usersByEmail.has(email)) {
        const error = new Error('duplicate email');
        error.code = '23505';
        throw error;
      }
      const user = {
        id: ++userSeq,
        email,
        passwordHash,
        fullName,
        role,
        status: 'active',
        authSource,
        oidcSub,
        createdAt: new Date(),
        lastLoginAt: null,
      };
      users.set(user.id, user);
      usersByEmail.set(email, user.id);
      return clone(user);
    },

    async findUserByEmail(email) {
      return clone(users.get(usersByEmail.get(email)));
    },

    async findUserById(id) {
      return clone(users.get(id));
    },

    async findUserByOidcSub(sub) {
      for (const user of users.values()) if (sub && user.oidcSub === sub) return clone(user);
      return null;
    },

    async updateUserFromProvider(userId, { oidcSub, fullName, role, authSource }) {
      const user = users.get(userId);
      if (!user) return null;
      if (oidcSub !== undefined && oidcSub !== null) user.oidcSub = oidcSub;
      if (fullName) user.fullName = fullName;
      if (role) user.role = role;
      if (authSource) user.authSource = authSource;
      return clone(user);
    },

    async touchLogin(userId) {
      const user = users.get(userId);
      if (user) user.lastLoginAt = new Date();
    },

    async createPass({ userId, serial, tier = 'standard', validUntil = null }) {
      const pass = {
        id: ++passSeq,
        userId,
        serial,
        tier,
        status: 'active',
        validFrom: new Date(),
        validUntil,
      };
      passes.set(pass.id, pass);
      return clone(pass);
    },

    async findPassByUserId(userId) {
      for (const pass of passes.values()) if (pass.userId === userId) return clone(pass);
      return null;
    },

    async findPassById(id) {
      return clone(passes.get(id));
    },

    async setPassStatus(passId, status) {
      const pass = passes.get(passId);
      if (!pass) return null;
      pass.status = status;
      return clone(pass);
    },

    async createSession({ tokenHash, userId, expiresAt, userAgent, ip, idToken = null }) {
      sessions.set(key(tokenHash), { userId, expiresAt, userAgent, ip, idToken });
    },

    async findSession(tokenHash) {
      const session = sessions.get(key(tokenHash));
      if (!session) return null;
      if (new Date(session.expiresAt) <= new Date()) {
        sessions.delete(key(tokenHash));
        return null;
      }
      return { userId: session.userId, expiresAt: session.expiresAt, idToken: session.idToken ?? null };
    },

    async deleteSession(tokenHash) {
      sessions.delete(key(tokenHash));
    },

    async deleteExpiredSessions() {
      let removed = 0;
      const now = new Date();
      for (const [hash, session] of sessions) {
        if (new Date(session.expiresAt) <= now) {
          sessions.delete(hash);
          removed++;
        }
      }
      return removed;
    },

    async recordScan(scan) {
      if (scan.jti) {
        if (seen.has(scan.jti)) return null;
        seen.add(scan.jti);
      }
      const row = {
        id: ++scanSeq,
        jti: scan.jti ?? null,
        passId: scan.passId ?? null,
        userId: scan.userId ?? null,
        staffId: scan.staffId ?? null,
        gate: scan.gate ?? null,
        result: scan.result,
        offline: scan.offline ?? false,
        issuedAt: scan.issuedAt ? new Date(scan.issuedAt * 1000) : null,
        scannedAt: new Date(),
      };
      scans.unshift(row);
      return decorate(row);
    },

    async findScanByJti(jti) {
      const found = scans.find((scan) => scan.jti === jti);
      return found ? decorate(found) : null;
    },

    async listScansForPass(passId, limit = 20) {
      return scans.filter((scan) => scan.passId === passId).slice(0, limit).map(decorate);
    },

    async listRecentScans(limit = 50) {
      return scans.slice(0, limit).map(decorate);
    },
  };
}
