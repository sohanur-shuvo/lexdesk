import crypto from 'node:crypto';
import { firebaseAdmin } from '../firebase';
import { sql, withTransaction } from '../db';
import { tsToIso, buildInsert, buildUpdateSet } from '../rows';
import { uploadUserPhoto, signedReadUrl, signedReadUrls } from '../storage';
import { FACE_EMBEDDING_MODEL, averageEmbeddings } from './face';
import { verifyFirebasePassword } from '../auth';

// User/employee/profile/face/password operations against Neon Postgres + Firebase
// Auth — ported from AttendDesk. Roles are stored in AttendDesk's vocabulary
// (ADMIN/EMPLOYEE/SUPER_ADMIN) since we share its live data; login maps them to
// LexDesk's lowercase for the JWT. Wrapper shapes match the old HTTP responses.

function newTempPassword() {
  return crypto.randomBytes(8).toString('base64url');
}

// Firebase Admin error code -> { friendly message, HTTP status, stable app code }.
// Same shape as LOGIN_GUARD_MESSAGES in api/auth/login/route.js. A FirebaseAuthError
// carries .code but no .status, so an unmapped one falls through every route's
// `status: err.status || 502` and leaks the raw SDK sentence to the user.
//
// 'auth/user-not-found' is 409, not 404: the routes already use 404 for "not in
// your organization", and the UI reads that as "this employee doesn't exist". The
// row DOES exist — Neon and Firebase Auth disagree, which is a conflict.
const FIREBASE_AUTH_ERRORS = {
  'auth/user-not-found': {
    status: 409,
    code: 'auth_account_missing',
    message: 'This employee has a profile but no sign-in account. A Dev can rebuild it from this page.',
  },
  'auth/email-already-exists': { status: 409, code: 'email_in_use', message: 'A user with that email already exists' },
  'auth/uid-already-exists': { status: 409, code: 'uid_in_use', message: 'A sign-in account already exists for this user.' },
  'auth/invalid-email': { status: 400, code: 'invalid_email', message: 'The email on file is not a valid address. Fix it, then try again.' },
  'auth/invalid-password': { status: 400, code: 'weak_password', message: 'Password must be at least 6 characters.' },
  'auth/too-many-requests': { status: 429, code: 'rate_limited', message: 'Too many attempts. Wait a minute and try again.' },
};

// Translate a FirebaseAuthError into a tagged Error the existing route handlers
// render correctly. Unmapped codes (internal/network) pass through untouched so
// they keep 502-ing — they genuinely are upstream failures.
export function firebaseAuthError(err) {
  const m = FIREBASE_AUTH_ERRORS[err?.code];
  if (!m) return err;
  return Object.assign(new Error(m.message), { status: m.status, code: m.code, cause: err });
}

// Shared by the email-change flow and the Auth-link repair below.
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// Maps a users row (snake_case pg columns) to the API/JSON contract shape.
function userRow(row, photoUrl) {
  return {
    id: row.firebase_uid,
    email: row.email,
    name: row.name,
    role: row.role,
    teamId: row.team_id ?? null,
    teamName: row.team_name ?? null,
    employeeId: row.employee_id ?? null,
    designation: row.designation ?? null,
    department: row.department ?? null,
    contactNumber: row.contact_number ?? null,
    birthDate: row.birth_date ?? null,
    joiningDate: row.joining_date ?? null,
    mustChangePassword: row.must_change_password ?? false,
    faceEnrolledAt: tsToIso(row.face_enrolled_at),
    createdAt: tsToIso(row.created_at),
    photoUrl: photoUrl ?? null,
    // Login device cap + per-employee IP allowlist (see services/loginGuard.js).
    loginDevices: (row.login_devices || []).map((d) => ({
      deviceId: d.deviceId,
      name: d.name ?? null,
      platform: d.platform ?? null,
      firstSeenAt: d.firstSeenAt ?? null,
      lastSeenAt: d.lastSeenAt ?? null,
    })),
    loginIpAllowlist: row.login_ip_allowlist || [],
  };
}

// signPhotos:false skips the org-wide signed-URL work and instead returns each
// row's raw photoStoragePath, so a caller that only needs photos for a subset
// (e.g. one team) can sign just those. Default keeps the original behavior.
export async function getEmployees(orgId, { signPhotos = true } = {}) {
  const rows = await sql`SELECT * FROM users WHERE org_id=${orgId} ORDER BY created_at DESC`;
  if (!signPhotos) {
    return {
      employees: rows.map((r) => ({
        ...userRow(r, null),
        photoStoragePath: r.photo_storage_path ?? null,
      })),
    };
  }
  const photoUrls = await signedReadUrls(rows.map((r) => r.photo_storage_path));
  return { employees: rows.map((r, i) => userRow(r, photoUrls[i])) };
}

export async function getEmployee(uid, orgId) {
  const rows = await sql`SELECT * FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!rows.length) throw Object.assign(new Error('not_found'), { status: 404 });
  const row = rows[0];
  const photoUrl = await signedReadUrl(row.photo_storage_path);
  return { employee: userRow(row, photoUrl) };
}

// body: { email, name, role: 'ADMIN'|'EMPLOYEE', teamId?, employeeId?,
//         designation?, department?, contactNumber?, birthDate?, joiningDate? }
export async function createEmployee(body, orgId) {
  const { auth } = firebaseAdmin();
  const email = String(body.email).toLowerCase();
  const tempPassword = newTempPassword();
  let record;
  try {
    record = await auth.createUser({ email, password: tempPassword, displayName: body.name, emailVerified: false });
  } catch (err) {
    throw firebaseAuthError(err);
  }

  // Everything past this point is compensated: if the row insert fails we delete
  // the Auth account we just made, so the outcome is "nothing happened" rather
  // than a claims-bearing Auth user with no users row (which /api/v1 would accept
  // for ADMIN/DEV roles, since those are exempt from the login-device guard).
  try {
    let teamId = body.teamId ?? null;
    let teamName = null;
    if (teamId) {
      const teamRows = await sql`SELECT name FROM teams WHERE id=${teamId} AND org_id=${orgId}`;
      if (teamRows.length) teamName = teamRows[0].name ?? null;
      else teamId = null;
    }

    const { text, params } = buildInsert('users', {
      firebaseUid: record.uid,
      orgId,
      email,
      name: body.name,
      role: body.role,
      teamId,
      teamName,
      employeeId: body.employeeId ?? null,
      designation: body.designation ?? null,
      department: body.department ?? null,
      contactNumber: body.contactNumber ?? null,
      birthDate: body.birthDate ?? null,
      joiningDate: body.joiningDate ?? null,
      mustChangePassword: true,
      faceEmbeddingB64: null,
      faceEmbeddingModel: null,
      faceEnrolledAt: null,
    });
    await sql.query(text, params);
  } catch (err) {
    try { await auth.deleteUser(record.uid); } catch { /* best-effort rollback */ }
    throw err;
  }

  // Claims come after the row and are deliberately best-effort — the users row is
  // the source of truth at login, and getMobileUser falls back to it when the
  // token carries no role claim. Rolling the account back over a claims failure
  // would leave the row behind and manufacture an orphan. Mirrors setEmployeeRole.
  try {
    await auth.setCustomUserClaims(record.uid, { role: body.role, orgId, email });
  } catch { /* non-fatal */ }

  return {
    employee: { uid: record.uid, email, name: body.name, role: body.role, temporaryPassword: tempPassword },
  };
}

export async function setEmployeeTeam(uid, teamId, orgId) {
  const existing = await sql`SELECT firebase_uid FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!existing.length) throw Object.assign(new Error('not_found'), { status: 404 });
  let resolvedTeamId = teamId || null;
  let teamName = null;
  if (resolvedTeamId) {
    const teamRows = await sql`SELECT name FROM teams WHERE id=${resolvedTeamId} AND org_id=${orgId}`;
    if (!teamRows.length) throw Object.assign(new Error('team_not_found'), { status: 404 });
    teamName = teamRows[0].name ?? null;
  } else {
    resolvedTeamId = null;
  }
  await sql`UPDATE users SET team_id=${resolvedTeamId}, team_name=${teamName} WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  return { ok: true, teamId: resolvedTeamId, teamName };
}

// Edit a member's basic profile fields (name, employeeId, designation,
// department, contactNumber, birthDate, joiningDate). Email/role/team are
// intentionally excluded here — those are identity/structure changes handled by
// dedicated flows. Keeps the Firebase Auth displayName in sync when name changes.
export async function updateEmployee(
  uid,
  { name, employeeId, designation, department, contactNumber, birthDate, joiningDate } = {},
  orgId,
) {
  const { auth } = firebaseAdmin();
  const existing = await sql`SELECT firebase_uid FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!existing.length) throw Object.assign(new Error('not_found'), { status: 404 });

  const updates = {};
  if (typeof name === 'string' && name.trim()) updates.name = name.trim();
  if (employeeId !== undefined) updates.employeeId = String(employeeId || '').trim() || null;
  if (designation !== undefined) updates.designation = String(designation || '').trim() || null;
  if (department !== undefined) updates.department = String(department || '').trim() || null;
  if (contactNumber !== undefined) updates.contactNumber = String(contactNumber || '').trim() || null;
  if (birthDate !== undefined) updates.birthDate = String(birthDate || '').trim() || null;
  if (joiningDate !== undefined) updates.joiningDate = String(joiningDate || '').trim() || null;
  if (Object.keys(updates).length === 0) return { ok: true };

  const { setClause, params, nextIndex } = buildUpdateSet(updates);
  await sql.query(
    `UPDATE users SET ${setClause} WHERE firebase_uid=$${nextIndex} AND org_id=$${nextIndex + 1}`,
    [...params, uid, orgId],
  );
  if (updates.name) {
    try { await auth.updateUser(uid, { displayName: updates.name }); } catch { /* non-fatal */ }
  }
  return { ok: true, ...updates };
}

// Assign/clear the IT Team role. Restricted to toggling between EMPLOYEE and
// IT_TEAM — it never elevates to (or demotes) ADMIN/SUPER_ADMIN, which are
// provisioned through their own dedicated flows. Updates the user row and the
// Firebase custom claims so both agree. The LexDesk session JWT carries the role
// from login, so the change takes effect when the user next signs in.
const ASSIGNABLE_ROLES = new Set(['EMPLOYEE', 'IT_TEAM', 'DEV']);

export async function setEmployeeRole(uid, role, orgId) {
  const next = String(role || '').toUpperCase();
  if (!ASSIGNABLE_ROLES.has(next)) throw Object.assign(new Error('invalid_role'), { status: 400 });
  const { auth } = firebaseAdmin();
  const rows = await sql`SELECT role, email FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!rows.length) throw Object.assign(new Error('not_found'), { status: 404 });
  const current = String(rows[0].role || '').toUpperCase();
  if (current === 'ADMIN' || current === 'SUPER_ADMIN') {
    throw Object.assign(new Error('cannot_change_admin_role'), { status: 403 });
  }
  const email = rows[0].email ?? '';
  await sql`UPDATE users SET role=${next} WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  try {
    await auth.setCustomUserClaims(uid, { role: next, orgId, email });
    await auth.revokeRefreshTokens(uid);
  } catch { /* claims are best-effort; the stored role is the source of truth at login */ }
  return { ok: true, role: next };
}

// Row first, Auth second, inside a transaction. The old order (deleteUser then
// DELETE) left a role-bearing users row with no sign-in account whenever the
// second step failed — the exact orphan that repairAuthAccount exists to undo.
// Now a failed Auth delete rolls the row back, and the worst case is an Auth
// account with no row, which login already rejects.
//
// auth/user-not-found counts as success: the account is already gone, so this is
// also the correct way to clear an orphaned row for someone who has left.
export async function deleteEmployee(uid, orgId) {
  const { auth } = firebaseAdmin();
  await withTransaction(async (client) => {
    const { rowCount } = await client.query(
      'DELETE FROM users WHERE firebase_uid=$1 AND org_id=$2',
      [uid, orgId],
    );
    if (!rowCount) throw Object.assign(new Error('not_found'), { status: 404 });
    try {
      await auth.deleteUser(uid);
    } catch (err) {
      if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
    }
  });
  return { ok: true };
}

// uid-keyed: the admin route already holds the target's firebase_uid, and
// users.email can drift from the Auth record (migrated rows were never
// normalized), so never round-trip through auth.getUserByEmail to re-derive it.
export async function resetUserPassword(uid, orgId) {
  const { auth } = firebaseAdmin();
  const existing = await sql`SELECT email FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!existing.length) throw Object.assign(new Error('user_not_found'), { status: 404 });
  const tempPassword = newTempPassword();
  try {
    await auth.updateUser(uid, { password: tempPassword });
    await auth.revokeRefreshTokens(uid);
  } catch (err) {
    throw firebaseAuthError(err);
  }
  await sql`UPDATE users SET must_change_password=true WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  return { email: String(existing[0].email || '').toLowerCase(), temporaryPassword: tempPassword };
}

// One-time enroll: 409 if the user already has an embedding (admin reset clears it).
export async function enrollFace(uid, embeddings, orgId) {
  const faceEmbeddingB64 = averageEmbeddings(embeddings);
  const outcome = await withTransaction(async (client) => {
    const { rows } = await client.query(
      'SELECT face_embedding_b64, face_enrolled_at FROM users WHERE firebase_uid=$1 AND org_id=$2 FOR UPDATE',
      [uid, orgId],
    );
    if (!rows.length) return { status: 404 };
    if (rows[0].face_embedding_b64) {
      return { status: 409, enrolledAt: tsToIso(rows[0].face_enrolled_at) };
    }
    await client.query(
      'UPDATE users SET face_embedding_b64=$1, face_embedding_model=$2, face_enrolled_at=now() WHERE firebase_uid=$3 AND org_id=$4',
      [faceEmbeddingB64, FACE_EMBEDDING_MODEL, uid, orgId],
    );
    return { status: 200 };
  });
  if (outcome.status === 404) throw Object.assign(new Error('not_found'), { status: 404 });
  if (outcome.status === 409) {
    throw Object.assign(new Error('already_enrolled'), {
      status: 409,
      body: { error: 'already_enrolled', enrolledAt: outcome.enrolledAt },
    });
  }
  return { ok: true, enrolledAt: new Date().toISOString() };
}

// Mobile enroll: OVERWRITE the user's face (re-enroll allowed), unlike the
// web one-time enrollFace. Averages the capture embeddings and stores them.
export async function enrollFaceOverwrite(uid, embeddings, orgId) {
  const faceEmbeddingB64 = averageEmbeddings(embeddings);
  await sql`UPDATE users SET face_embedding_b64=${faceEmbeddingB64}, face_embedding_model=${FACE_EMBEDDING_MODEL}, face_enrolled_at=now() WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  return { ok: true, enrolledAt: new Date().toISOString() };
}

export async function resetFace(uid, orgId) {
  const rows = await sql`SELECT face_embedding_b64 FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!rows.length) throw Object.assign(new Error('not_found'), { status: 404 });
  const wasEnrolled = !!rows[0].face_embedding_b64;
  await sql`UPDATE users SET face_embedding_b64=NULL, face_embedding_model=NULL, face_enrolled_at=NULL WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  return { ok: true, wasEnrolled };
}

const ALLOWED_PHOTO = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MAX_PHOTO_BYTES = 2 * 1024 * 1024;

// uid-keyed (the session JWT carries it). Touches Firebase Auth zero times —
// matching the mobile twin at api/v1/me/photo/route.js.
export async function uploadPhoto(uid, dataUrl, orgId) {
  const m = /^data:(image\/[a-z+]+);base64,(.+)$/i.exec(String(dataUrl).trim());
  if (!m) throw Object.assign(new Error('invalid_image'), { status: 400 });
  const contentType = m[1].toLowerCase();
  if (!ALLOWED_PHOTO.has(contentType)) throw Object.assign(new Error('unsupported_type'), { status: 415 });
  const bytes = Buffer.from(m[2], 'base64');
  if (bytes.length <= 0 || bytes.length > MAX_PHOTO_BYTES) {
    throw Object.assign(new Error('file_too_large'), { status: 413 });
  }
  const { storagePath } = await uploadUserPhoto(orgId, uid, bytes, contentType);
  await sql`UPDATE users SET photo_storage_path=${storagePath}, photo_updated_at=now() WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  return { ok: true, photoUrl: await signedReadUrl(storagePath) };
}

// verifyFirebasePassword returns { uid, email } from Identity Toolkit, and that
// uid is authoritative — the caller just proved they own that account. No second
// lookup needed.
export async function changePassword(email, currentPassword, newPassword) {
  const verified = await verifyFirebasePassword(email, currentPassword);
  if (!verified) throw Object.assign(new Error('Current password is incorrect'), { status: 400 });
  const { auth } = firebaseAdmin();
  try {
    await auth.updateUser(verified.uid, { password: newPassword });
    await auth.revokeRefreshTokens(verified.uid);
  } catch (err) {
    throw firebaseAuthError(err);
  }
  return { ok: true };
}

// Change a user's login email. This is an IDENTITY change, not a profile edit:
// the address is the Firebase Auth credential they sign in with and the one
// password-reset mail goes to, so it lives in its own function with its own
// guards rather than inside updateEmployee.
//
// Firebase first, then Neon: Firebase is the side that can reject a duplicate,
// and since nothing resolves an account by email any more (resolveUid is gone),
// a Neon failure afterwards leaves only a stale display value — which
// scripts/audit-auth-links.mjs reports as EMAIL_SKEW. The reverse order could
// hand out a login the database doesn't know about.
export async function setEmployeeEmail(uid, email, orgId) {
  const { auth } = firebaseAdmin();
  const next = String(email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(next)) {
    throw Object.assign(new Error('That is not a valid email address.'), { status: 400, code: 'invalid_email' });
  }

  const rows = await sql`SELECT email, role FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (!rows.length) throw Object.assign(new Error('not_found'), { status: 404 });
  const current = String(rows[0].email || '').trim().toLowerCase();
  if (current === next) return { ok: true, email: current, changed: false };

  // users.email has no unique index, so guard the collision here rather than
  // letting two rows silently share an address.
  const clash = await sql`
    SELECT firebase_uid FROM users
    WHERE org_id=${orgId} AND lower(trim(email))=${next} AND firebase_uid <> ${uid}
  `;
  if (clash.length) {
    throw Object.assign(new Error('Another employee already uses that email.'), { status: 409, code: 'email_in_use' });
  }

  try {
    // emailVerified resets: the new address has not been proven yet.
    await auth.updateUser(uid, { email: next, emailVerified: false });
  } catch (err) {
    throw firebaseAuthError(err);
  }
  await sql`UPDATE users SET email=${next} WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  // Claims embed the email, and the sign-in identity just changed, so drop
  // existing sessions. Best-effort — the row is the source of truth at login.
  try {
    await auth.setCustomUserClaims(uid, { role: String(rows[0].role || '').toUpperCase(), orgId, email: next });
    await auth.revokeRefreshTokens(uid);
  } catch { /* non-fatal */ }

  return { ok: true, email: next, changed: true, previousEmail: current || null };
}

// Org-wide version of diagnoseAuthLink, for when you need to know whether a
// broken sign-in is one row or the whole org — and, crucially, WHICH Firebase
// project the running deployment is talking to. scripts/audit-auth-links.mjs
// answers the same question from a laptop, but it can only ever use local
// credentials; this runs wherever it is deployed, so it reports the truth about
// that environment. Strictly read-only.
export async function auditAuthLinks(orgId) {
  const { app, auth } = firebaseAdmin();
  const rows = await sql`SELECT firebase_uid, email, name, role FROM users WHERE org_id=${orgId} ORDER BY role, email`;

  // One getUsers() call per 100 rows instead of one getUser() per row.
  const found = new Map();
  const missing = new Set();
  for (let i = 0; i < rows.length; i += 100) {
    const chunk = rows.slice(i, i + 100);
    const res = await auth.getUsers(chunk.map((r) => ({ uid: r.firebase_uid })));
    for (const u of res.users) found.set(u.uid, u);
    for (const nf of res.notFound) missing.add(nf.uid);
  }

  const counts = new Map();
  const findings = [];
  for (const r of rows) {
    const email = String(r.email || '').trim().toLowerCase();
    let state;
    let detail = null;

    if (!email) {
      state = 'NO_EMAIL';
    } else if (missing.has(r.firebase_uid)) {
      // No account at this uid — is the address free, or owned by another uid?
      let owner = null;
      try {
        owner = (await auth.getUserByEmail(email)).uid;
      } catch (err) {
        if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
      }
      state = owner ? 'UID_CONFLICT' : 'ORPHAN';
      if (owner) detail = `email belongs to Auth uid ${owner}`;
    } else {
      const authEmail = String(found.get(r.firebase_uid)?.email || '');
      if (authEmail.toLowerCase() !== email) {
        state = 'EMAIL_SKEW';
        detail = `Auth has "${authEmail || '—'}"`;
      } else {
        state = 'OK';
      }
    }

    counts.set(state, (counts.get(state) || 0) + 1);
    if (state !== 'OK') findings.push({ uid: r.firebase_uid, email: r.email, name: r.name, role: r.role, state, detail });
  }

  return {
    // The whole point of running this in-environment: name the project.
    firebaseProjectId: app.options?.projectId ?? null,
    orgId,
    total: rows.length,
    counts: Object.fromEntries(counts),
    healthy: findings.length === 0,
    findings,
  };
}

// ---- Neon <-> Firebase Auth reconciliation ---------------------------------
// A users row whose firebase_uid has no Firebase Auth account behind it (an
// "orphan") breaks every Auth-touching admin action. repairAuthAccount rebuilds
// the missing account AT THE SAME UID, so attendance_events.uid, team leadership,
// face embeddings, login devices and the photo storage path (users/{orgId}/{uid})
// all stay attached — there are no FK constraints to cascade (see db/schema.sql),
// so allocating a new uid would silently orphan every one of them.
//
// SECURITY: uid, email, name and role are read back from the row and are NEVER
// taken from the client. Web login resolves the caller's role from the users row
// keyed by Firebase uid, so creating an account at a chosen uid mints credentials
// carrying that row's role. Deriving everything from the row makes this strictly
// a reconciliation of state the database already asserts. Callers must also apply
// the target-role ceiling (enforced again below, defensively).
const REPAIRABLE_ROLES = new Set(['EMPLOYEE', 'IT_TEAM', 'DEV']);

// Shared read for diagnose + repair. Returns the row plus its normalized email,
// or throws the same tagged errors both paths need.
async function loadAuthLinkTarget(uid, orgId) {
  const rows = await sql`SELECT firebase_uid, email, name, role FROM users WHERE firebase_uid=${uid} AND org_id=${orgId}`;
  if (rows.length !== 1) throw Object.assign(new Error('not_found'), { status: 404 });
  const row = rows[0];
  const email = String(row.email || '').trim().toLowerCase();
  // users.email carries no unique constraint, so a collision would make any
  // email-keyed decision ambiguous. Refuse rather than guess.
  let duplicates = 0;
  if (email) {
    const dupes = await sql`SELECT firebase_uid FROM users WHERE org_id=${orgId} AND lower(trim(email))=${email}`;
    duplicates = dupes.length;
  }
  return {
    uid: row.firebase_uid,
    email,
    name: row.name ?? null,
    role: String(row.role || '').toUpperCase(),
    duplicates,
  };
}

// Non-mutating. Drives the UI affordance and the admin's understanding of what
// is actually wrong before they act.
export async function diagnoseAuthLink(uid, orgId) {
  const { auth } = firebaseAdmin();
  const t = await loadAuthLinkTarget(uid, orgId);
  const base = { uid: t.uid, email: t.email, name: t.name, role: t.role, authUid: null, authEmail: null, canRepair: false };

  if (!t.email) return { ...base, state: 'no_email', detail: 'This profile has no email on file.' };
  if (t.duplicates > 1) {
    return { ...base, state: 'duplicate_email', detail: `${t.duplicates} profiles share this email — de-duplicate them first.` };
  }

  let rec = null;
  try {
    rec = await auth.getUser(t.uid);
  } catch (err) {
    if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
  }

  if (rec) {
    const authEmail = String(rec.email || '');
    if (authEmail.toLowerCase() !== t.email) {
      // Harmless since nothing resolves accounts by email any more; reported so
      // the mismatch is visible rather than silent.
      return { ...base, state: 'email_skew', authUid: rec.uid, authEmail, detail: `Sign-in account exists, but its email is "${authEmail || '—'}".` };
    }
    return { ...base, state: 'ok', authUid: rec.uid, authEmail, detail: 'Profile and sign-in account are linked.' };
  }

  // No account at this uid. Is the email free?
  try {
    const other = await auth.getUserByEmail(t.email);
    return {
      ...base,
      state: 'uid_conflict',
      authUid: other.uid,
      detail: `That email already belongs to a different sign-in account (${other.uid}). Fix the email on the profile first.`,
    };
  } catch (err) {
    if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
  }

  return {
    ...base,
    state: 'missing',
    canRepair: REPAIRABLE_ROLES.has(t.role),
    detail: 'No sign-in account exists for this profile. It can be rebuilt at the same id.',
  };
}

// Rebuild the missing Firebase Auth account. Creates only — it will NEVER call
// auth.updateUser to set a password on an existing account, which would turn
// repair into a password reset that bypasses the role ladder in the
// reset-password route and make it strictly more powerful than that flow.
export async function repairAuthAccount(uid, orgId) {
  const { auth } = firebaseAdmin();
  const t = await loadAuthLinkTarget(uid, orgId);

  if (!t.email) throw Object.assign(new Error('This user has no email on file — add one before repairing.'), { status: 400, code: 'no_email' });
  if (!EMAIL_RE.test(t.email)) throw Object.assign(new Error('The email on file is not a valid address. Fix it, then try again.'), { status: 400, code: 'invalid_email' });
  if (t.duplicates > 1) throw Object.assign(new Error('Another profile shares this email. De-duplicate them before repairing.'), { status: 409, code: 'duplicate_email_rows' });
  // Defence in depth — the route applies this ceiling too. Fails closed on an
  // unknown or NULL role.
  if (!REPAIRABLE_ROLES.has(t.role)) {
    throw Object.assign(new Error('This account’s sign-in cannot be rebuilt here.'), { status: 403, code: 'unsupported_target_role' });
  }

  // Must genuinely have no account. A network/permission failure must never be
  // read as "no account", so only auth/user-not-found continues.
  let existing = null;
  try {
    existing = await auth.getUser(t.uid);
  } catch (err) {
    if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
  }
  if (existing) {
    throw Object.assign(new Error('This employee already has a sign-in account. Use Reset password instead.'), { status: 409, code: 'auth_account_exists' });
  }

  // The email must be unclaimed. If it belongs to another uid the row's PK is
  // stale (or the email is a typo pointing at a real person) — creating an
  // account is the wrong remedy for both, so stop.
  let emailOwner = null;
  try {
    emailOwner = await auth.getUserByEmail(t.email);
  } catch (err) {
    if (err?.code !== 'auth/user-not-found') throw firebaseAuthError(err);
  }
  if (emailOwner) {
    throw Object.assign(
      new Error(`That email already belongs to a different sign-in account (${emailOwner.uid}). Fix the email on the profile first.`),
      { status: 409, code: 'email_bound_to_other_uid', body: { authUid: emailOwner.uid } },
    );
  }

  const tempPassword = newTempPassword();
  try {
    await auth.createUser({
      uid: t.uid,
      email: t.email,
      password: tempPassword,
      displayName: t.name || undefined,
      emailVerified: false,
    });
  } catch (err) {
    throw firebaseAuthError(err);
  }
  // Best-effort, as in createEmployee: the account now exists, so failing the
  // whole repair over claims would report failure for work that succeeded and
  // leave the admin retrying into auth_account_exists.
  try {
    await auth.setCustomUserClaims(t.uid, { role: t.role, orgId, email: t.email });
  } catch { /* non-fatal — users.role is the source of truth at login */ }
  await sql`UPDATE users SET must_change_password=true WHERE firebase_uid=${t.uid} AND org_id=${orgId}`;

  return { ok: true, action: 'created', uid: t.uid, email: t.email, name: t.name, role: t.role, temporaryPassword: tempPassword };
}

export async function writeAuditLog(orgId, actorUid, action, targetId, metadata) {
  const { text, params } = buildInsert(
    'audit_logs',
    {
      orgId,
      actorUid,
      action,
      targetId,
      metadata: metadata ?? null,
    },
    { jsonbKeys: ['metadata'] },
  );
  await sql.query(text, params);
}
