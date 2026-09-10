// Drop-in replacement for the old src/lib/attenddesk.js HTTP client. Same
// function names + return shapes, but backed directly by Firestore/Firebase
// (single org, shared AttendDesk project). Routes only swap their import path
// from '@/lib/attenddesk' to '@/lib/backend'. The trailing orgId arg now equals
// the pinned ORG_ID the login JWT carries.

import { sql } from './db';
import { processCheckIn, listAttendance } from './services/attendance';

export { signedReadUrls } from './storage';

export { addManualAttendance } from './services/attendance';

export {
  getEmployees,
  getEmployee,
  createEmployee,
  setEmployeeTeam,
  setEmployeeRole,
  setEmployeeEmail,
  updateEmployee,
  deleteEmployee,
  resetUserPassword,
  enrollFace,
  resetFace,
  uploadPhoto,
  changePassword,
  diagnoseAuthLink,
  repairAuthAccount,
  auditAuthLinks,
  writeAuditLog,
} from './services/users';
export { enforceLoginGuards, resetUserDevices, setUserLoginIps, isRestrictedRole, MAX_LOGIN_DEVICES } from './services/loginGuard';
export { getLeaveRequests, submitLeave, decideLeave } from './services/leave';
export { getAssetRequests, createAssetRequest, decideAssetRequest } from './services/assets';
export { getTeams, createTeam, updateTeam, deleteTeam, listLedTeamMemberUids, isManager, canManageUser, getLineManager } from './services/teams';
export { assignManagementRole, DEPARTMENTS } from './services/management';
export { getAccessories, createAccessory, deleteAccessory } from './services/accessories';
export { getTracking, createTracking, deleteTracking } from './services/tracking';
export { getReconRequests, submitRecon, decideRecon, getRecon } from './services/recon';
export { getRemoteRequests, submitRemote, decideRemote, getRemote } from './services/remote';
export { listNotices, createNotice, deleteNotice } from './services/notices';
export { recordBreak, listMyBreaks } from './services/breaks';

export { getHolidays, createHoliday, deleteHoliday } from './services/holidays';
export { getOffice, updateOffice } from './services/office';
export { getPolicy, updatePolicy } from './services/policy';

// Attendance read: { events } with nested user, same as the old wrapper.
export function getAttendance(query = {}, orgId) {
  return listAttendance(orgId, query);
}

// Check-in: body carries userId (forced from the token by the route). We look
// up the email for the event record, then run the full anti-cheat pipeline.
export async function checkIn(body, orgId) {
  const rows = await sql`SELECT email FROM users WHERE firebase_uid = ${body.userId} AND org_id = ${orgId}`;
  if (!rows.length) throw Object.assign(new Error('user_not_found'), { status: 404 });
  const email = rows[0].email ?? '';
  return processCheckIn(body.userId, orgId, email, body);
}

// Trigger Firebase's own password-reset email (Identity Toolkit). The caller
// (forgot route) always responds ok, so swallow per-address errors here.
export async function forgotPassword(email) {
  const apiKey = process.env.NEXT_PUBLIC_FIREBASE_API_KEY;
  if (!apiKey) return { ok: true };
  try {
    await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestType: 'PASSWORD_RESET', email: String(email).toLowerCase() }),
      cache: 'no-store',
    });
  } catch {
    // ignore — don't reveal whether the address exists
  }
  return { ok: true };
}
