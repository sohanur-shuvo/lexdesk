import { NextResponse } from 'next/server';
import { getUserFromRequest } from '@/lib/auth';
import { auditAuthLinks } from '@/lib/backend';

export const dynamic = 'force-dynamic';

// GET /api/admin/auth-audit — read-only reconciliation report for THIS
// deployment: which Firebase project it is actually configured with, and how
// every users row lines up against that project's Auth.
//
// scripts/audit-auth-links.mjs answers the same question locally, but it can
// only ever read local credentials. When production disagrees with a laptop —
// e.g. an employee whose sign-in works locally but 404s in production — the two
// environments are pointed at different Firebase projects, and only something
// running inside the deployment can prove it. This is that.
//
// Dev and superadmin only: the report lists every employee email in the org.
const canAudit = (user) => user.role === 'dev' || user.role === 'superadmin';

export async function GET(request) {
  const user = getUserFromRequest(request);
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  if (!canAudit(user)) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  if (!user.orgId) return NextResponse.json({ error: 'no_org_on_session' }, { status: 400 });

  try {
    return NextResponse.json(await auditAuthLinks(user.orgId));
  } catch (err) {
    return NextResponse.json(
      { error: err.message, code: err.code ?? null, upstream: err.body ?? null },
      { status: err.status || 502 },
    );
  }
}
