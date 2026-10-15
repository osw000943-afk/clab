import tls from 'node:tls';
import fs from 'node:fs';
import { q } from '../../db.js';
import { decryptSecret } from '../../security/crypto.js';
import { assertHostPortAllowed, tcpProbe, resolveHost, isBlockedIp } from '../../security/scope.js';

/**
 * Database Security Audit — READ-ONLY by design:
 * exposure check, TLS negotiation, auth with owner-provided credentials,
 * privilege/role inspection via metadata queries only.
 * Never dumps rows, never modifies schema/permissions.
 * Drivers loaded dynamically: pg (PostgreSQL), mysql2 (MySQL/MariaDB);
 * MongoDB: exposure + TLS + hello probe natively (deep checks need driver);
 * SQLite: local file checks.
 */
export default {
  id: 's21',
  name: 'Database Security Audit',
  tools: [],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const targetIds = opts.dbTargetIds || [];
    const targets = q('SELECT * FROM db_targets').filter((t) => !targetIds.length || targetIds.includes(t.id));
    if (!targets.length) {
      ctx.log('info', 'Chưa có DB target nào được cấu hình (Settings → Database Targets)');
      ctx.setSummary({ skipped: 'no-db-targets' });
      return { summary: ctx._summary };
    }
    const results = [];
    for (const dt of targets) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      if (!dt.scope_confirmed) {
        results.push({ id: dt.id, name: dt.name, skipped: 'scope-not-confirmed' });
        continue;
      }
      try {
        if (dt.db_type === 'sqlite') {
          results.push(await auditSqlite(ctx, dt));
        } else {
          results.push(await auditNetwork(ctx, dt));
        }
      } catch (e) {
        results.push({ id: dt.id, name: dt.name, error: e.message.slice(0, 200) });
        ctx.log('error', 'DB audit ' + dt.name + ' failed: ' + e.message);
      }
    }
    ctx.setSummary({ targets: results.length, results });
    return { summary: ctx._summary };
  },
};

async function auditSqlite(ctx, dt) {
  const out = { id: dt.id, name: dt.name, type: 'sqlite' };
  const file = dt.host; // for sqlite, host stores the file path
  if (!fs.existsSync(file)) {
    out.error = 'file-not-found';
    return out;
  }
  const st = fs.statSync(file);
  out.sizeBytes = st.size;
  const mode = (st.mode & 0o777).toString(8);
  out.permissions = mode;
  if ((st.mode & 0o007) !== 0) {
    ctx.addFinding({
      asset: file, stageId: 's21', tool: 'builtin-sqlite', severity: 'medium', confidence: 'high',
      title: 'File SQLite có quyền world-accessible',
      description: 'File DB (mode ' + mode + ') cho phép user khác trên máy đọc/ghi.',
      evidence: 'path=' + file + ' mode=' + mode,
      recommendation: 'Giới hạn quyền 600 và đặt ngoài web root.', verification: 'confirmed',
    });
  }
  // check if encrypted (SQLCipher) — first 16 bytes not 'SQLite format 3'
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(16);
  fs.readSync(fd, buf, 0, 16, 0);
  fs.closeSync(fd);
  out.encrypted = buf.toString('utf8', 0, 15) !== 'SQLite format 3';
  out.note = 'Chi kiểm tra metadata file, không đọc nội dung bản ghi.';
  return out;
}

async function auditNetwork(ctx, dt) {
  const out = { id: dt.id, name: dt.name, type: dt.db_type, host: dt.host, port: dt.port };
  const defPorts = { postgres: 5432, mysql: 3306, mongodb: 27017 };

  // 1. Scope + exposure
  await assertHostPortAllowed(dt.host, dt.port);
  const probe = await tcpProbe(dt.host, dt.port, 5000);
  out.exposed = probe.open;
  if (!probe.open) {
    out.error = 'not-reachable: ' + (probe.error || 'closed');
    return out;
  }
  ctx.addFinding({
    asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'builtin-db-probe',
    severity: 'informational', confidence: 'high',
    title: 'Cổng DB ' + dt.db_type + ' phản hồi kết nối / Database port reachable',
    description: 'Cổng ' + dt.port + ' của ' + dt.db_type + ' accept kết nối từ vị trí quét. Đây là kiểm tra reachability, không phải bằng chứng bị xâm nhập.',
    evidence: 'tcp connect ok (' + dt.host + ':' + dt.port + ')',
    component: dt.db_type, recommendation: 'Xác nhận chỉ các IP được phép truy cập cổng này ở firewall.',
    verification: 'confirmed',
  });

  // 2. TLS negotiation
  out.tls = await new Promise((resolve) => {
    let done = false;
    const fin = (r) => { if (!done) { done = true; resolve(r); } };
    try {
      const s = tls.connect({ host: dt.host, port: dt.port, rejectUnauthorized: false, timeout: 6000,
        servername: dt.host, ALPNProtocols: ['mongodb'] }, () => {
        const c = s.getPeerCertificate();
        fin({ negotiated: true, protocol: s.getProtocol(), subject: c && c.subject, valid_to: c && c.valid_to });
        s.end();
      });
      s.on('error', (e) => fin({ negotiated: false, error: e.message.slice(0, 120) }));
      s.on('timeout', () => { s.destroy(); fin({ negotiated: false, error: 'timeout' }); });
    } catch (e) { fin({ negotiated: false, error: e.message }); }
  });
  if (!out.tls.negotiated && ['postgres', 'mysql'].includes(dt.db_type)) {
    ctx.addFinding({
      asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'builtin-db-probe', severity: 'medium', confidence: 'medium',
      title: dt.db_type + ' không hỗ trợ TLS (handshake thất bại)',
      description: 'Không thương lượng được TLS tới cổng DB — kết nối có thể bị chặn băng thông nếu đi qua mạng không tin cậy.',
      evidence: JSON.stringify(out.tls), component: dt.db_type + ' transport',
      recommendation: 'Bật TLS cho ' + dt.db_type + ' và yêu cầu sslmode/require.', verification: 'needs-verification',
    });
  }

  // 3. Auth + read-only metadata checks with owner-provided credentials
  if (!dt.secret_enc) {
    out.auth = 'no-credentials-provided (bỏ qua kiểm tra quyền)';
    return out;
  }
  let secret;
  try { secret = decryptSecret(dt.secret_enc); } catch { out.auth = 'decrypt-failed (kiểm tra ENCRYPTION_KEY)'; return out; }

  if (dt.db_type === 'postgres') out.pg = await auditPostgres(ctx, dt, secret);
  else if (dt.db_type === 'mysql') out.mysql = await auditMysql(ctx, dt, secret);
  else if (dt.db_type === 'mongodb') out.mongo = await auditMongodb(ctx, dt, secret);
  return out;
}

async function auditPostgres(ctx, dt, password) {
  let pg;
  try { pg = (await import('pg')).default; } catch { return { error: 'driver-missing: pg' }; }
  const client = new pg.Client({ host: dt.host, port: dt.port, database: 'postgres', user: dt.username,
    password, connectionTimeoutMillis: 8000, ssl: dt.tls_mode === 'require' ? { rejectUnauthorized: false } : undefined });
  try {
    await client.connect();
    const out = { authenticated: true };
    const one = async (sql) => (await client.query(sql)).rows.slice(0, 20);
    out.version = await one("SELECT version()");
    out.role = await one('SELECT current_user, session_user, usesuper FROM pg_user WHERE usename = current_user');
    out.ssl = await one("SELECT name, setting FROM pg_settings WHERE name IN ('ssl','password_encryption')");
    out.superusers = await one("SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolsuper = true LIMIT 10");
    out.excessiveGrants = await one("SELECT grantee, table_schema, privilege_type FROM information_schema.role_table_grants WHERE grantee NOT IN ('PUBLIC') LIMIT 15");
    out.publicSchemaWrite = await one("SELECT has_schema_privilege('public', 'CREATE') AS can_create");

    if (out.role[0] && out.role[0].usesuper) {
      ctx.addFinding({
        asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'pg', severity: 'medium', confidence: 'high',
        title: 'Tài khoản ứng dụng PostgreSQL là SUPERUSER',
        description: 'Ứng dụng kết nối bằng superuser — vi phạm least privilege; attacker qua SQLi có quyền toàn hệ thống.',
        evidence: JSON.stringify(out.role[0]), component: 'postgres roles',
        recommendation: 'Tạo role riêng chỉ cần SELECT/INSERT/UPDATE trên schema cần dùng.', verification: 'confirmed',
      });
    }
    const enc = out.ssl.find((s) => s.name === 'password_encryption');
    if (enc && !/scram/i.test(enc.setting)) {
      ctx.addFinding({
        asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'pg', severity: 'low', confidence: 'high',
        title: 'password_encryption không phải SCRAM: ' + enc.setting,
        description: 'PostgreSQL đang hash mật khẩu bằng cơ chế yếu hơn SCRAM-SHA-256.',
        evidence: JSON.stringify(enc), component: 'postgres auth',
        recommendation: "Đặt password_encryption = 'scram-sha-256' và đổi mật khẩu user.", verification: 'confirmed',
      });
    }
    return out;
  } catch (e) {
    return { authenticated: false, error: String(e.message).slice(0, 200) };
  } finally { await client.end().catch(() => {}); }
}

async function auditMysql(ctx, dt, password) {
  let mysql;
  try { mysql = (await import('mysql2/promise')).default; } catch { return { error: 'driver-missing: mysql2' }; }
  let conn;
  try {
    conn = await mysql.createConnection({ host: dt.host, port: dt.port, user: dt.username, password,
      connectTimeout: 8000, ssl: dt.tls_mode === 'require' ? { rejectUnauthorized: false } : undefined });
    const out = { authenticated: true };
    const one = async (sql) => { const [r] = await conn.query(sql); return (r || []).slice(0, 20); };
    out.version = (await one('SELECT VERSION() AS v'))[0];
    out.grants = await one('SHOW GRANTS FOR CURRENT_USER()');
    out.users = await one("SELECT user, host, account_locked FROM mysql.user LIMIT 15").catch(() => 'permission-denied');
    const grantsText = JSON.stringify(out.grants);
    if (/ALL PRIVILEGES|SUPER|FILE PRIVILEGE/i.test(grantsText)) {
      ctx.addFinding({
        asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'mysql2', severity: 'high', confidence: 'high',
        title: 'Tài khoản MySQL có quyền dư thừa (ALL/SUPER/FILE)',
        description: 'Tài khoản ứng dụng giữ quyền vượt quá nhu cầu — FILE/SUPER cho phép đọc file server và vượt qua mọi kiểm soát.',
        evidence: grantsText.slice(0, 800), component: 'mysql grants',
        recommendation: 'Cấp lại GRANT đúng mức cần thiết (SELECT/INSERT/UPDATE trên DB ứng dụng).', verification: 'confirmed',
      });
    }
    return out;
  } catch (e) {
    return { authenticated: false, error: String(e.message).slice(0, 200) };
  } finally { if (conn) await conn.end().catch(() => {}); }
}

async function auditMongodb(ctx, dt, password) {
  let mongodb;
  try { mongodb = (await import('mongodb')).MongoClient; } catch {
    return { error: 'driver-missing: mongodb (deep checks skipped — exposure + TLS đã kiểm tra)' };
  }
  const url = 'mongodb://' + encodeURIComponent(dt.username || 'x') + ':' + encodeURIComponent(password) + '@' + dt.host + ':' + dt.port + '/?authSource=admin&serverSelectionTimeoutMS=8000';
  const cli = new mongodb(url, { tls: dt.tls_mode === 'require' });
  try {
    await cli.connect();
    const out = { authenticated: true };
    const adm = cli.db('admin');
    out.buildInfo = (await adm.command({ buildInfo: 1 })).version;
    out.connections = await adm.command({ connectionStatus: 1 }).then((r) => ({ user: r.authInfo?.authenticatedUser, roles: r.authInfo?.authenticatedUserRoles })).catch(() => null);
    const users = await adm.command({ usersInfo: 1 }).catch(() => null);
    if (users?.users) {
      const weak = users.users.filter((u) => (u.credentials || []).some((c) => c.mechanism && !/SCRAM/i.test(c.mechanism)));
      out.userCount = users.users.length;
      if (weak.length) {
        ctx.addFinding({
          asset: dt.host + ':' + dt.port, stageId: 's21', tool: 'mongodb', severity: 'low', confidence: 'medium',
          title: 'MongoDB user dùng cơ chế xác thực yếu',
          description: weak.length + ' user không dùng SCRAM.',
          evidence: JSON.stringify(weak.map((u) => u.user)).slice(0, 300), component: 'mongodb auth',
          recommendation: 'Chuyển sang SCRAM-SHA-256; vô hiệu authMechanism cũ.', verification: 'needs-verification',
        });
      }
    }
    return out;
  } catch (e) {
    return { authenticated: false, error: String(e.message).slice(0, 200) };
  } finally { await cli.close().catch(() => {}); }
}
