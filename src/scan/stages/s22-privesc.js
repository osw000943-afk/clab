import { q, q1, decryptSecretSafe } from './_helpers.js';

/**
 * Privilege Escalation & Access Control Audit (User → Admin).
 * Uses owner-provided test accounts (Settings → Test Accounts).
 * Safe access attempts only: GET/HEAD compare responses across roles,
 * optional IDOR pair probing, HTTP-method authorization checks.
 * No account takeover, no role modification of real users.
 */
export default {
  id: 's22',
  name: 'Privilege Escalation & Access Control Audit',
  tools: [],
  async run(ctx) {
    const opts = JSON.parse(ctx.scan.options || '{}');
    const accounts = q('SELECT * FROM test_accounts');
    const enabled = accounts.filter((a) => !opts.testAccountIds || opts.testAccountIds.includes(a.id));
    if (enabled.length < 2) {
      ctx.log('info', 'Cần ít nhất 2 test accounts (mỗi role) — cấu hình ở Settings → Test Accounts');
      ctx.setSummary({ skipped: 'need-2-test-accounts', have: enabled.length });
      return { summary: ctx._summary };
    }
    const base = enabled[0].base_url.replace(/\/+$/, '');
    const endpoints = buildEndpointList(ctx, base, opts);
    const sessionByAccount = {};

    // login each test account (owner-provided credentials, own lab only)
    for (const acc of enabled) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      const secret = acc.secret_enc ? decryptSecretSafe(acc.secret_enc) : null;
      const headers = safeHeaders(acc.headers);
      sessionByAccount[acc.id] = { acc, headers, cookies: {} };
      const loginPath = opts.loginPath || '/api/auth/login';
      try {
        const r = await ctx.fetch(acc.base_url.replace(/\/+$/, '') + loginPath, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...headers },
          body: JSON.stringify({ username: acc.username, password: secret, email: acc.username }),
          maxBytes: 16384, timeoutMs: 10000,
        });
        const setCookie = r.headers['set-cookie'];
        if (setCookie) {
          const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
          sessionByAccount[acc.id].cookies = cookies.map((c) => c.split(';')[0]).join('; ');
          sessionByAccount[acc.id].loggedIn = r.status < 400;
        } else {
          sessionByAccount[acc.id].loggedIn = r.status < 400;
        }
        ctx.log('info', 'Test account ' + acc.label + ' (' + acc.role + '): login HTTP ' + r.status);
      } catch (e) {
        ctx.log('warn', 'Login thất bại cho ' + acc.label + ': ' + e.message);
        sessionByAccount[acc.id].loggedIn = false;
      }
    }

    const results = { endpointsTested: 0, anomalies: [] };
    const requester = async (accId, url, method = 'GET') => {
      const s = sessionByAccount[accId];
      const h = { ...s.headers };
      if (s.cookies) h.cookie = s.cookies;
      try {
        const r = await ctx.fetch(url, { method, headers: h, maxBytes: 16384, timeoutMs: 8000, includeBody: true });
        return { status: r.status, len: r.body ? r.body.length : 0,
          isLogin: /login|sign.in/i.test((r.body ? r.body.toString('utf8', 0, 2000) : '')),
          bodyHash: simpleHash(r.body ? r.body.toString('utf8', 0, 2000) : '') };
      } catch (e) { return { error: e.code || e.message.slice(0, 80) }; }
    };

    for (const url of endpoints) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      if (results.endpointsTested >= 25) break; // bounded
      results.endpointsTested++;
      const responses = {};
      for (const acc of enabled) responses[acc.id] = await requester(acc.id, url);

      const roles = enabled.map((a) => ({ role: a.role, id: a.id, r: responses[a.id] }));
      const nonPriv = roles.filter((x) => !/admin|owner|super/i.test(x.role));
      const priv = roles.filter((x) => /admin|owner|super/i.test(x.role));
      if (!nonPriv.length || !priv.length) continue;

      for (const np of nonPriv) {
        for (const pr of priv) {
          if (np.r.status && pr.r.status) {
            const privOk = pr.r.status >= 200 && pr.r.status < 300;
            const nonPrivOk = np.r.status >= 200 && np.r.status < 300 && !np.r.isLogin;
            const sameBody = np.r.bodyHash === pr.r.bodyHash && np.r.len > 100;
            if (privOk && nonPrivOk && (sameBody || /admin|role|permission|dashboard/i.test(url))) {
              results.anomalies.push({ url, lowRole: np.role, highRole: pr.role, lowStatus: np.r.status, highStatus: pr.r.status });
              ctx.addFinding({
                asset: url, stageId: 's22', tool: 'builtin-authz', severity: 'high', confidence: sameBody ? 'high' : 'medium',
                title: 'Vertical privilege escalation: role ' + np.role + ' truy cập được chức năng của ' + pr.role,
                description: 'Endpoint trả về thành công (HTTP ' + np.r.status + ') cho vai trò ' + np.role + ' — cùng nội dung với ' + pr.role + ' (hash khớp: ' + sameBody + ').',
                evidence: JSON.stringify({ url, low: np.r, high: pr.r }).slice(0, 600),
                component: url, recommendation: 'Kiểm tra authorization ở backend cho endpoint này (không tin vào frontend); thêm regression test.',
                verification: 'needs-verification',
              });
            }
          }
        }
      }

      // method authorization: DELETE/PUT/PATCH on non-priv session
      if (/\/(admin|users|settings|roles)/i.test(url)) {
        for (const method of ['DELETE', 'PUT', 'PATCH']) {
          const np = nonPriv[0];
          const r = await requester(np.id, url, method);
          if (r.status && r.status < 300 && r.status !== 405) {
            results.anomalies.push({ url, method, lowRole: np.role, status: r.status });
            ctx.addFinding({
              asset: url, stageId: 's22', tool: 'builtin-authz', severity: 'medium', confidence: 'medium',
              title: 'Broken function-level authorization: ' + method + ' được phép cho role ' + np.role,
              description: 'HTTP ' + method + ' trả về ' + r.status + ' với session vai trò thấp trên endpoint nhạy cảm.',
              evidence: JSON.stringify({ url, method, status: r.status }).slice(0, 400),
              component: url, recommendation: 'Từ chối method không thuộc vai trò ở tầng backend; bật allowlist method.',
              verification: 'needs-verification',
            });
          }
        }
      }
    }

    // IDOR probe if owner supplied object pairs: options.idorPairs = [{urlPattern, lowId, highId}]
    const pairs = (opts.idorPairs || []).slice(0, 5);
    for (const pair of pairs) {
      if (!pair.urlPattern || !pair.lowId || !pair.highId) continue;
      const np = enabled.find((a) => !/admin|owner|super/i.test(a.role)) || enabled[0];
      const otherUrl = pair.urlPattern.replace('{id}', String(pair.highId));
      const ownUrl = pair.urlPattern.replace('{id}', String(pair.lowId));
      const own = await requester(np.id, ownUrl);
      const other = await requester(np.id, otherUrl);
      if (own.status === 200 && other.status === 200 && own.bodyHash && own.bodyHash === other.bodyHash) {
        results.anomalies.push({ idor: otherUrl, role: np.role });
        ctx.addFinding({
          asset: otherUrl, stageId: 's22', tool: 'builtin-authz', severity: 'high', confidence: 'medium',
          title: 'Nghi vấn IDOR/BOLA: truy cập object của user khác',
          description: 'Session ' + np.role + ' GET object ' + pair.highId + ' trả về nội dung trùng với object của chính mình — dấu hiệu thiếu so sánh chủ sở hữu.',
          evidence: JSON.stringify({ ownUrl, otherUrl, sameBody: true }).slice(0, 400),
          component: otherUrl, recommendation: 'Kiểm tra ownership ở backend mỗi lần truy cập object; dùng UUID khó đoán.',
          verification: 'needs-verification',
        });
      }
    }

    ctx.setSummary(results);
    return { summary: ctx._summary };
  },
};

function buildEndpointList(ctx, base, opts) {
  const fromStore = (ctx.store.discoveredUrls || []).slice(0, 8);
  const common = [
    '/admin', '/admin/', '/api/admin', '/api/users', '/api/settings', '/settings',
    '/dashboard', '/api/roles', '/api/me', '/users', '/manage', '/api/v1/admin',
  ].map((p) => base + p).slice(0, 12);
  const owner = (opts.authzEndpoints || []).map((u) => u.slice(0, 400)).slice(0, 8);
  return [...new Set([...owner, ...common, ...fromStore])];
}

function safeHeaders(raw) {
  try {
    const h = JSON.parse(raw || '{}');
    const out = {};
    for (const [k, v] of Object.entries(h)) {
      if (!/^content-type|accept|x-requested-with|authorization$/i.test(k)) continue;
      out[k.toLowerCase()] = String(v).slice(0, 300);
    }
    return out;
  } catch { return {}; }
}

function simpleHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) | 0; }
  return h;
}
