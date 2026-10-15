const INTERESTING_HEADERS = [
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator',
  'x-drupal-cache', 'x-shopify-stage', 'cf-ray', 'x-amz-cf-id', 'via', 'x-backend-server',
];

export default {
  id: 's03',
  name: 'HTTP/HTTPS Discovery',
  tools: ['httpx'],
  async run(ctx) {
    const t = ctx.getTarget();
    if (!t) throw new Error('no-target');
    const base = t.url.toString().replace(/\/+$/, '');

    const main = await ctx.fetch(base, { maxBytes: 256 * 1024 });
    const bodyText = main.body ? main.body.toString('utf8', 0, 256 * 1024) : '';
    ctx.store.http = {
      status: main.status, headers: main.headers, bodySnippet: bodyText.slice(0, 32_768),
      finalUrl: main.finalUrl, redirects: main.redirectCount,
    };
    ctx.log('info', `GET ${base} → ${main.status} (${main.body?.length ?? 0} bytes, ${main.redirectCount} redirects)`);

    // common endpoints (GET with small cap; HEAD where possible)
    const endpoints = [];
    const paths = ['/robots.txt', '/sitemap.xml', '/favicon.ico', '/security.txt', '/.well-known/security.txt'];
    for (const p of paths) {
      if (ctx.signal.aborted) throw new Error('cancelled');
      try {
        const r = await ctx.fetch(base + p, { maxBytes: 64 * 1024, timeoutMs: 10_000 });
        endpoints.push({
          path: p, status: r.status, contentType: r.headers['content-type'] || null,
          length: r.body?.length ?? 0,
          snippet: p.includes('robots') && r.body ? r.body.toString('utf8', 0, 2000) : undefined,
        });
      } catch (e) {
        endpoints.push({ path: p, error: e.code || e.message });
      }
    }
    ctx.store.endpoints = endpoints;

    // harvest links/params for later stages (bounded)
    const urls = new Set();
    const paramUrls = new Set();
    const linkRe = /(?:href|src|action)=["']([^"']{1,300})["']/gi;
    let m;
    while ((m = linkRe.exec(bodyText)) && urls.size < 60) {
      try {
        const abs = new URL(m[1], base).toString();
        if (abs.startsWith('http')) {
          urls.add(abs.split('#')[0]);
          if (abs.includes('?')) paramUrls.add(abs);
        }
      } catch { /* ignore bad links */ }
    }
    ctx.store.discoveredUrls = [...urls].slice(0, 40);
    ctx.store.paramUrls = [...paramUrls].slice(0, 15);

    // tech hints from headers
    const banners = {};
    for (const h of INTERESTING_HEADERS) if (main.headers[h]) banners[h] = main.headers[h];
    ctx.store.banners = banners;

    ctx.setSummary({
      status: main.status, finalUrl: main.finalUrl, redirects: main.redirectCount,
      server: main.headers['server'] || null, poweredBy: main.headers['x-powered-by'] || null,
      endpoints, discoveredUrls: ctx.store.discoveredUrls.length, paramUrls: ctx.store.paramUrls.length,
    });
    return { summary: ctx._summary };
  },
};
