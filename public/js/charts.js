/* Dependency-free SVG charts (works offline, no CDN) */

const SEV_COLORS = { critical: '#7F1D1D', high: '#B91C1C', medium: '#D97706', low: '#A16207', informational: '#0369A1' };

export function donut(data, { size = 168, thickness = 22 } = {}) {
  const total = Object.values(data).reduce((a, b) => a + b, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  if (!total) return emptyChart(size, size);
  let offset = 0;
  const segs = [];
  for (const [k, v] of Object.entries(data)) {
    if (!v) continue;
    const frac = v / total;
    segs.push(`<circle r="${r}" cx="${size / 2}" cy="${size / 2}" fill="none"
      stroke="${SEV_COLORS[k] || '#64748B'}" stroke-width="${thickness}"
      stroke-dasharray="${(frac * c - 2).toFixed(2)} ${(c - frac * c + 2).toFixed(2)}"
      stroke-dashoffset="${(-offset * c).toFixed(2)}"
      transform="rotate(-90 ${size / 2} ${size / 2})"><title>${k}: ${v}</title></circle>`);
    offset += frac;
  }
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="severity donut">
    ${segs.join('')}
    <text x="${size / 2}" y="${size / 2 - 4}" text-anchor="middle" font-size="26" font-weight="750" fill="#0F172A">${total}</text>
    <text x="${size / 2}" y="${size / 2 + 16}" text-anchor="middle" font-size="11" fill="#64748B">findings</text>
  </svg>`;
}

export function legend(data) {
  return '<div class="chart-legend">' + Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => `<span><i style="background:${SEV_COLORS[k] || '#64748B'}"></i>${k} · <b>${v}</b></span>`)
    .join('') + '</div>';
}

export function bars(items, { width = 460, height = 170, unit = '%' } = {}) {
  if (!items.length) return emptyChart(width, height);
  const pad = { l: 8, r: 8, t: 18, b: 34 };
  const iw = width - pad.l - pad.r;
  const ih = height - pad.t - pad.b;
  const bw = Math.min(46, (iw / items.length) * 0.62);
  const gap = iw / items.length;
  const maxV = Math.max(...items.map((i) => i.value), 1);
  const barsSvg = items.map((it, idx) => {
    const h = (it.value / maxV) * ih;
    const x = pad.l + gap * idx + (gap - bw) / 2;
    const y = pad.t + ih - h;
    return `<g><rect class="bar" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(h, 1.5).toFixed(1)}" rx="4" fill="${it.color || '#1E40AF'}"><title>${it.label}: ${it.value}${unit}</title></rect>
      <text x="${(x + bw / 2).toFixed(1)}" y="${(y - 5).toFixed(1)}" text-anchor="middle" font-size="11" font-weight="700" fill="#334155">${it.value}${unit}</text>
      <text x="${(x + bw / 2).toFixed(1)}" y="${height - 16}" text-anchor="middle" font-size="10.5" fill="#64748B">${truncate(it.label, 9)}</text></g>`;
  }).join('');
  return `<svg viewBox="0 0 ${width} ${height}" width="100%" role="img" aria-label="bar chart">
    <line x1="${pad.l}" y1="${height - pad.b + 4}" x2="${width - pad.r}" y2="${height - pad.b + 4}" stroke="#E2E8F0"/>
    ${barsSvg}</svg>`;
}

export function line(points, { width = 460, height = 170, labelKey = 'label', valueKey = 'value' } = {}) {
  if (!points.length) return emptyChart(width, height);
  const pad = { l: 26, r: 10, t: 14, b: 30 };
  const iw = width - pad.l - pad.r;
  const ih = height - pad.t - pad.b;
  const maxV = Math.max(...points.map((p) => p[valueKey]), 1);
  const step = points.length > 1 ? iw / (points.length - 1) : 0;
  const xy = points.map((p, i) => [pad.l + i * step, pad.t + ih - (p[valueKey] / maxV) * ih]);
  const path = xy.map(([x, y], i) => (i ? 'L' : 'M') + x.toFixed(1) + ',' + y.toFixed(1)).join(' ');
  const area = path + ` L${(xy[xy.length - 1][0]).toFixed(1)},${pad.t + ih} L${xy[0][0].toFixed(1)},${pad.t + ih} Z`;
  const dots = xy.map(([x, y], i) => `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.4" fill="#1E40AF"><title>${points[i][labelKey]}: ${points[i][valueKey]}</title></circle>`).join('');
  const xLabels = points.map(([x, y], i) => (i % Math.ceil(points.length / 6 || 1) === 0)
    ? `<text x="${x.toFixed(1)}" y="${height - 10}" text-anchor="middle" font-size="9.5" fill="#94A3B8">${truncate(String(points[i][labelKey]), 8)}</text>` : '').join('');
  return `<svg viewBox="0 0 ${width} ${height}" width="100%" role="img" aria-label="line chart">
    <defs><linearGradient id="lg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#1E40AF" stop-opacity=".18"/><stop offset="100%" stop-color="#1E40AF" stop-opacity="0"/>
    </linearGradient></defs>
    <line x1="${pad.l}" y1="${pad.t}" x2="${pad.l}" y2="${pad.t + ih}" stroke="#E2E8F0"/>
    <line x1="${pad.l}" y1="${pad.t + ih}" x2="${width - pad.r}" y2="${pad.t + ih}" stroke="#E2E8F0"/>
    <text x="4" y="${pad.t + 8}" font-size="9.5" fill="#94A3B8">${maxV}</text>
    <text x="4" y="${pad.t + ih}" font-size="9.5" fill="#94A3B8">0</text>
    <path d="${area}" fill="url(#lg)"/>
    <path d="${path}" fill="none" stroke="#1E40AF" stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>
    ${dots}${xLabels}</svg>`;
}

function emptyChart(w, h) {
  return `<div class="empty" style="padding:28px 14px"><div class="ico">⌀</div><p>—</p></div>`;
}
function truncate(s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }
export { SEV_COLORS };
