let csrfToken = null;

export function setCsrf(tok) { csrfToken = tok; }
export function getCsrf() { return csrfToken; }

class ApiError extends Error {
  constructor(status, body) {
    super((body && (body.message || body.error)) || 'HTTP ' + status);
    this.status = status;
    this.code = body && body.error;
  }
}

export async function api(path, { method = 'GET', body, headers } = {}) {
  const opts = {
    method,
    headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...(headers || {}) },
    credentials: 'same-origin',
  };
  if (method !== 'GET' && csrfToken) opts.headers['x-csrf-token'] = csrfToken;
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch { /* non-json */ }
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('clab:unauthorized', { detail: data }));
    throw new ApiError(401, data);
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

/** Open an authenticated SSE stream with automatic reconnect. */
export function openStream(path, handlers = {}) {
  let es;
  let closed = false;
  let retry = 1000;

  const connect = () => {
    es = new EventSource(path, { withCredentials: true });
    const on = (type) => es.addEventListener(type, (ev) => {
      retry = 1000;
      try { handlers[type] && handlers[type](JSON.parse(ev.data)); } catch { /* bad frame */ }
    });
    ['snapshot', 'log', 'finding', 'stage-status', 'progress', 'scan-status', 'worker', 'heartbeat'].forEach(on);
    es.onerror = () => {
      if (closed) return;
      handlers.onerror && handlers.onerror();
      es.close();
      setTimeout(connect, retry);
      retry = Math.min(retry * 1.7, 10000);
    };
  };
  connect();
  return { close() { closed = true; try { es && es.close(); } catch { /* */ } } };
}
