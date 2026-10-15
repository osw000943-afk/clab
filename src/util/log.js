import fs from 'node:fs';
import path from 'node:path';
import { config } from '../config.js';

const MAX_LINE = 4096;

function safe(v) {
  let s;
  try {
    s = typeof v === 'string' ? v : JSON.stringify(v);
  } catch {
    s = String(v);
  }
  if (s.length > MAX_LINE) s = s.slice(0, MAX_LINE) + '…[truncated]';
  return s.replace(/\r?\n/g, ' | ');
}

/** Redact obvious secrets before they reach disk. */
export function redact(s) {
  return String(s)
    .replace(/(api[_-]?key|authorization|token|password|secret)["']?\s*[:=]\s*["']?[\w\-./+]{8,}/gi, '$1=[REDACTED]')
    .replace(/Bearer\s+[\w\-./+]{8,}/gi, 'Bearer [REDACTED]');
}

class RotatingFile {
  constructor(dir, base, maxKB, keep) {
    this.file = path.join(dir, `${base}.log`);
    this.maxBytes = maxKB * 1024;
    this.keep = keep;
    fs.mkdirSync(dir, { recursive: true });
  }
  write(line) {
    try {
      let size = 0;
      try {
        size = fs.statSync(this.file).size;
      } catch {}
      if (size > this.maxBytes) this.rotate();
      fs.appendFileSync(this.file, line + '\n');
    } catch {
      /* logging must never crash the server */
    }
  }
  rotate() {
    for (let i = this.keep - 1; i >= 1; i--) {
      const from = `${this.file}.${i}`;
      const to = `${this.file}.${i + 1}`;
      if (fs.existsSync(from)) fs.renameSync(from, to);
    }
    if (fs.existsSync(this.file)) fs.renameSync(this.file, `${this.file}.1`);
  }
}

const fileSink = new RotatingFile(config.logDir, 'clab', config.logMaxKB, config.logKeep);

function emit(level, args) {
  const line = `${new Date().toISOString()} [${level}] ${args.map((a) => safe(redact(a))).join(' ')}`;
  fileSink.write(line);
  if (config.isDev || level === 'ERROR') process.stdout.write(line + '\n');
}

export const log = {
  info: (...a) => emit('INFO', a),
  warn: (...a) => emit('WARN', a),
  error: (...a) => emit('ERROR', a),
  debug: (...a) => {
    if (config.isDev) emit('DEBUG', a);
  },
};
