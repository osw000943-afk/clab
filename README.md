# clab — WhiteHat Lab

Nền tảng kiểm thử bảo mật website thực tế: scanner thật, dashboard VI/EN,
AI phân tích bằng chứng, lịch sử quét, Tool Registry, Skill Registry.
Chạy ổn định trên server 1 GB RAM (worker tuần tự, timeout mọi tool).

## 1. Yêu cầu

- Node.js ≥ 22.5 (dùng `node:sqlite` built-in, không cần build tool)
- npm ≥ 10
- Các scanner là optional — hệ thống tự phát hiện binary nào có/không có
  (`/api/tools`), stage nào thiếu tool sẽ `skipped` với lý do rõ ràng.

## 2. Cài đặt

```bash
npm install          # chỉ: express (+ pg, mysql2 cho DB audit module)
cp .env.example .env
npm run gen-key      # sinh SESSION_SECRET + ENCRYPTION_KEY -> ghi vào .env
npm run set-password # đặt mật khẩu chủ Lab (scrypt hash, không lưu plaintext)
```

## 3. Chạy

```bash
npm start            # production: http://127.0.0.1:3000
npm run dev          # development (stack trace chi tiết)
```

Health check (public, không secret): `GET /api/health`

## 4. Cấu hình AI qua giao diện web (không cần .env)

Đăng nhập → **Settings → AI Provider**:

1. Thêm provider: Base URL + Model ID + API key (OpenAI-compatible / Nemotron).
2. API key được mã hóa AES-256-GCM bằng `ENCRYPTION_KEY` (env-only, không nằm trong DB).
3. Nút *Test Connection*, *List Models*, *Test Model*, *Xoay key*, *Xóa key*.
4. Frontend chỉ thấy `api_key_hint` (4 ký tự cuối) — key không bao giờ trả về, không log, không vào báo cáo.
5. Nếu chưa cấu hình AI, mọi scanner vẫn chạy bình thường; finding có `ai_status=unavailable`.

## 5. Chế độ quét & module

- **quick / standard / deep / full** — Full Audit chạy đủ 24 stage (S01–S24, gồm DB audit,
  privesc, bypass, availability, correlation S19, deep audit S20).
- Mọi scan yêu cầu tick **xác nhận phạm vi + quyền kiểm thử** (bắt buộc ở API).
- Scope & Safety Engine chặn SSRF: loopback, link-local, cloud metadata
  **không bao giờ** được quét (kể cả `CLAB_ALLOW_PRIVATE=1` — flag này chỉ mở
  RFC1918 cho lab nội bộ được cấu hình riêng).
- Hàng đợi tuần tự (1 worker nặng), timeout từng tool, hủy giữa chừng (`POST /api/scans/:id/cancel`),
  restart không mất kết quả (trạng thái trong SQLite WAL).

## 6. Cài scanner (tùy chọn, theo nhu cầu)

```bash
# Kiểm tra tool nào đang thiếu:
curl -b cookie -H 'x-csrf-token: ...' http://127.0.0.1:3000/api/tools | python3 -m json.tool
```

| Tool | Cài đặt gợi ý (Debian/Ubuntu) |
|---|---|
| nmap, nikto, whatweb, sqlmap | `sudo apt install nmap nikto whatweb sqlmap` |
| httpx (ProjectDiscovery) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| testssl.sh | `git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh` |
| wpscan, dalfox | `gem install wpscan` / `go install github.com/hahwul/dalfox/v2@latest` |
| trivy, osv-scanner | xem docs chính thức (binary release) |
| semgrep | `pipx install semgrep` |
| gitleaks, checkov, retire | `go install ...` / `pipx install checkov` / `npm i -g retire` |
| tshark | `sudo apt install tshark` |

Tool nặng (ZAP, sqlmap, dalfox, availability load sim) có thể tắt ở Settings → System.

## 7. Kiểm thử

```bash
npm test   # unit (security.test.js) + integration (auth/SSRF/lifecycle/AI redaction)
```

Kết quả kỳ vọng: unit 4/4, integration 12/12 PASS.

## 8. Backup / restore / vận hành

```bash
npm run backup              # snapshot SQLite -> ./backups/clab-YYYYMMDD-HHmmss.db
# restore: dừng server, chép file backup đè lên $DB_PATH, khởi động lại
```

- Log xoay vòng trong `./logs` (`LOG_MAX_KB`/`LOG_KEEP`).
- Không chạy scan nặng tự động khi boot; tool lỗi không sập server (stage `failed` + tiếp tục).
- Giới hạn 1 GB RAM: worker tuần tự, `maxBytes` output, dọn file tạm, tắt module nặng khi cần.

## 9. Cấu trúc dự án

```
src/
  server.js            express app + boot()
  config.js            .env loader, limits
  db.js                SQLite WAL + schema (scans, stages, findings, ai_providers, db_targets, test_accounts…)
  security/            password (scrypt), crypto (AES-GCM), session, scope (SSRF), middleware
  ai/                  provider adapter (OpenAI-compatible), ai-analyze (batch findings)
  scan/                orchestrator (queue tuần tự, SSE progress) + stages/s01..s24 + tools-registry
  routes/              auth, scans, findings, dashboard, tools, ai, settings, db-targets, test-accounts, events
public/                SPA (VI/EN, dashboard charts SVG, scan wizard, history compare, AI settings)
tests/                 security.test.js, integration.test.js
scripts/               set-password.mjs, gen-key.mjs, backup.mjs
design-system/clab/    quyết định UI/UX Pro Max + Taste art direction
```
