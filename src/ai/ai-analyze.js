import { q, run, resourceLimits } from '../db.js';
import { getActive, chatCompletion, cleanError } from './provider.js';
import { log } from '../util/log.js';

/**
 * AI analysis pipeline — runs after scan completion (or on demand).
 * Minimal payload: finding metadata + truncated evidence only.
 * Never invents CVEs/scanner results; output is labeled interpretation.
 * If AI is unconfigured/fails: findings stay intact, ai_status records why.
 */

const pending = new Set(); // scan ids currently being analyzed
let timer = null;

export function enqueueScanAnalysis(scanId) {
  if (pending.has(scanId)) return;
  pending.add(scanId);
  if (!timer) {
    timer = setTimeout(() => {
      timer = null;
      const batch = [...pending];
      pending.clear();
      (async () => {
        for (const id of batch) {
          try {
            await analyzeScan(id);
          } catch (e) {
            log.warn('ai-analysis error', id, e.message);
          }
        }
      })();
    }, 2000);
    timer.unref?.();
  }
}

export async function analyzeScan(scanId) {
  const provider = getActive();
  const findings = q(
    `SELECT * FROM findings WHERE scan_id=? AND ai_status='pending' ORDER BY
       CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
     LIMIT 20`, [scanId]
  );
  if (!findings.length) return { analyzed: 0 };

  if (!provider || !provider.model_id) {
    run('UPDATE findings SET ai_status=? WHERE scan_id=? AND ai_status=\'pending\'',
      ['unconfigured', scanId]);
    return { analyzed: 0, status: 'unconfigured' };
  }

  const limits = resourceLimits();
  const batchSize = Math.max(1, limits.aiBatchSize || 5);
  let analyzed = 0;

  for (let i = 0; i < findings.length; i += batchSize) {
    const batch = findings.slice(i, i + batchSize);
    const payload = batch.map((f) => ({
      id: f.id, asset: f.asset, stage: f.stage_id, tool: f.tool, title: f.title,
      severity: f.severity, confidence: f.confidence,
      description: f.description.slice(0, 500), evidence: f.evidence.slice(0, 700),
      recommendation: f.recommendation?.slice(0, 300) || null,
    }));
    try {
      const r = await chatCompletion(provider, {
        jsonMode: true,
        messages: [
          {
            role: 'system',
            content: 'You are a senior application security reviewer. Analyze ONLY the provided evidence. ' +
              'Never invent CVEs, scanner output, or vulnerabilities not supported by evidence. ' +
              'For each finding return JSON: {"analyses":[{"id":"...","explain":"plain-language explanation",' +
              '"severity_adjusted":"critical|high|medium|low|informational","confidence":"high|medium|low",' +
              '"evidence_vs_hypothesis":"what is proven vs assumed","remediation":"concrete fix",' +
              '"follow_up":"next check needed if evidence is insufficient"}]}',
          },
          { role: 'user', content: JSON.stringify({ findings: payload }) },
        ],
        maxTokens: provider.max_tokens || 2048,
      });
      if (!r.ok) {
        const errClean = cleanError(r.text);
        for (const f of batch) {
          run('UPDATE findings SET ai_status=? WHERE id=?', [`failed: ${errClean}`, f.id]);
        }
        log.warn('ai call failed', r.status, errClean);
        continue;
      }
      const content = r.json?.choices?.[0]?.message?.content || '{}';
      let parsed;
      try { parsed = JSON.parse(content); } catch { parsed = null; }
      const byId = {};
      for (const a of (parsed?.analyses || [])) byId[a.id] = a;
      for (const f of batch) {
        const a = byId[f.id];
        if (a) {
          run('UPDATE findings SET ai_status=?, ai_analysis=? WHERE id=?',
            ['ok', JSON.stringify({
              explain: String(a.explain || '').slice(0, 1200),
              severity_adjusted: a.severity_adjusted,
              confidence: a.confidence,
              evidence_vs_hypothesis: String(a.evidence_vs_hypothesis || '').slice(0, 800),
              remediation: String(a.remediation || '').slice(0, 800),
              follow_up: String(a.follow_up || '').slice(0, 500),
              model: provider.model_id,
              at: Date.now(),
            }), f.id]);
        } else {
          run('UPDATE findings SET ai_status=? WHERE id=?', ['no-analysis-returned', f.id]);
        }
        analyzed++;
      }
    } catch (e) {
      const errClean = cleanError(e.message);
      for (const f of batch) run('UPDATE findings SET ai_status=? WHERE id=?', [`failed: ${errClean}`, f.id]);
      log.warn('ai analyze exception', errClean);
    }
  }
  return { analyzed };
}
