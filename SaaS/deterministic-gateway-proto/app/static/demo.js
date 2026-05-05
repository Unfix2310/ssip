// CONFIG — change this to your actual API base URL
const API_BASE = 'http://localhost:8000';

pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

let extractedResults = [];
let allYaml = '';

// ── FILE HANDLING ──────────────────────────────────────────────────────────

const pdfInput = document.getElementById('pdfInput');
const uploadZone = document.getElementById('uploadZone');

pdfInput.addEventListener('change', (e) => {
  if (e.target.files[0]) handleFile(e.target.files[0]);
});

uploadZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  uploadZone.classList.add('drag-over');
});

uploadZone.addEventListener('dragleave', () => {
  uploadZone.classList.remove('drag-over');
});

uploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f && f.type === 'application/pdf') handleFile(f);
});

function handleFile(file) {
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileSize').textContent =
    (file.size / 1024).toFixed(1) + ' KB';
  document.getElementById('fileLoaded').classList.add('active');
  document.getElementById('extractBtn').disabled = false;
  uploadZone.style.display = 'none';

  // Auto-detect document ID from filename
  const name = file.name.toUpperCase();
  if (name.includes('107') || name.includes('GOVERNANCE')) {
    document.getElementById('docId').value = 'RBI/2023-24/107';
    document.getElementById('effectiveDate').value = '2024-04-01';
  } else if (name.includes('123') || name.includes('DPSS') || name.includes('CYBER')) {
    document.getElementById('docId').value = 'RBI/DPSS/2024-25/123';
    document.getElementById('effectiveDate').value = '2024-07-30';
  }

  window._pendingFile = file;
}

// ── PDF TEXT EXTRACTION ────────────────────────────────────────────────────

async function extractPdfText(file) {
  const arrayBuffer = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  let fullText = '';
  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const content = await page.getTextContent();
    fullText += content.items.map(item => item.str).join(' ') + '\n';
  }
  return fullText;
}

function deduplicateRepeatedPdfText(rawText) {
  const midpoint = Math.floor(rawText.length / 2);
  const firstHalf = rawText.slice(0, midpoint);
  const secondHalf = rawText.slice(midpoint);
  const probe = firstHalf.slice(0, 200);
  return probe && secondHalf.includes(probe) ? firstHalf : rawText;
}

// ── CLAUSE SPLITTING ──────────────────────────────────────────────────────
// Splits by numbered section headers: "15." "16(a)" etc.
// Returns array of { section, text }

function splitIntoClauses(rawText) {
  const clauses = [];

  // Clean up PDF extraction artifacts
  // BUG FIX: use \d{1,2} not \d+ — avoids false breaks on years (2024. Policy...)
  const text = rawText
    .replace(/\s+/g, ' ')
    .replace(/(\d{1,2})\s*\.\s*([A-Z])/g, '\n$1. $2')
    .replace(/([a-z])\s*\(\s*([a-z])\s*\)/g, '$1 ($2)')
    .trim();

  // Split by TOP-LEVEL section numbers only: "13.", "14.", "15(a)"
  // BUG FIX: removed (?:\.\d+)? — sub-sections like 13.1 now stay merged
  // with their parent clause instead of fragmenting the intro paragraph.
  const sectionPattern = /(?:^|\n)\s*(\d{1,2}(?:\([a-z]\))?)\s*[.)\s]/gm;

  const matches = [...text.matchAll(sectionPattern)];

  if (matches.length === 0) {
    // Fallback: split by sentences, group into paragraphs
    const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z])/);
    for (let i = 0; i < sentences.length; i += 3) {
      const chunk = sentences.slice(i, i + 3).join(' ').trim();
      if (chunk.length > 40) {
        clauses.push({ section: String(i + 1), text: chunk });
      }
    }
    return clauses;
  }

  for (let i = 0; i < matches.length; i++) {
    const start = matches[i].index + matches[i][0].length;
    const end = i + 1 < matches.length ? matches[i + 1].index : text.length;
    const clauseText = text.slice(start, end).trim();

    // Skip very short or header-only sections
    if (clauseText.length < 60) continue;

    // Skip TOC-like entries (just numbers and dots)
    if (/^[\d\s.]+$/.test(clauseText)) continue;

    clauses.push({
      section: matches[i][1],
      text: clauseText.slice(0, 800) // cap at 800 chars per clause
    });
  }

  // Post-process: split compound rules into atomic sub-clauses
  return splitCompoundClauses(clauses);
}

// ── COMPOUND CLAUSE SPLITTING ──────────────────────────────────────────────
// Detects clauses with multiple enforceable rules and splits them.
// e.g. "VA every 6 months and PT every 12 months for systems in DMZ"
//   → §26a: "VA every 6 months for systems in DMZ"
//   → §26b: "PT every 12 months for systems in DMZ"

function splitCompoundClauses(clauses) {
  const result = [];

  // Patterns that signal multiple rules in one clause
  const COMPOUND_PATTERNS = [
    // Two frequencies: "every 6 months and ... every 12 months"
    /(\d+)\s*months?\s+and\b.+?(\d+)\s*months?/i,
    // Two actions with shall: "X shall ... and Y shall ..."
    /shall\b.+?\band\b.+?shall\b/i,
    // Enumerated obligations: "(a) ... (b) ..."
    /\([a-z]\).+?\([a-z]\)/i,
    // Semicolon-separated obligations with verbs
    /shall\b[^;]+;\s*\w+.*shall\b/i,
  ];

  for (const clause of clauses) {
    let isCompound = false;

    for (const pattern of COMPOUND_PATTERNS) {
      if (pattern.test(clause.text)) {
        isCompound = true;
        break;
      }
    }

    if (!isCompound) {
      result.push(clause);
      continue;
    }

    // Detect shared resource tail — "for critical systems in DMZ" etc.
    const sharedTail = extractSharedTail(clause.text);

    // Split into sub-clauses
    const parts = splitOnConjunction(clause.text);

    if (parts.length <= 1) {
      result.push(clause);
      continue;
    }

    let subIdx = 0;
    for (const part of parts) {
      let trimmed = part.trim();
      if (trimmed.length < 40) continue;

      // Append shared tail if this sub-clause doesn't already contain it
      if (sharedTail && !trimmed.toLowerCase().includes(sharedTail.toLowerCase())) {
        trimmed = trimmed.replace(/[.;,]?\s*$/, '') + ' ' + sharedTail;
      }

      const suffix = String.fromCharCode(97 + subIdx); // a, b, c...
      result.push({
        section: `${clause.section}${suffix}`,
        text: trimmed,
        parentText: clause.text  // preserve full context for API
      });
      subIdx++;
    }

    if (subIdx === 0) {
      // Splitting produced nothing usable — keep original
      result.push(clause);
    }
  }

  return result;
}

function splitOnConjunction(text) {
  // Strategy 1: Split on " and " when followed by a new subject/verb pattern
  // Avoids splitting "X and Y controls" (noun list, not compound rule)
  const andParts = text.split(/\s+and\s+(?=[A-Z]|\bPT\b|\bVA\b|\bREs\b|\bregulated\b|\ball\b|\bthe\b)/);
  if (andParts.length > 1) return andParts;

  // Strategy 2: Split on semicolons (RBI uses "X shall ...; Y shall ...")
  const semiParts = text.split(/;\s+(?=[A-Z])/);
  if (semiParts.length > 1) return semiParts;

  // Strategy 3: Split on sub-clause markers (a), (b), (c)
  const subParts = text.split(/(?=\([b-z]\)\s)/);
  if (subParts.length > 1) return subParts;

  return [text];
}

function extractSharedTail(text) {
  // Extract trailing prepositional phrase that applies to all sub-clauses
  // e.g. "for critical systems in the DMZ" or "in the de-militarized zone"
  const tailMatch = text.match(/\b(for\s+(?:critical\s+)?(?:systems?|information|all).+?)\.?\s*$/i);
  if (tailMatch) return tailMatch[1].trim();

  const inMatch = text.match(/\b(in\s+the\s+(?:DMZ|de-?militarized zone).+?)\.?\s*$/i);
  if (inMatch) return inMatch[1].trim();

  return '';
}

// ── MAIN EXTRACTION ───────────────────────────────────────────────────────

async function runExtraction() {
  const file = window._pendingFile;
  if (!file) return;

  const docId = document.getElementById('docId').value.trim() || 'UNKNOWN';
  const effectiveDate = document.getElementById('effectiveDate').value.trim() || '';

  // Reset state
  extractedResults = [];
  allYaml = '';
  document.getElementById('resultsBody').innerHTML = '';
  document.getElementById('yamlBody').innerHTML = '';
  document.getElementById('resultsPanel').classList.remove('active');
  document.getElementById('yamlPanel').classList.remove('active');
  document.getElementById('metricsBar').classList.remove('active');
  document.getElementById('timingBanner').classList.remove('active');

  const btn = document.getElementById('extractBtn');
  btn.disabled = true;
  btn.textContent = 'Processing...';

  // Show progress
  const progressPanel = document.getElementById('progressPanel');
  progressPanel.classList.add('active');
  clearLog();

  const startTime = Date.now();

  try {
    log('Parsing PDF...', 'line');
    const rawText = await extractPdfText(file);
    log(`Extracted ${rawText.length} characters from PDF`, 'ok');

    const cleanText = deduplicateRepeatedPdfText(rawText);
    if (cleanText.length !== rawText.length) {
      log(`Removed repeated PDF text (${rawText.length} → ${cleanText.length} characters)`, 'warn');
    }

    const clauses = splitIntoClauses(cleanText);
    log(`Split into ${clauses.length} clauses for extraction`, 'ok');

    if (clauses.length === 0) {
      log('No clauses detected — check PDF format', 'err');
      return;
    }

    let processed = 0;
    let compiled = 0;
    let approved = 0;
    let review = 0;
    let rejected = 0;
    const seen_sections = new Set();

    updateProgress(0, clauses.length);

    for (const clause of clauses) {
      // Sub-clauses from compound splitting are shorter — use 60 char min
      const minLen = clause.parentText ? 60 : 300;
      if (clause.text.length < minLen || seen_sections.has(clause.section)) {
        log(`§${clause.section} — skipped (${clause.text.length < minLen ? 'too short' : 'duplicate'})`, 'warn');
        continue;
      }
      seen_sections.add(clause.section);
      log(`§${clause.section} — sending to /generate-control`, 'line');

      try {
        const body = {
          input_text: clause.text,
          document_id: docId,
          section: clause.section,
          effective_date: effectiveDate || undefined
        };
        // Pass parent context for compound sub-clauses so LLM knows
        // the full original sentence (shared subject/resource)
        if (clause.parentText) {
          body.parent_context = clause.parentText;
        }

        const resp = await fetch(`${API_BASE}/generate-control`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });

        const data = await resp.json();

        if (data.status === 'success') {
          extractedResults.push({ clause, data });
          compiled++;

          const routing = data.routing?.decision || 'unknown';
          if (routing === 'auto_approve') approved++;
          else if (routing === 'review_required' || routing === 'catalog_enrichment') review++;

          allYaml += `# ── §${clause.section} ──────────────────────────────\n`;
          allYaml += data.compiled_yaml + '\n';

          log(`§${clause.section} ✓ ${data.ir?.action?.normalized || '?'} [${routing}]`, 'ok');
          renderRow(clause.section, data);
        } else {
          rejected++;
          log(`§${clause.section} ✗ ${data.message || 'rejected'}`, 'warn');
        }
      } catch (err) {
        rejected++;
        log(`§${clause.section} ✗ API error: ${err.message}`, 'err');
      }

      processed++;
      updateProgress(processed, clauses.length);

      // Small delay to avoid hammering API
      await sleep(120);
    }

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    // Show metrics
    document.getElementById('mExtracted').textContent = compiled;
    document.getElementById('mApproved').textContent = approved;
    document.getElementById('mReview').textContent = review;
    document.getElementById('mRejected').textContent = rejected;
    document.getElementById('mAccuracy').textContent =
      compiled > 0 ? Math.round((compiled / clauses.length) * 100) + '%' : '0%';
    document.getElementById('metricsBar').classList.add('active');

    // Show timing
    const manualHours = Math.max(4, Math.round(clauses.length * 0.3));
    const speedup = Math.round((manualHours * 3600) / parseFloat(elapsed));
    document.getElementById('timingSeconds').textContent = elapsed + 's';
    document.getElementById('timingClauses').textContent = clauses.length;
    document.getElementById('timingExtracted').textContent = compiled;
    document.getElementById('speedupText').textContent =
      `~${speedup}× faster than manual extraction`;
    document.getElementById('timingBanner').classList.add('active');

    // Show panels
    if (extractedResults.length > 0) {
      document.getElementById('resultsPanel').classList.add('active');
      renderYaml();
      document.getElementById('yamlPanel').classList.add('active');
    }

    log(`Done — ${compiled} controls extracted in ${elapsed}s`, 'ok');

  } catch (err) {
    log(`Fatal error: ${err.message}`, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Extract Controls →';
  }
}

// ── TABLE RENDERING ───────────────────────────────────────────────────────

function renderRow(section, data) {
  const ir = data.ir;
  const routing = data.routing?.decision || 'unknown';
  const tbody = document.getElementById('resultsBody');

  const statusTag = routing === 'auto_approve'
    ? '<span class="tag tag-green">AUTO-APPROVED</span>'
    : routing === 'review_required'
      ? '<span class="tag tag-yellow">REVIEW</span>'
      : routing === 'catalog_enrichment'
        ? '<span class="tag tag-yellow">ENRICH</span>'
        : '<span class="tag tag-red">REJECTED</span>';

  const ruleTypeTag = `<span class="tag tag-blue">${(ir.rule_type || '?').replace(/_/g, ' ')}</span>`;

  const temporal = formatTemporal(ir.temporal);
  const conf = ir.confidence?.overall || 0;
  const confClass = conf >= 0.85 ? '' : conf >= 0.6 ? 'mid' : 'low';
  const confPct = Math.round(conf * 100);

  const row = document.createElement('tr');
  row.innerHTML = `
    <td><span class="source-text">§${section}</span></td>
    <td>${ruleTypeTag}</td>
    <td><span class="action-text">${ir.action?.normalized || '—'}</span></td>
    <td><span class="resource-text">${ir.resource?.canonical_key || ir.resource?.raw || '—'}</span></td>
    <td><span class="temporal-text">${temporal}</span></td>
    <td>
      <div class="conf-bar">
        <div class="conf-track">
          <div class="conf-fill ${confClass}" style="width:${confPct}%"></div>
        </div>
        <div class="conf-num">${confPct}%</div>
      </div>
    </td>
    <td>${statusTag}</td>
  `;
  tbody.appendChild(row);
}

function formatTemporal(t) {
  if (!t) return '—';
  if (t.frequency) return t.frequency.replace(/_/g, ' ');
  if (t.deadline) return t.deadline.replace(/_/g, ' ');
  if (t.retention) return t.retention.replace(/_/g, ' ');
  if (t.cooling_period) return t.cooling_period.replace(/_/g, ' ');
  return '—';
}

// ── YAML RENDERING ────────────────────────────────────────────────────────

function renderYaml() {
  const container = document.getElementById('yamlBody');
  const highlighted = allYaml
    .replace(/^(#.*)$/gm, '<span class="yaml-comment">$1</span>')
    .replace(/^(\s*)([\w_-]+):/gm, '$1<span class="yaml-key">$2</span>:')
    .replace(/:\s*(RBI[^\n]+)/g, ': <span class="yaml-id">$1</span>')
    .replace(/:\s*([^\n<{[]+)/g, (m, v) => {
      const trimmed = v.trim();
      if (!trimmed || trimmed === '') return m;
      return `: <span class="yaml-val">${v}</span>`;
    });
  container.innerHTML = highlighted;
}

function downloadYaml() {
  const blob = new Blob([allYaml], { type: 'text/yaml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'compiled_controls.yaml';
  a.click();
  URL.revokeObjectURL(url);
}

// ── UTILITIES ─────────────────────────────────────────────────────────────

function updateProgress(done, total) {
  const pct = total > 0 ? (done / total) * 100 : 0;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressStats').textContent = `${done} / ${total}`;
}

function log(msg, type = 'line') {
  const container = document.getElementById('progressLog');
  const line = document.createElement('div');
  line.className = `log-${type}`;
  line.textContent = `> ${msg}`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function clearLog() {
  document.getElementById('progressLog').innerHTML = '';
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Check API connectivity on load
fetch(`${API_BASE}/health`)
  .then(() => {
    document.querySelector('.status-pill').textContent = '● API CONNECTED';
    document.querySelector('.status-pill').style.color = 'var(--green)';
    document.querySelector('.status-pill').style.borderColor = 'var(--green)';
  })
  .catch(() => {
    document.querySelector('.status-pill').textContent = '● API OFFLINE';
    document.querySelector('.status-pill').style.color = 'var(--red)';
    document.querySelector('.status-pill').style.borderColor = 'var(--red)';
  });
