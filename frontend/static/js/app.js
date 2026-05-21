const API_BASE = 'http://localhost:5000';
let currentData = null;
let currentStrings = { ascii: [], unicode: [] };
let activeStab = 'ascii';
let entropyChart = null;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const uploadSection   = document.getElementById('upload-section');
const loadingSection  = document.getElementById('loading-section');
const resultsSection  = document.getElementById('results-section');
const dropZone        = document.getElementById('drop-zone');
const fileInput       = document.getElementById('file-input');
const vtKeyInput      = document.getElementById('vt-key');
const toggleKeyBtn    = document.getElementById('toggle-key');
const loadingFname    = document.getElementById('loading-filename');
const loadingBar      = document.getElementById('loading-bar');
const btnBack         = document.getElementById('btn-back');
const btnExport       = document.getElementById('btn-export');
const stringsSearch   = document.getElementById('strings-search');

// ── Drag & Drop ───────────────────────────────────────────────────────────────
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) submitFile(file);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) submitFile(fileInput.files[0]);
});

// VT key toggle
toggleKeyBtn.addEventListener('click', () => {
  vtKeyInput.type = vtKeyInput.type === 'password' ? 'text' : 'password';
});

btnBack.addEventListener('click', resetToUpload);
btnExport.addEventListener('click', exportJSON);

// Tabs
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
    tab.classList.add('active');
    document.getElementById('panel-' + tab.dataset.tab).classList.remove('hidden');
  });
});

// String sub-tabs
document.querySelectorAll('.stab').forEach(stab => {
  stab.addEventListener('click', () => {
    document.querySelectorAll('.stab').forEach(s => s.classList.remove('active'));
    stab.classList.add('active');
    activeStab = stab.dataset.stab;
    renderStrings();
  });
});

stringsSearch.addEventListener('input', renderStrings);

// ── Upload & Analysis ─────────────────────────────────────────────────────────
async function submitFile(file) {
  showLoading(file.name);
  animateLoadingSteps();

  const formData = new FormData();
  formData.append('file', file);
  const vtKey = vtKeyInput.value.trim();
  if (vtKey) formData.append('vt_api_key', vtKey);

  try {
    const resp = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      body: formData
    });

    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.error || `HTTP ${resp.status}`);
    }

    currentData = await resp.json();
    showResults(currentData);
  } catch (err) {
    alert(`Analysis failed: ${err.message}\n\nMake sure the backend is running on port 5000.`);
    resetToUpload();
  }
}

// ── Loading animation ─────────────────────────────────────────────────────────
function showLoading(filename) {
  uploadSection.classList.add('hidden');
  resultsSection.classList.add('hidden');
  loadingSection.classList.remove('hidden');
  loadingFname.textContent = filename;
  loadingBar.style.width = '0%';
  document.querySelectorAll('.step').forEach(s => {
    s.classList.remove('active', 'done');
  });
}

function animateLoadingSteps() {
  const steps = document.querySelectorAll('.step');
  const durations = [400, 600, 700, 800, 1200, 300];
  let elapsed = 0;

  steps.forEach((step, i) => {
    setTimeout(() => {
      if (i > 0) steps[i - 1].classList.remove('active');
      steps[i].classList.add('active');
      loadingBar.style.width = `${Math.round((i + 1) / steps.length * 85)}%`;
    }, elapsed);
    elapsed += durations[i] || 500;
  });
}

// ── Show Results ──────────────────────────────────────────────────────────────
function showResults(data) {
  loadingSection.classList.add('hidden');
  uploadSection.classList.add('hidden');
  resultsSection.classList.remove('hidden');
  loadingBar.style.width = '100%';

  document.getElementById('result-filename').textContent = data.filename || 'Unknown file';

  renderRiskBanner(data);
  renderOverview(data);
  renderStringsTab(data);
  renderIOCs(data);
  renderEntropy(data);
  renderSpecificAnalysis(data);
  renderVirusTotal(data);

  // Reset to overview tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
  document.querySelector('.tab[data-tab="overview"]').classList.add('active');
  document.getElementById('panel-overview').classList.remove('hidden');
}

// ── Risk Banner ───────────────────────────────────────────────────────────────
function renderRiskBanner(data) {
  const score = data.risk_score || 0;
  const scoreEl = document.getElementById('risk-score-val');
  const verdictEl = document.getElementById('risk-verdict');

  let verdict, cls;
  if (score === 0)       { verdict = 'CLEAN';    cls = 'clean'; }
  else if (score <= 20)  { verdict = 'LOW RISK'; cls = 'low'; }
  else if (score <= 45)  { verdict = 'MODERATE'; cls = 'medium'; }
  else if (score <= 70)  { verdict = 'HIGH RISK';cls = 'high'; }
  else                   { verdict = 'CRITICAL'; cls = 'critical'; }

  scoreEl.textContent = score;
  scoreEl.className = 'risk-score ' + cls;
  verdictEl.textContent = verdict;
  verdictEl.className = 'risk-verdict ' + cls;

  // Gauge needle rotation: 0% = -90deg, 100% = 90deg
  const needle = document.getElementById('gauge-needle');
  const arc = document.getElementById('gauge-arc');
  const rotation = -90 + (score / 100) * 180;
  needle.setAttribute('transform', `rotate(${rotation}, 100, 100)`);

  // Arc fill
  const arcLen = 251.2 * (score / 100);
  arc.setAttribute('stroke-dasharray', `${arcLen} 251.2`);

  // Risk factors
  const list = document.getElementById('risk-factors-list');
  list.innerHTML = '';
  (data.risk_factors || []).slice(0, 5).forEach(f => {
    const div = document.createElement('div');
    div.className = `risk-factor ${f.severity}`;
    div.innerHTML = `<span class="rf-cat">[${(f.category || '').toUpperCase()}]</span><span>${f.description}</span>`;
    list.appendChild(div);
  });
}

// ── Overview Tab ──────────────────────────────────────────────────────────────
function renderOverview(data) {
  const ft = data.file_type || {};
  const grid = document.getElementById('overview-grid');
  grid.innerHTML = '';

  const cards = [
    { label: 'FILE TYPE', value: ft.label || 'Unknown', cls: '' },
    { label: 'CATEGORY', value: (ft.category || 'unknown').toUpperCase(), cls: '' },
    { label: 'SIZE', value: formatBytes(ft.size_bytes || 0), cls: '' },
    { label: 'EXTENSION', value: ft.extension ? `.${ft.extension}` : 'N/A', cls: '' },
    { label: 'MIME TYPE', value: ft.mime_type || 'N/A', cls: '' },
    { label: 'EXT MATCHES MAGIC', value: ft.extension_matches_magic === false ? 'NO ⚠' : 'YES', cls: ft.extension_matches_magic === false ? 'red' : 'green' },
    { label: 'ENTROPY', value: (data.entropy?.overall ?? '--') + ' / 8.0', cls: entropyColor(data.entropy?.overall) },
    { label: 'STRINGS (ASCII)', value: data.strings?.total_ascii ?? 0, cls: '' },
    { label: 'IOCS FOUND', value: (data.iocs || []).length, cls: (data.iocs || []).length > 0 ? 'amber' : '' },
  ];

  cards.forEach(c => {
    const card = document.createElement('div');
    card.className = 'info-card';
    card.innerHTML = `<div class="info-card-label">${c.label}</div><div class="info-card-value ${c.cls}">${c.value}</div>`;
    grid.appendChild(card);
  });

  // Hashes
  const hashBlock = document.getElementById('hash-block');
  const hashes = data.hashes || {};
  hashBlock.innerHTML = ['md5', 'sha1', 'sha256'].map(algo => `
    <div class="hash-row">
      <span class="hash-label">${algo.toUpperCase()}</span>
      <span class="hash-value" id="hash-${algo}">${hashes[algo] || 'N/A'}</span>
      <button class="copy-btn" onclick="copyHash('${algo}')">COPY</button>
    </div>
  `).join('');
}

function copyHash(algo) {
  const val = document.getElementById('hash-' + algo)?.textContent;
  if (val) { navigator.clipboard.writeText(val); }
}

// ── Strings Tab ───────────────────────────────────────────────────────────────
function renderStringsTab(data) {
  currentStrings.ascii = data.strings?.ascii || [];
  currentStrings.unicode = data.strings?.unicode || [];
  renderStrings();
}

function renderStrings() {
  const list = document.getElementById('strings-list');
  const filter = stringsSearch.value.toLowerCase();
  const source = currentStrings[activeStab] || [];
  const filtered = filter ? source.filter(s => s.toLowerCase().includes(filter)) : source;

  list.innerHTML = filtered.slice(0, 500).map((s, i) => `
    <div class="string-item">
      <span class="string-idx">${i}</span>
      <span class="string-val">${escHtml(s)}</span>
      <span class="string-len">${s.length}</span>
    </div>
  `).join('') || '<div class="ioc-empty">No strings found.</div>';
}

// ── IOCs ──────────────────────────────────────────────────────────────────────
function renderIOCs(data) {
  const list = document.getElementById('ioc-list');
  const iocs = data.iocs || [];

  if (!iocs.length) {
    list.innerHTML = '<div class="ioc-empty">No IOCs extracted from this file.</div>';
    return;
  }

  list.innerHTML = iocs.map(ioc => `
    <div class="ioc-item">
      <span class="ioc-type ${ioc.type}">${ioc.type.toUpperCase()}</span>
      <span class="ioc-value">${escHtml(ioc.value)}</span>
    </div>
  `).join('');
}

// ── Entropy ───────────────────────────────────────────────────────────────────
function renderEntropy(data) {
  const entropy = data.entropy || {};

  // Summary cards
  const summary = document.getElementById('entropy-summary');
  summary.innerHTML = [
    { label: 'OVERALL ENTROPY', value: (entropy.overall ?? '--') + ' / 8.0', cls: entropyColor(entropy.overall) },
    { label: 'AVG CHUNK', value: (entropy.avg_chunk ?? '--') + ' / 8.0', cls: '' },
    { label: 'HIGH ENTROPY CHUNKS', value: entropy.high_entropy_chunks ?? '--', cls: (entropy.high_entropy_chunks > 0) ? 'amber' : '' },
    { label: 'INTERPRETATION', value: entropy.interpretation || '--', cls: '' },
  ].map(c => `
    <div class="info-card">
      <div class="info-card-label">${c.label}</div>
      <div class="info-card-value ${c.cls}">${c.value}</div>
    </div>
  `).join('');

  // Chunk chart
  const chunks = (entropy.chunks_sample || []).slice(0, 50);
  if (chunks.length && typeof Chart !== 'undefined') {
    const ctx = document.getElementById('entropy-chart').getContext('2d');
    if (entropyChart) entropyChart.destroy();
    entropyChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: chunks.map(c => '0x' + c.offset.toString(16).toUpperCase()),
        datasets: [{
          label: 'Entropy per 4KB chunk',
          data: chunks.map(c => c.entropy),
          backgroundColor: chunks.map(c =>
            c.entropy > 7.5 ? 'rgba(255,51,51,0.7)' :
            c.entropy > 7.0 ? 'rgba(255,170,0,0.7)' :
            'rgba(0,255,136,0.5)'
          ),
          borderWidth: 0,
          borderRadius: 2,
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: ctx => `Entropy: ${ctx.raw.toFixed(3)}` } }
        },
        scales: {
          x: {
            ticks: { color: '#555', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 10 },
            grid: { color: '#1a1a1a' }
          },
          y: {
            min: 0, max: 8,
            ticks: { color: '#555', font: { family: 'JetBrains Mono', size: 10 } },
            grid: { color: '#1a1a1a' }
          }
        }
      }
    });
  }

  // PE Sections table
  const sections = entropy.sections || [];
  const tbl = document.getElementById('sections-table');
  if (!sections.length || sections[0]?.error) {
    tbl.innerHTML = '';
    return;
  }

  tbl.innerHTML = `
    <div class="section-row header">
      <span>SECTION</span><span>ENTROPY</span><span>ENTROPY BAR</span><span>SIZE</span>
    </div>
    ${sections.map(s => `
      <div class="section-row">
        <span style="color:var(--blue)">${escHtml(s.name)}</span>
        <span style="color:${entropyHex(s.entropy)}">${s.entropy}</span>
        <span>
          <div class="entropy-bar-wrap">
            <div class="entropy-bar-fill" style="width:${(s.entropy/8*100).toFixed(1)}%;background:${entropyHex(s.entropy)}"></div>
          </div>
        </span>
        <span style="color:var(--text-dim)">${formatBytes(s.size)}</span>
      </div>
    `).join('')}
  `;
}

// ── Deep Analysis ─────────────────────────────────────────────────────────────
function renderSpecificAnalysis(data) {
  const container = document.getElementById('specific-content');
  container.innerHTML = '';
  const sa = data.specific_analysis || {};
  const cat = data.file_type?.category || 'unknown';

  if (sa.error) {
    container.innerHTML = `<div class="ioc-empty">${escHtml(sa.error)}</div>`;
    return;
  }

  if (cat === 'executable') renderPEAnalysis(container, sa, data);
  else if (cat === 'pdf') renderPDFAnalysis(container, sa);
  else if (cat === 'office') renderOfficeAnalysis(container, sa);
  else if (cat === 'script') renderScriptAnalysis(container, sa);
  else container.innerHTML = '<div class="ioc-empty">No specific analysis available for this file type.</div>';
}

function renderPEAnalysis(container, sa, data) {
  // Basic info
  appendSection(container, 'PE HEADER', `
    <div class="spec-grid">
      ${specItem('Architecture', sa.architecture)}
      ${specItem('Subsystem', sa.subsystem)}
      ${specItem('Is DLL', sa.is_dll ? 'YES' : 'NO')}
      ${specItem('Entry Point', sa.entry_point)}
      ${specItem('Image Base', sa.image_base)}
      ${specItem('Packed', sa.is_packed ? 'YES ⚠' : 'NO', sa.is_packed ? 'bad' : 'ok')}
      ${specItem('Compilation Time', sa.compilation_timestamp?.human || 'N/A')}
      ${specItem('Overlay Data', sa.overlay ? `YES (${formatBytes(sa.overlay.size)})` : 'NO', sa.overlay?.suspicious ? 'warn' : '')}
    </div>
    ${sa.packer_hints?.length ? `<div style="margin-top:12px"><div class="spec-item-label">PACKER HINTS</div><div class="tag-list" style="margin-top:6px">${sa.packer_hints.map(h => `<span class="tag bad">${escHtml(h)}</span>`).join('')}</div></div>` : ''}
  `);

  // Security mitigations
  const m = sa.security_mitigations || {};
  appendSection(container, 'SECURITY MITIGATIONS', `
    <div class="spec-grid">
      ${specItem('ASLR', m.ASLR ? 'ENABLED' : 'DISABLED ⚠', m.ASLR ? 'ok' : 'bad')}
      ${specItem('DEP / NX', m['DEP/NX'] ? 'ENABLED' : 'DISABLED ⚠', m['DEP/NX'] ? 'ok' : 'bad')}
      ${specItem('Safe SEH', m.SEH ? 'ENABLED' : 'DISABLED', m.SEH ? 'ok' : 'warn')}
      ${specItem('CFG', m.CFG ? 'ENABLED' : 'DISABLED', m.CFG ? 'ok' : 'warn')}
      ${specItem('High Entropy VA', m.high_entropy_va ? 'ENABLED' : 'DISABLED', m.high_entropy_va ? 'ok' : '')}
    </div>
  `);

  // Suspicious imports
  if (sa.suspicious_imports?.length) {
    appendSection(container, `SUSPICIOUS IMPORTS (${sa.suspicious_imports.length})`, `
      <div class="tag-list">${sa.suspicious_imports.map(f => `<span class="tag bad">${escHtml(f)}</span>`).join('')}</div>
    `);
  }

  // Imports tree
  if (sa.imports?.length) {
    const susSet = new Set(sa.suspicious_imports || []);
    appendSection(container, `IMPORT TABLE (${sa.imports.length} DLLs)`, `
      <div class="imports-list">
        ${sa.imports.slice(0, 20).map(imp => `
          <div class="import-dll">${escHtml(imp.dll)}</div>
          <div>${(imp.functions || []).slice(0, 20).map(f =>
            `<span class="import-fn ${susSet.has(f) ? 'suspicious' : ''}">${escHtml(f)}</span>`
          ).join('')}</div>
        `).join('')}
      </div>
    `);
  }

  // Version info
  if (Object.keys(sa.version_info || {}).length) {
    appendSection(container, 'VERSION INFO', `
      <div class="spec-grid">
        ${Object.entries(sa.version_info).map(([k, v]) => specItem(k, v)).join('')}
      </div>
    `);
  }
}

function renderPDFAnalysis(container, sa) {
  appendSection(container, 'PDF FEATURES', `
    <div class="spec-grid">
      ${specItem('Pages', sa.page_count ?? 'N/A')}
      ${specItem('JavaScript', sa.has_javascript ? 'YES ⚠' : 'NO', sa.has_javascript ? 'bad' : 'ok')}
      ${specItem('Auto Action', sa.has_auto_action ? 'YES ⚠' : 'NO', sa.has_auto_action ? 'bad' : 'ok')}
      ${specItem('Embedded Files', sa.has_embedded_files ? 'YES' : 'NO', sa.has_embedded_files ? 'warn' : '')}
      ${specItem('Encryption', sa.has_encryption ? 'YES' : 'NO', sa.has_encryption ? 'warn' : '')}
      ${specItem('XFA Forms', sa.has_xfa ? 'YES' : 'NO', sa.has_xfa ? 'warn' : '')}
      ${specItem('AcroForm', sa.has_acroform ? 'YES' : 'NO')}
      ${specItem('URI Actions', sa.has_uri_actions ? 'YES' : 'NO', sa.has_uri_actions ? 'warn' : '')}
    </div>
  `);

  if (sa.dangerous_keywords?.length) {
    appendSection(container, 'DANGEROUS KEYWORDS', `
      <div class="tag-list">${sa.dangerous_keywords.map(k =>
        `<span class="tag bad">${escHtml(k)} <span style="color:var(--text-muted)">(×${sa.keyword_counts?.[k] || 1})</span></span>`
      ).join('')}</div>
    `);
  }

  if (sa.suspicious_patterns?.length) {
    appendSection(container, 'SUSPICIOUS PATTERNS', `
      ${sa.suspicious_patterns.map(p => `<div class="risk-factor medium" style="margin-bottom:6px">${escHtml(p)}</div>`).join('')}
    `);
  }

  if (Object.keys(sa.metadata || {}).length) {
    appendSection(container, 'DOCUMENT METADATA', `
      <div class="spec-grid">${Object.entries(sa.metadata).map(([k,v]) => specItem(k, v)).join('')}</div>
    `);
  }
}

function renderOfficeAnalysis(container, sa) {
  appendSection(container, 'OFFICE DOCUMENT FEATURES', `
    <div class="spec-grid">
      ${specItem('Format', sa.format)}
      ${specItem('VBA Macros', sa.has_macros ? 'YES ⚠' : 'NO', sa.has_macros ? 'bad' : 'ok')}
      ${specItem('Auto Macros', sa.has_auto_macros ? 'YES ⚠' : 'NO', sa.has_auto_macros ? 'bad' : 'ok')}
      ${specItem('External Links', sa.has_external_links ? 'YES' : 'NO', sa.has_external_links ? 'warn' : '')}
      ${specItem('OLE Objects', sa.has_ole_objects ? 'YES' : 'NO', sa.has_ole_objects ? 'warn' : '')}
      ${specItem('DDE Fields', sa.has_dde ? 'YES ⚠' : 'NO', sa.has_dde ? 'bad' : 'ok')}
      ${specItem('VBA Code Size', sa.vba_code_size ? formatBytes(sa.vba_code_size) : '0')}
    </div>
  `);

  if (sa.auto_macro_names?.length) {
    appendSection(container, 'AUTO-EXEC MACROS', `
      <div class="tag-list">${sa.auto_macro_names.map(n => `<span class="tag bad">${escHtml(n)}</span>`).join('')}</div>
    `);
  }

  if (sa.dangerous_functions?.length) {
    appendSection(container, 'DANGEROUS VBA FUNCTIONS', `
      <div class="tag-list">${sa.dangerous_functions.map(f => `<span class="tag bad">${escHtml(f)}</span>`).join('')}</div>
    `);
  }

  if (sa.suspicious_patterns?.length) {
    appendSection(container, 'SUSPICIOUS PATTERNS', `
      ${sa.suspicious_patterns.map(p => `<div class="risk-factor medium" style="margin-bottom:6px">${escHtml(p)}</div>`).join('')}
    `);
  }

  if (Object.keys(sa.metadata || {}).length) {
    appendSection(container, 'DOCUMENT METADATA', `
      <div class="spec-grid">${Object.entries(sa.metadata).map(([k,v]) => specItem(k, v)).join('')}</div>
    `);
  }
}

function renderScriptAnalysis(container, sa) {
  appendSection(container, 'SCRIPT OVERVIEW', `
    <div class="spec-grid">
      ${specItem('Language', sa.language)}
      ${specItem('Line Count', sa.line_count)}
      ${specItem('Avg Line Length', sa.avg_line_length)}
      ${specItem('Max Line Length', sa.max_line_length, sa.max_line_length > 500 ? 'warn' : '')}
      ${specItem('Entropy', sa.entropy)}
      ${specItem('Obfuscated', sa.is_obfuscated ? 'YES ⚠' : 'NO', sa.is_obfuscated ? 'bad' : 'ok')}
    </div>
  `);

  if (sa.suspicious_patterns?.length) {
    appendSection(container, `SUSPICIOUS PATTERNS (${sa.suspicious_patterns.length})`, `
      ${sa.suspicious_patterns.map(p => `<div class="risk-factor medium" style="margin-bottom:6px">${escHtml(p)}</div>`).join('')}
    `);
  }

  if (sa.obfuscation_indicators?.length) {
    appendSection(container, 'OBFUSCATION INDICATORS', `
      ${sa.obfuscation_indicators.map(p => `<div class="risk-factor high" style="margin-bottom:6px">${escHtml(p)}</div>`).join('')}
    `);
  }

  if (sa.network_indicators?.length) {
    appendSection(container, 'NETWORK INDICATORS', `
      <div class="tag-list">${sa.network_indicators.map(n => `<span class="tag bad">${escHtml(n)}</span>`).join('')}</div>
    `);
  }

  if (sa.execution_indicators?.length) {
    appendSection(container, 'EXECUTION INDICATORS', `
      <div class="tag-list">${sa.execution_indicators.map(e => `<span class="tag warn">${escHtml(e)}</span>`).join('')}</div>
    `);
  }
}

// ── VirusTotal ────────────────────────────────────────────────────────────────
function renderVirusTotal(data) {
  const container = document.getElementById('vt-content');
  const vt = data.virustotal;

  if (!vt) {
    container.innerHTML = `
      <div class="vt-not-configured">
        <div style="font-size:28px;color:var(--text-muted)">VT</div>
        <p>No VirusTotal API key provided.</p>
        <p style="margin-top:4px;font-size:11px">Add your free API key in the upload screen to enable hash lookup.</p>
      </div>`;
    return;
  }

  if (vt.error) {
    container.innerHTML = `<div class="ioc-empty" style="color:var(--red)">VirusTotal error: ${escHtml(vt.error)}</div>`;
    return;
  }

  if (!vt.found) {
    container.innerHTML = `<div class="ioc-empty">
      <p>${escHtml(vt.message || 'Not found in VirusTotal')}</p>
      <p style="margin-top:8px;font-size:11px;color:var(--text-muted)">SHA256: ${escHtml(vt.sha256 || '')}</p>
    </div>`;
    return;
  }

  const isDirty = vt.malicious > 0;
  container.innerHTML = `
    <div class="vt-score-big">
      <div>
        <div class="risk-label">DETECTIONS</div>
        <div class="vt-num ${isDirty ? 'dirty' : 'clean'}">${vt.malicious}/${vt.total_engines}</div>
        <div style="font-size:12px;color:var(--text-dim);margin-top:4px">${vt.detection_rate}% detection rate</div>
      </div>
      <div style="flex:1;padding-left:20px">
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">TYPE</div>
        <div style="font-size:13px;margin-bottom:12px">${escHtml(vt.type_description || 'Unknown')}</div>
        ${vt.names?.length ? `<div style="font-size:11px;color:var(--text-muted);margin-bottom:4px">KNOWN AS</div>
        <div class="tag-list">${vt.names.map(n => `<span class="tag">${escHtml(n)}</span>`).join('')}</div>` : ''}
        ${vt.tags?.length ? `<div style="margin-top:10px" class="tag-list">${vt.tags.map(t => `<span class="tag bad">${escHtml(t)}</span>`).join('')}</div>` : ''}
      </div>
    </div>
    ${vt.detections?.length ? `
      <div>
        <div style="font-size:10px;letter-spacing:0.1em;color:var(--text-muted);margin-bottom:10px">FLAGGING ENGINES</div>
        <div class="vt-det-list">
          ${vt.detections.map(d => `
            <div class="vt-det-item">
              <span class="vt-engine">${escHtml(d.engine)}</span>
              <span class="vt-result-name">${escHtml(d.result || '')}</span>
              <span class="vt-category ${d.category}">${d.category}</span>
            </div>
          `).join('')}
        </div>
      </div>` : ''}
    <a href="${escHtml(vt.permalink)}" target="_blank" class="vt-permalink">
      View on VirusTotal →
    </a>
  `;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function appendSection(container, title, bodyHTML) {
  const div = document.createElement('div');
  div.className = 'spec-section';
  div.innerHTML = `<div class="spec-header">${title}</div><div class="spec-body">${bodyHTML}</div>`;
  container.appendChild(div);
}

function specItem(label, value, cls = '') {
  const val = value === undefined || value === null ? 'N/A' : value;
  return `<div class="spec-item">
    <div class="spec-item-label">${label.toUpperCase()}</div>
    <div class="spec-item-value ${cls}">${escHtml(String(val))}</div>
  </div>`;
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function entropyColor(val) {
  if (!val) return '';
  if (val > 7.5) return 'red';
  if (val > 7.0) return 'amber';
  return '';
}

function entropyHex(val) {
  if (val > 7.5) return '#ff3333';
  if (val > 7.0) return '#ffaa00';
  return '#00ff88';
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function resetToUpload() {
  resultsSection.classList.add('hidden');
  loadingSection.classList.add('hidden');
  uploadSection.classList.remove('hidden');
  fileInput.value = '';
  currentData = null;
}

function exportJSON() {
  if (!currentData) return;
  const blob = new Blob([JSON.stringify(currentData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `malscan_${(currentData.filename || 'report').replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
  a.click();
}
