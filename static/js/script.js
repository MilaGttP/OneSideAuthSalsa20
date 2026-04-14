/**
 * script.js — UI logic for the One-Side Authentication Protocol visualizer.
 * Communicates with the Flask backend via Fetch API, step by step.
 */

// ── Shared state across steps ──────────────────────────────────────────────
const state = {
  key:          '',
  serverId:     '',
  deltaT:       30,
  plaintextHex: '',
  nonceHex:     '',
  ciphertextHex: '',
};

// ── Utility helpers ────────────────────────────────────────────────────────

function showSpinner() {
  const el = document.createElement('div');
  el.className = 'spinner-overlay';
  el.id = 'globalSpinner';
  el.innerHTML = '<div class="spinner"></div>';
  document.body.appendChild(el);
}

function hideSpinner() {
  const el = document.getElementById('globalSpinner');
  if (el) el.remove();
}

async function apiFetch(url, body) {
  showSpinner();
  try {
    const res = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Server error');
    return data;
  } finally {
    hideSpinner();
  }
}

/** Activate a step card (remove locked, add active; mark previous as done). */
function activateStep(stepId) {
  document.querySelectorAll('.step').forEach(s => {
    s.classList.remove('active');
    if (!s.classList.contains('locked')) s.classList.add('done');
  });
  const el = document.getElementById(stepId);
  el.classList.remove('locked', 'done');
  el.classList.add('active');
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  syncProgressTracker(stepId);
}

/** Sync the horizontal progress tracker with the current active step. */
function syncProgressTracker(activeStepId) {
  const order = ['step1','step2','step3','step4','step5'];
  const positions = [10, 30, 50, 70, 90];
  const fillWidths = [0, 20, 40, 60, 80];
  const activeIdx = order.indexOf(activeStepId);

  order.forEach((sid, i) => {
    const dot = document.getElementById('pt' + (i + 1));
    dot.style.left = positions[i] + '%';
    dot.classList.remove('active', 'done', 'locked');
    if      (i < activeIdx)   dot.classList.add('done');
    else if (i === activeIdx) dot.classList.add('active');
    else                      dot.classList.add('locked');
  });

  document.getElementById('ptFill').style.width = fillWidths[activeIdx] + '%';
}

function randomKey() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  document.getElementById('keyInput').value =
    Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Step 1 → Step 2 ───────────────────────────────────────────────────────

async function runStep1() {
  const keyInput = document.getElementById('keyInput').value.trim();
  const serverId = document.getElementById('serverIdInput').value.trim();
  const deltaT   = parseInt(document.getElementById('deltaTInput').value, 10);
  const hint     = document.getElementById('keyHint');

  hint.textContent = '';
  document.getElementById('idHint').textContent = '';

  if (!/^[0-9a-fA-F]{64}$/.test(keyInput)) {
    hint.textContent = 'Key must be exactly 64 hex characters (256 bits).';
    return;
  }
  if (!serverId) {
    hint.textContent = 'Server ID cannot be empty.';
    return;
  }

  state.key      = keyInput;
  state.serverId = serverId;
  state.deltaT   = isNaN(deltaT) ? 30 : deltaT;

  let data;
  try {
    data = await apiFetch('/api/step/prepare', {
      key: state.key,
      server_id: state.serverId,
    });
  } catch (e) {
    if (e.message.toLowerCase().includes('server id')) {
      document.getElementById('idHint').textContent = e.message;
    } else {
      hint.textContent = e.message;
    }
    return;
  }

  document.getElementById('tAValue').innerHTML = data.timestamp + ' <span class="unix-label">(Unix)</span>';
  document.getElementById('tAHex').textContent = data.timestamp_hex;
  document.getElementById('idHex').textContent = data.server_id_hex;
  document.getElementById('plaintextHex').textContent = data.plaintext_hex;

  state.plaintextHex = data.plaintext_hex;

  activateStep('step2');
}

// ── Step 2 → Step 3 (encrypt + matrix) ────────────────────────────────────

async function runStep3() {
  let data;
  try {
    data = await apiFetch('/api/step/encrypt', {
      key:           state.key,
      nonce:         '',
      plaintext_hex: state.plaintextHex,
    });
  } catch (e) {
    alert('Encryption error: ' + e.message);
    return;
  }

  state.nonceHex = data.nonce_hex;
  state.ciphertextHex = data.ciphertext_b64;

  document.getElementById('nonceDisplay').textContent = data.nonce_hex;
  document.getElementById('ciphertextHex').textContent = data.ciphertext_hex;

  renderMatrix('initMatrix', data.initial_matrix, true);

  activateStep('step3');

  await shuffleMatrix('outMatrix', data.output_matrix, 1500);
}

/**
 * Fills a matrix with random hex values that flicker for `duration` ms,
 * then renders the real final values.
 */
function shuffleMatrix(tableId, finalMatrix, duration) {
  return new Promise(resolve => {
    const table = document.getElementById(tableId);

    table.innerHTML = '';
    const cells = [];
    finalMatrix.forEach(row => {
      const tr = document.createElement('tr');
      row.forEach(() => {
        const td = document.createElement('td');
        td.className = 'cell-out shuffling';
        td.textContent = randomHex32();
        tr.appendChild(td);
        cells.push(td);
      });
      table.appendChild(tr);
    });

    const interval = setInterval(() => {
      cells.forEach(td => { td.textContent = randomHex32(); });
    }, 80);

    setTimeout(() => {
      clearInterval(interval);
      cells.forEach((td, i) => {
        const r = Math.floor(i / 4), c = i % 4;
        td.textContent = finalMatrix[r][c];
        td.classList.remove('shuffling');
      });
      resolve();
    }, duration);
  });
}

function randomHex32() {
  return (Math.random() * 0xFFFFFFFF >>> 0).toString(16).padStart(8, '0').toUpperCase();
}

/**
 * Render a 4×4 matrix into a <table>.
 * For the initial state, apply color classes based on Salsa20 layout:
 *   positions [0,5,10,15] = sigma constants
 *   positions [1,2,3,4,11,12,13,14] = key words
 *   positions [6,7,8,9] = nonce / counter
 */
function renderMatrix(tableId, matrix, colorCode) {
  const table = document.getElementById(tableId);
  table.innerHTML = '';

  const colorMap = {
    0: 'cell-sigma', 5: 'cell-sigma', 10: 'cell-sigma', 15: 'cell-sigma',
    1: 'cell-key',   2: 'cell-key',   3: 'cell-key',    4: 'cell-key',
    11: 'cell-key',  12: 'cell-key',  13: 'cell-key',   14: 'cell-key',
    6: 'cell-nonce', 7: 'cell-nonce', 8: 'cell-nonce',  9: 'cell-nonce',
  };

  matrix.forEach((row, r) => {
    const tr = document.createElement('tr');
    row.forEach((cell, c) => {
      const td = document.createElement('td');
      td.textContent = cell;
      if (colorCode) {
        const idx = r * 4 + c;
        td.className = colorMap[idx] || '';
      } else {
        td.className = 'cell-out';
      }
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });
}

// ── Step 3 → Step 4 (just reveal the hex dump card) ───────────────────────

function showStep4() {
  activateStep('step4');
}

function activateStep5() {
  document.getElementById('serverExpectedId').value = state.serverId;
  activateStep('step5');
}

// ── Step 4 → Step 5 (server authentication) ───────────────────────────────

async function runStep5() {
  const serverExpected = document.getElementById('serverExpectedId').value.trim() || state.serverId;
  const deltaTServer   = state.deltaT;

  let data;
  try {
    data = await apiFetch('/api/step/authenticate', {
      key: state.key,
      nonce: state.nonceHex,
      ciphertext_hex: state.ciphertextHex,
      server_id: serverExpected, 
      delta_t: deltaTServer,
    });
  } catch (e) {
    alert('Authentication error: ' + e.message);
    return;
  }

  document.getElementById('authTA').innerHTML = data.t_a_extracted + ' <span class="unix-label">(Unix)</span>';
  document.getElementById('authTB').innerHTML = data.t_b + ' <span class="unix-label">(Unix)</span>';
  document.getElementById('authDeltaStar').textContent = data.delta_t_star + ' s';
  document.getElementById('authDelta').textContent = data.delta_t + ' s';
  document.getElementById('authIDExtracted').textContent = data.id_extracted;
  document.getElementById('authIDExpected').textContent = serverExpected;

  setCheck('checkID',   data.id_match);
  setCheck('checkTime', data.time_ok);

  const box  = document.getElementById('decisionBox');
  const text = document.getElementById('decisionText');
  if (data.access_granted) {
    box.className  = 'decision-box granted';
    text.textContent = '✓  ACCESS GRANTED';
  } else {
    box.className  = 'decision-box denied';
    text.textContent = '✗  ACCESS DENIED';
  }
}

function setCheck(id, passed) {
  const el = document.getElementById(id);
  el.classList.remove('pass', 'fail');
  el.classList.add(passed ? 'pass' : 'fail');
  el.querySelector('.check-icon').textContent = '';
}

// ── Reset ──────────────────────────────────────────────────────────────────

function resetAll() {
  Object.assign(state, {
    key: '', serverId: '', deltaT: 30,
    plaintextHex: '', nonceHex: '', ciphertextHex: '',
  });

  document.getElementById('keyInput').value =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  document.getElementById('serverIdInput').value = 'SERVER-ALPHA-01';
  document.getElementById('deltaTInput').value   = '30';
  document.getElementById('keyHint').textContent = '';

  document.getElementById('serverExpectedId').value = '';

  ['tAValue','tAHex','idHex','plaintextHex','nonceDisplay','ciphertextHex',
   'authTA','authTB','authDeltaStar','authDelta','authIDExtracted','authIDExpected',
   'decisionText'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '—';
  });

  ['initMatrix','outMatrix'].forEach(id => {
    const t = document.getElementById(id);
    if (t) t.innerHTML = '';
  });

  ['checkID','checkTime'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('pass','fail');
    el.querySelector('.check-icon').textContent = '';
  });

  const box = document.getElementById('decisionBox');
  box.className = 'decision-box';
  document.getElementById('decisionText').textContent = 'Awaiting...';

  document.querySelectorAll('.step').forEach(s => {
    s.classList.remove('active','done','locked');
  });
  document.getElementById('step1').classList.add('active');
  ['step2','step3','step4','step5'].forEach(id =>
    document.getElementById(id).classList.add('locked')
  );

  window.scrollTo({ top: 0, behavior: 'smooth' });
  syncProgressTracker('step1');
}

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('step1').classList.add('active');
  document.getElementById('qrHelpBtn').addEventListener('click', () => {
    document.getElementById('qrOverlay').classList.add('open');
  });
  syncProgressTracker('step1');
});

function closeQRHelp() {
  document.getElementById('qrOverlay').classList.remove('open');
}

function copyCiphertext() {
  const text = document.getElementById('ciphertextHex').textContent;
  if (!text || text === '—') return;
  navigator.clipboard.writeText(text).then(() => {
    const btn   = document.getElementById('copyBtn');
    const label = document.getElementById('copyLabel');
    btn.classList.add('copied');
    label.textContent = 'Copied!';
    setTimeout(() => {
      btn.classList.remove('copied');
      label.textContent = 'Copy';
    }, 2000);
  });
}
