/* ═══════════════════════════════════════════════════════════
   app.js — CRYPTEX · Logique Frontend Complète
   Gère : Boot, Navigation, Chiffrement, Déchiffrement,
          Dashboard Clés, Historique, Toasts, Animations
═══════════════════════════════════════════════════════════ */

'use strict';

const API = 'http://127.0.0.1:8000/api';

/* ══════════════════════════════════════════════════════════
   UTILITAIRES GLOBAUX
══════════════════════════════════════════════════════════ */

function $(id) { return document.getElementById(id); }

function show(el) { if (typeof el === 'string') el = $(el); el?.classList.remove('hidden'); }
function hide(el) { if (typeof el === 'string') el = $(el); el?.classList.add('hidden'); }
function toggle(el, condition) { condition ? show(el) : hide(el); }

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1048576).toFixed(2)} Mo`;
}

function formatTime(isoStr) {
  const d = new Date(isoStr);
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit' })
    + ' · ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

function getFileExt(name) {
  const parts = name.split('.');
  return parts.length > 1 ? parts.pop().toUpperCase() : 'FILE';
}

/* ══════════════════════════════════════════════════════════
   TOAST SYSTÈME
══════════════════════════════════════════════════════════ */

function toast(type, title, msg, duration = 4000) {
  const container = $('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `
    <div class="toast-dot"></div>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      ${msg ? `<div class="toast-msg">${msg}</div>` : ''}
    </div>
  `;
  container.appendChild(el);

  const dismiss = () => {
    el.classList.add('hiding');
    setTimeout(() => el.remove(), 280);
  };
  setTimeout(dismiss, duration);
  el.addEventListener('click', dismiss);
}

/* ══════════════════════════════════════════════════════════
   MODALE DE CONFIRMATION
══════════════════════════════════════════════════════════ */

function confirmModal(title, body) {
  return new Promise((resolve) => {
    $('modal-title').textContent = title;
    $('modal-body').textContent  = body;
    show('modal-overlay');

    const onConfirm = () => { cleanup(); resolve(true); };
    const onCancel  = () => { cleanup(); resolve(false); };

    function cleanup() {
      hide('modal-overlay');
      $('modal-confirm').removeEventListener('click', onConfirm);
      $('modal-cancel').removeEventListener('click', onCancel);
    }

    $('modal-confirm').addEventListener('click', onConfirm);
    $('modal-cancel').addEventListener('click', onCancel);
  });
}

/* ══════════════════════════════════════════════════════════
   CANVAS DE FOND — Grille hexagonale animée
══════════════════════════════════════════════════════════ */

function initBgCanvas() {
  const canvas = $('bg-canvas');
  const ctx    = canvas.getContext('2d');

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const dots = [];
  const COUNT = 60;

  for (let i = 0; i < COUNT; i++) {
    dots.push({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      r: Math.random() * 1.5 + 0.3,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      alpha: Math.random() * 0.4 + 0.1,
    });
  }

  function drawFrame() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Connexions entre points proches
    for (let i = 0; i < dots.length; i++) {
      for (let j = i + 1; j < dots.length; j++) {
        const dx = dots[i].x - dots[j].x;
        const dy = dots[i].y - dots[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 140) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(0, 229, 255, ${(1 - dist / 140) * 0.06})`;
          ctx.lineWidth   = 0.5;
          ctx.moveTo(dots[i].x, dots[i].y);
          ctx.lineTo(dots[j].x, dots[j].y);
          ctx.stroke();
        }
      }
    }

    // Points
    dots.forEach(dot => {
      ctx.beginPath();
      ctx.arc(dot.x, dot.y, dot.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 229, 255, ${dot.alpha})`;
      ctx.fill();

      dot.x += dot.vx;
      dot.y += dot.vy;

      if (dot.x < 0 || dot.x > canvas.width)  dot.vx *= -1;
      if (dot.y < 0 || dot.y > canvas.height)  dot.vy *= -1;
    });

    requestAnimationFrame(drawFrame);
  }

  drawFrame();
}

/* ══════════════════════════════════════════════════════════
   FLUX DE CARACTÈRES (animation chiffrement)
══════════════════════════════════════════════════════════ */

let cipherStreamInterval = null;
const HEX_CHARS = '0123456789ABCDEF';

function startCipherStream() {
  const el = $('cipher-stream');
  cipherStreamInterval = setInterval(() => {
    let str = '';
    for (let i = 0; i < 80; i++) {
      str += HEX_CHARS[Math.floor(Math.random() * 16)];
      if (i % 2 === 1 && i < 79) str += ':';
    }
    el.textContent = str;
  }, 80);
}

function stopCipherStream() {
  clearInterval(cipherStreamInterval);
  $('cipher-stream').textContent = '';
}

/* ══════════════════════════════════════════════════════════
   ANIMATION DES ÉTAPES DE PROGRESSION
══════════════════════════════════════════════════════════ */

async function animateEncryptSteps() {
  show('encrypt-progress');
  const steps = ['hash', 'sign', 'aes', 'rsa'];
  const weights = [15, 35, 75, 100];
  const bar     = $('progress-bar');

  startCipherStream();

  for (let i = 0; i < steps.length; i++) {
    const el = $(`pstep-${steps[i]}`);
    el.classList.add('active');
    bar.style.width = weights[i] + '%';
    await sleep(420);
    el.classList.remove('active');
    el.classList.add('done');
  }

  stopCipherStream();
}

function resetEncryptProgress() {
  hide('encrypt-progress');
  $('progress-bar').style.width = '0%';
  ['hash','sign','aes','rsa'].forEach(s => {
    const el = $(`pstep-${s}`);
    el.classList.remove('active', 'done');
  });
}

async function animateDecryptChecks(success) {
  const checks = ['key', 'gcm', 'hash', 'sig'];

  for (let i = 0; i < checks.length; i++) {
    const el = $(`vcheck-${checks[i]}`);
    const status = el.querySelector('.vcheck-status');
    el.classList.add('checking');
    status.textContent = '…';
    await sleep(350);

    if (!success && i === checks.length - 1) {
      el.classList.remove('checking');
      el.classList.add('fail');
      status.textContent = '✕ Échec';
    } else {
      el.classList.remove('checking');
      el.classList.add('ok');
      status.textContent = '✓ OK';
    }
    await sleep(100);
  }
}

function resetDecryptChecks() {
  ['key','gcm','hash','sig'].forEach(id => {
    const el = $(`vcheck-${id}`);
    el.classList.remove('checking', 'ok', 'fail');
    el.querySelector('.vcheck-status').textContent = '—';
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ══════════════════════════════════════════════════════════
   FORCE DU MOT DE PASSE
══════════════════════════════════════════════════════════ */

function checkPasswordStrength(pwd) {
  let score = 0;
  if (pwd.length >= 8)  score++;
  if (pwd.length >= 14) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  const levels = [
    { label: '', color: 'transparent', w: '0%' },
    { label: 'Faible', color: '#ff3d5a', w: '25%' },
    { label: 'Moyen',  color: '#ffab00', w: '50%' },
    { label: 'Bien',   color: '#00b8d4', w: '75%' },
    { label: 'Robuste',color: '#00ff88', w: '100%' },
  ];

  const level = Math.min(score, 4);
  return levels[level];
}

/* ══════════════════════════════════════════════════════════
   FINGERPRINT DISPLAY
══════════════════════════════════════════════════════════ */

function renderFingerprint(fp) {
  if (!fp) return;

  // Sidebar (version courte)
  $('sidebar-fingerprint').textContent = fp.slice(0, 23) + '…';

  // Dashboard (grille complète)
  const grid = $('fingerprint-grid');
  grid.innerHTML = '';
  const pairs = fp.split(':');
  pairs.forEach(pair => {
    const cell = document.createElement('span');
    cell.className = 'kfp-cell';
    cell.textContent = pair;
    grid.appendChild(cell);
  });
}

function setKeyStatus(loaded) {
  const dot  = $('status-dot');
  const text = $('status-text');
  if (loaded) {
    dot.classList.add('online');
    text.textContent = 'Clés actives';
  } else {
    dot.classList.remove('online');
    text.textContent = 'Hors ligne';
  }
}

/* ══════════════════════════════════════════════════════════
   NAVIGATION ENTRE PANELS
══════════════════════════════════════════════════════════ */

function initNav() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const panelId = btn.dataset.panel;

      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => {
        p.classList.remove('active');
        hide(p);
      });

      btn.classList.add('active');
      const panel = $(`panel-${panelId}`);
      show(panel);
      panel.classList.add('active');

      if (panelId === 'history') loadHistory();
    });
  });
}

/* ══════════════════════════════════════════════════════════
   BOOT — ÉCRAN DE DÉMARRAGE
══════════════════════════════════════════════════════════ */

async function initBoot() {
  let status;
  try {
    const res = await fetch(`${API}/keys/status`);
    status = await res.json();
  } catch (e) {
    // Le serveur n'est peut-être pas encore démarré — mode démo
    status = { keys_on_disk: false, keys_loaded: false, fingerprint: null };
  }

  if (status.keys_loaded) {
    // Déjà chargées (ne devrait pas arriver au boot normal, mais par précaution)
    bootSuccess(status.fingerprint);
    return;
  }

  if (status.keys_on_disk) {
    show('boot-existing');
  } else {
    show('boot-new');
  }

  // Password strength meter
  $('new-password').addEventListener('input', (e) => {
    const s = checkPasswordStrength(e.target.value);
    $('strength-fill').style.width      = s.w;
    $('strength-fill').style.background = s.color;
    $('strength-label').textContent     = s.label;
  });

  // Générer une nouvelle paire
  $('btn-generate-keys').addEventListener('click', async () => {
    const pwd = $('new-password').value.trim();
    if (!pwd) { toast('warning', 'Passphrase requise', 'Saisissez une passphrase pour protéger la clé privée.'); return; }
    await bootAction('Génération RSA-4096 en cours…', async () => {
      const fd = new FormData();
      fd.append('password', pwd);
      const res  = await fetch(`${API}/keys/generate`, { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Erreur serveur');
      if (data.warning) toast('warning', 'Avertissement', data.warning, 7000);
      bootSuccess(data.fingerprint);
    });
  });

  // Charger les clés existantes
  $('btn-load-keys')?.addEventListener('click', async () => {
    const pwd = $('load-password').value;
    if (!pwd) { toast('warning', 'Passphrase requise', ''); return; }
    await bootAction('Dérivation Argon2id en cours…', async () => {
      const fd = new FormData();
      fd.append('password', pwd);
      const res  = await fetch(`${API}/keys/load`, { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Mot de passe incorrect');
      bootSuccess(data.fingerprint);
    });
  });

  // Autoriser Entrée sur les champs password
  [$('new-password'), $('load-password')].forEach(input => {
    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const btn = $('btn-generate-keys') || $('btn-load-keys');
        btn?.click();
      }
    });
  });

  // Régénérer depuis l'écran existant
  $('btn-regen-keys')?.addEventListener('click', () => {
    hide('boot-existing');
    show('boot-new');
  });
}

async function bootAction(processingText, fn) {
  hide('boot-new');
  hide('boot-existing');
  show('boot-loading');
  $('boot-processing-text').textContent = processingText;

  try {
    await fn();
  } catch (e) {
    hide('boot-loading');
    // Reaffiche le bon formulaire
    const status = await fetch(`${API}/keys/status`).then(r => r.json()).catch(() => ({ keys_on_disk: false }));
    status.keys_on_disk ? show('boot-existing') : show('boot-new');
    toast('error', 'Erreur', e.message, 6000);
  }
}

function bootSuccess(fingerprint) {
  renderFingerprint(fingerprint);
  setKeyStatus(true);

  const overlay = $('boot-overlay');
  overlay.style.transition = 'opacity 0.5s ease';
  overlay.style.opacity    = '0';
  setTimeout(() => {
    hide(overlay);
    show('app');
    initBgCanvas();
  }, 500);
}

/* ══════════════════════════════════════════════════════════
   PANEL CHIFFREMENT
══════════════════════════════════════════════════════════ */

let encryptFile = null;

function initEncrypt() {
  // Toggle mode Fichier / Message
  $('mode-file').addEventListener('click', () => switchMode('file'));
  $('mode-msg').addEventListener('click',  () => switchMode('message'));

  function switchMode(mode) {
    $('mode-file').classList.toggle('active', mode === 'file');
    $('mode-msg').classList.toggle('active', mode === 'message');
    toggle('encrypt-file-mode', mode === 'file');
    toggle('encrypt-msg-mode',  mode === 'message');
    resetEncryptProgress();
  }

  // Dropzone Fichier
  const dropzone = $('encrypt-dropzone');
  const fileInput = $('file-input');

  dropzone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => { if (e.target.files[0]) setEncryptFile(e.target.files[0]); });

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) setEncryptFile(e.dataTransfer.files[0]);
  });

  $('file-remove').addEventListener('click', clearEncryptFile);

  // Chiffrement fichier
  $('btn-encrypt-file').addEventListener('click', handleEncryptFile);

  // Compteur de caractères message
  $('message-input').addEventListener('input', (e) => {
    $('char-count').textContent = `${e.target.value.length} caractères`;
  });

  // Chiffrement message
  $('btn-encrypt-msg').addEventListener('click', handleEncryptMessage);
}

function setEncryptFile(file) {
  encryptFile = file;
  hide('encrypt-dropzone');
  show('file-preview');
  $('file-ext').textContent  = getFileExt(file.name);
  $('file-name').textContent = file.name;
  $('file-size').textContent = formatBytes(file.size);
  $('btn-encrypt-file').disabled = false;
}

function clearEncryptFile() {
  encryptFile = null;
  show('encrypt-dropzone');
  hide('file-preview');
  $('file-input').value = '';
  $('btn-encrypt-file').disabled = true;
  resetEncryptProgress();
}

async function handleEncryptFile() {
  if (!encryptFile) return;
  const btn = $('btn-encrypt-file');

  setButtonLoading(btn, true);
  resetEncryptProgress();

  try {
    const anim = animateEncryptSteps();

    const fd = new FormData();
    fd.append('file', encryptFile);
    fd.append('save_to_disk', $('save-to-disk').checked);

    const res = await fetch(`${API}/encrypt/file`, { method: 'POST', body: fd });

    await anim;

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.detail || 'Erreur de chiffrement');
    }

    // Téléchargement automatique
    const blob     = await res.blob();
    const filename = extractFilename(res) || `encrypted_${Date.now()}.bin`;
    downloadBlob(blob, filename);

    toast('success', 'Fichier chiffré', `Téléchargement de "${filename}" démarré.`);
    clearEncryptFile();

  } catch (e) {
    stopCipherStream();
    toast('error', 'Échec du chiffrement', e.message, 7000);
  } finally {
    setButtonLoading(btn, false);
  }
}

async function handleEncryptMessage() {
  const msg = $('message-input').value.trim();
  if (!msg) { toast('warning', 'Message vide', 'Saisissez un message à chiffrer.'); return; }

  const btn = $('btn-encrypt-msg');
  setButtonLoading(btn, true);
  resetEncryptProgress();

  try {
    const anim = animateEncryptSteps();

    const fd = new FormData();
    fd.append('message', msg);

    const res = await fetch(`${API}/encrypt/message`, { method: 'POST', body: fd });

    await anim;

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.detail || 'Erreur de chiffrement');
    }

    const blob     = await res.blob();
    const filename = extractFilename(res) || `message_${Date.now()}.bin`;
    downloadBlob(blob, filename);

    toast('success', 'Message chiffré', `Téléchargement de "${filename}" démarré.`);
    $('message-input').value = '';
    $('char-count').textContent = '0 caractères';

  } catch (e) {
    stopCipherStream();
    toast('error', 'Échec du chiffrement', e.message, 7000);
  } finally {
    setButtonLoading(btn, false);
  }
}

/* ══════════════════════════════════════════════════════════
   PANEL DÉCHIFFREMENT
══════════════════════════════════════════════════════════ */

let decryptFile = null;

function initDecrypt() {
  const dropzone  = $('decrypt-dropzone');
  const fileInput = $('decrypt-input');

  dropzone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => { if (e.target.files[0]) setDecryptFile(e.target.files[0]); });

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) setDecryptFile(e.dataTransfer.files[0]);
  });

  $('decrypt-remove').addEventListener('click', clearDecryptFile);
  $('btn-decrypt').addEventListener('click', handleDecrypt);
}

function setDecryptFile(file) {
  decryptFile = file;
  hide('decrypt-dropzone');
  show('decrypt-preview');
  $('decrypt-name').textContent = file.name;
  $('decrypt-size').textContent = formatBytes(file.size);
  $('btn-decrypt').disabled = false;
  resetDecryptChecks();
}

function clearDecryptFile() {
  decryptFile = null;
  show('decrypt-dropzone');
  hide('decrypt-preview');
  $('decrypt-input').value = '';
  $('btn-decrypt').disabled = true;
  resetDecryptChecks();
}

async function handleDecrypt() {
  if (!decryptFile) return;
  const btn = $('btn-decrypt');
  setButtonLoading(btn, true);
  resetDecryptChecks();

  try {
    const fd = new FormData();
    fd.append('file', decryptFile);

    const [res] = await Promise.all([
      fetch(`${API}/decrypt/file`, { method: 'POST', body: fd }),
      animateDecryptChecks(true),
    ]);

    if (!res.ok) {
      const data = await res.json();
      await animateDecryptChecks(false);
      throw new Error(data.detail || 'Erreur de déchiffrement');
    }

    const blob     = await res.blob();
    const filename = extractFilename(res) || `decrypted_${Date.now()}`;
    downloadBlob(blob, filename);

    toast('success', 'Déchiffrement réussi', `Intégrité et signature vérifiées. "${filename}" téléchargé.`, 6000);
    clearDecryptFile();

  } catch (e) {
    toast('error', 'Échec du déchiffrement', e.message, 8000);
  } finally {
    setButtonLoading(btn, false);
  }
}

/* ══════════════════════════════════════════════════════════
   PANEL CLÉS
══════════════════════════════════════════════════════════ */

function initKeys() {
  // Export clé publique
  $('btn-export-pub').addEventListener('click', async () => {
    try {
      const res = await fetch(`${API}/keys/export/public`);
      if (!res.ok) throw new Error('Erreur export');
      const blob = await res.blob();
      downloadBlob(blob, 'public_key.pem');
      toast('success', 'Clé publique exportée', 'Fichier "public_key.pem" téléchargé.');
    } catch (e) {
      toast('error', 'Erreur export', e.message);
    }
  });

  // Import clé publique externe
  const pubKeyDropzone = $('pubkey-dropzone');
  const pubKeyInput    = $('pubkey-input');

  pubKeyDropzone.addEventListener('click', () => pubKeyInput.click());
  pubKeyDropzone.addEventListener('dragover', (e) => { e.preventDefault(); pubKeyDropzone.classList.add('dragover'); });
  pubKeyDropzone.addEventListener('dragleave', () => pubKeyDropzone.classList.remove('dragover'));
  pubKeyDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    pubKeyDropzone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) importPubKey(e.dataTransfer.files[0]);
  });
  pubKeyInput.addEventListener('change', (e) => { if (e.target.files[0]) importPubKey(e.target.files[0]); });

  async function importPubKey(file) {
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res  = await fetch(`${API}/keys/import/public`, { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail);

      show('imported-key-info');
      $('imported-fp').textContent = data.fingerprint.slice(0, 47) + '…';
      toast('success', 'Clé importée', `Fingerprint : ${data.fingerprint.slice(0, 23)}…`);
    } catch (e) {
      toast('error', 'Import échoué', e.message);
    }
  }

  // Régénération (danger zone)
  $('btn-regen-from-panel').addEventListener('click', async () => {
    const confirmed = await confirmModal(
      'Régénérer le trousseau ?',
      'Tous les fichiers chiffrés avec la paire de clés actuelle seront définitivement illisibles. Cette action est irréversible.'
    );
    if (confirmed) {
      // Recharge l'overlay de boot pour saisir la nouvelle passphrase
      show('boot-overlay');
      hide('boot-loading');
      hide('boot-existing');
      show('boot-new');
      $('new-password').value = '';
    }
  });
}

/* ══════════════════════════════════════════════════════════
   HISTORIQUE
══════════════════════════════════════════════════════════ */

async function loadHistory() {
  try {
    const res     = await fetch(`${API}/history`);
    const entries = await res.json();
    renderHistory(entries);
  } catch {
    renderHistory([]);
  }
}

function renderHistory(entries) {
  const list = $('history-list');
  list.innerHTML = '';

  if (!entries.length) {
    list.innerHTML = '<div class="history-empty"><p>Aucune opération enregistrée.</p></div>';
    return;
  }

  // Tri du plus récent au plus ancien
  [...entries].reverse().forEach(entry => {
    const el     = document.createElement('div');
    const isOk   = entry.status === 'success';
    const action = entry.action.replace('_MSG', ' MSG');

    const chipClass = entry.status === 'error' ? 'chip-error'
      : action.includes('ENCRYPT') ? 'chip-encrypt'
      : 'chip-decrypt';

    el.className = `history-entry ${isOk ? 'success' : 'error'}`;
    el.innerHTML = `
      <span class="history-action-chip ${chipClass}">${action}</span>
      <div class="history-meta">
        <div class="history-filename">${entry.filename}</div>
        ${entry.detail ? `<div class="history-detail">${entry.detail}</div>` : ''}
      </div>
      <span class="history-time">${formatTime(entry.timestamp)}</span>
    `;
    list.appendChild(el);
  });
}

function initHistory() {
  $('btn-clear-history').addEventListener('click', async () => {
    const confirmed = await confirmModal('Effacer l\'historique ?', 'Toutes les entrées seront supprimées. Cette action est irréversible.');
    if (!confirmed) return;
    try {
      await fetch(`${API}/history`, { method: 'DELETE' });
      renderHistory([]);
      toast('success', 'Historique effacé', '');
    } catch {
      toast('error', 'Erreur', 'Impossible d\'effacer l\'historique.');
    }
  });
}

/* ══════════════════════════════════════════════════════════
   UTILITAIRES UI
══════════════════════════════════════════════════════════ */

function setButtonLoading(btn, loading) {
  const text   = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  btn.disabled = loading;
  if (text)   toggle(text,   !loading);
  if (loader) toggle(loader, loading);
}

function extractFilename(res) {
  const cd = res.headers.get('Content-Disposition') || '';
  const match = cd.match(/filename=(.+)/);
  return match ? match[1].replace(/"/g, '') : null;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ══════════════════════════════════════════════════════════
   POINT D'ENTRÉE
══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', async () => {
  initNav();
  initEncrypt();
  initDecrypt();
  initKeys();
  initHistory();

  // Fermeture modale via overlay
  $('modal-overlay').addEventListener('click', (e) => {
    if (e.target === $('modal-overlay')) hide('modal-overlay');
  });

  // Démarre le boot
  await initBoot();
});
