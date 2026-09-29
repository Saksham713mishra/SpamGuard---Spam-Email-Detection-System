const defaultSettings = {
  apiBaseUrl: 'http://127.0.0.1:5000',
  apiKey: '',
  superScanDefault: true,
};

const state = {
  settings: { ...defaultSettings },
  lastScan: null,
};

const messageInput = document.getElementById('messageInput');
const urlInput = document.getElementById('urlInput');
const superScanToggle = document.getElementById('superScanToggle');
const resultPanel = document.getElementById('resultPanel');
const verdictText = document.getElementById('verdictText');
const riskText = document.getElementById('riskText');
const reasonList = document.getElementById('reasonList');
const statusText = document.getElementById('statusText');
const feedbackStatus = document.getElementById('feedbackStatus');

const scanBtn = document.getElementById('scanBtn');
const clearBtn = document.getElementById('clearBtn');
const markSafeBtn = document.getElementById('markSafeBtn');
const markScamBtn = document.getElementById('markScamBtn');
const openOptionsBtn = document.getElementById('openOptionsBtn');

function setStatus(text, isError = false) {
  statusText.textContent = text || '';
  statusText.style.color = isError ? '#b91c1c' : '#64748b';
}

function setFeedbackStatus(text, isError = false) {
  feedbackStatus.textContent = text || '';
  feedbackStatus.style.color = isError ? '#b91c1c' : '#166534';
}

async function loadSettings() {
  const stored = await chrome.storage.sync.get(defaultSettings);
  state.settings = {
    apiBaseUrl: String(stored.apiBaseUrl || defaultSettings.apiBaseUrl).trim(),
    apiKey: String(stored.apiKey || '').trim(),
    superScanDefault: Boolean(stored.superScanDefault),
  };
  superScanToggle.checked = state.settings.superScanDefault;
}

function getHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (state.settings.apiKey) {
    headers['X-API-Key'] = state.settings.apiKey;
  }
  return headers;
}

async function getActiveTabContext() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const activeTab = tabs && tabs.length > 0 ? tabs[0] : null;

  if (!activeTab) {
    return;
  }

  urlInput.value = activeTab.url || '';

  try {
    const response = await chrome.tabs.sendMessage(activeTab.id, { type: 'SPAMGUARD_GET_CONTEXT' });
    if (response && typeof response.selectedText === 'string' && response.selectedText.trim()) {
      messageInput.value = response.selectedText.trim();
    }
  } catch (error) {
    // Content script may not run on restricted pages (chrome://, extension pages).
  }
}

async function loadStoredSelectionFallback() {
  const data = await chrome.storage.local.get({
    spamguard_selection_text: '',
    spamguard_selection_url: '',
  });

  if (!messageInput.value.trim() && data.spamguard_selection_text) {
    messageInput.value = String(data.spamguard_selection_text).trim();
  }

  if (!urlInput.value.trim() && data.spamguard_selection_url) {
    urlInput.value = String(data.spamguard_selection_url).trim();
  }
}

function renderScanResult(payload) {
  resultPanel.classList.remove('hidden');

  const verdict = String(payload.verdict || 'unknown').replaceAll('_', ' ').toUpperCase();
  const score = Number(payload.risk_score || 0);
  const level = String(payload.risk_level || 'low').toUpperCase();

  verdictText.textContent = `Verdict: ${verdict}`;
  riskText.textContent = `Risk: ${score}/100 (${level})`;

  const explanations = Array.isArray(payload.explanations) ? payload.explanations : [];
  reasonList.innerHTML = '';

  if (explanations.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No explanation available.';
    reasonList.appendChild(li);
  } else {
    explanations.slice(0, 4).forEach((item) => {
      const li = document.createElement('li');
      li.textContent = String(item);
      reasonList.appendChild(li);
    });
  }

  state.lastScan = payload;
  setFeedbackStatus('');
}

async function runScan() {
  const emailText = messageInput.value.trim();
  const url = urlInput.value.trim();

  if (!emailText && !url) {
    setStatus('Provide message text or URL before scanning.', true);
    return;
  }

  scanBtn.disabled = true;
  setStatus('Running scan...');

  const requestBody = {
    email_text: emailText,
    url,
    super_scan: superScanToggle.checked,
  };

  try {
    const response = await fetch(`${state.settings.apiBaseUrl}/scan`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(requestBody),
    });

    const payload = await response.json();
    if (!response.ok || payload.error) {
      setStatus(payload.error || 'Scan failed.', true);
      return;
    }

    renderScanResult(payload);
    setStatus('Scan completed.');
  } catch (error) {
    setStatus('Unable to connect to SpamGuard API.', true);
  } finally {
    scanBtn.disabled = false;
  }
}

async function submitFeedback(feedbackLabel) {
  if (!state.lastScan) {
    setFeedbackStatus('Run a scan before sending feedback.', true);
    return;
  }

  const payload = {
    feedback_label: feedbackLabel,
    email_text: messageInput.value.trim(),
    url: urlInput.value.trim(),
    scan_history_id: state.lastScan.scan_history_id,
    original_scan: {
      verdict: state.lastScan.verdict,
      risk_level: state.lastScan.risk_level,
      risk_score: state.lastScan.risk_score,
    },
    source: 'extension_beta',
  };

  markSafeBtn.disabled = true;
  markScamBtn.disabled = true;
  setFeedbackStatus('Submitting feedback...');

  try {
    const response = await fetch(`${state.settings.apiBaseUrl}/feedback`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (!response.ok || result.error) {
      setFeedbackStatus(result.error || 'Feedback failed.', true);
      return;
    }

    setFeedbackStatus('Feedback recorded for retraining.');
  } catch (error) {
    setFeedbackStatus('Unable to submit feedback.', true);
  } finally {
    markSafeBtn.disabled = false;
    markScamBtn.disabled = false;
  }
}

function clearFields() {
  messageInput.value = '';
  urlInput.value = '';
  resultPanel.classList.add('hidden');
  state.lastScan = null;
  setStatus('');
  setFeedbackStatus('');
}

scanBtn.addEventListener('click', runScan);
clearBtn.addEventListener('click', clearFields);
markSafeBtn.addEventListener('click', () => submitFeedback('safe'));
markScamBtn.addEventListener('click', () => submitFeedback('scam'));
openOptionsBtn.addEventListener('click', () => chrome.runtime.openOptionsPage());

(async function init() {
  await loadSettings();
  await getActiveTabContext();
  await loadStoredSelectionFallback();
})();
