const defaults = {
  apiBaseUrl: 'http://127.0.0.1:5000',
  apiKey: '',
  superScanDefault: true,
};

const apiBaseUrlInput = document.getElementById('apiBaseUrl');
const apiKeyInput = document.getElementById('apiKey');
const superScanDefaultInput = document.getElementById('superScanDefault');
const statusText = document.getElementById('statusText');
const saveBtn = document.getElementById('saveBtn');
const resetBtn = document.getElementById('resetBtn');

function setStatus(message, isError = false) {
  statusText.textContent = message;
  statusText.style.color = isError ? '#b91c1c' : '#166534';
}

async function loadSettings() {
  const settings = await chrome.storage.sync.get(defaults);
  apiBaseUrlInput.value = settings.apiBaseUrl || defaults.apiBaseUrl;
  apiKeyInput.value = settings.apiKey || '';
  superScanDefaultInput.checked = Boolean(settings.superScanDefault);
}

async function saveSettings() {
  const apiBaseUrl = apiBaseUrlInput.value.trim();
  if (!apiBaseUrl) {
    setStatus('API base URL is required.', true);
    return;
  }

  await chrome.storage.sync.set({
    apiBaseUrl,
    apiKey: apiKeyInput.value.trim(),
    superScanDefault: superScanDefaultInput.checked,
  });

  setStatus('Settings saved.');
}

async function resetSettings() {
  await chrome.storage.sync.set({ ...defaults });
  await loadSettings();
  setStatus('Settings reset to defaults.');
}

saveBtn.addEventListener('click', saveSettings);
resetBtn.addEventListener('click', resetSettings);

loadSettings();
