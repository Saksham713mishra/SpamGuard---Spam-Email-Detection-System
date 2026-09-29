chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'spamguard-open-scanner',
    title: 'Scan selected text with SpamGuard',
    contexts: ['selection']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'spamguard-open-scanner') {
    return;
  }

  if (info.selectionText) {
    await chrome.storage.local.set({
      spamguard_selection_text: info.selectionText,
      spamguard_selection_url: tab && tab.url ? tab.url : ''
    });
  }

  if (tab && tab.id) {
    if (chrome.action && typeof chrome.action.openPopup === 'function') {
      chrome.action.openPopup().catch(() => {
        // Ignore popup-open failures on unsupported browser versions.
      });
    }
  }
});
