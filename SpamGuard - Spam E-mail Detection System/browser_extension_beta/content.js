chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== 'SPAMGUARD_GET_CONTEXT') {
    return;
  }

  const selectedText = (window.getSelection && window.getSelection().toString()) || '';
  sendResponse({
    selectedText: selectedText.trim(),
    pageUrl: window.location.href,
    pageTitle: document.title,
  });
});
