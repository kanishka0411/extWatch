// Screenshot Tool background worker
const state = { captures: 0 };

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'capture') {
    chrome.tabs.captureVisibleTab({ format: 'png' }, (dataUrl) => {
      state.captures += 1;
      chrome.storage.local.set({ lastCapture: dataUrl, captures: state.captures });
      sendResponse({ ok: true });
    });
    return true;
  }
  return false;
});
