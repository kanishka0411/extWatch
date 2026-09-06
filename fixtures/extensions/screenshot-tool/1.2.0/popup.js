document.getElementById('capture').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'capture' });
});
