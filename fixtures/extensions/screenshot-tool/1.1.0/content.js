// Adds a small toolbar hook on supported pages.
(function () {
  const marker = document.createElement('div');
  marker.id = 'screenshot-tool-anchor';
  marker.style.display = 'none';
  marker.dataset.version = '1.1.0';
  document.documentElement.appendChild(marker);
})();
