// Adds a small toolbar hook on supported pages.
(function () {
  const marker = document.createElement('div');
  marker.id = 'screenshot-tool-anchor';
  marker.style.display = 'none';
  document.documentElement.appendChild(marker);
})();
