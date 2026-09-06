// ExtWatch Companion: a thin bridge between the browser's management API and the ExtWatch
// desktop app. It connects to the native messaging host that ExtWatch registers and answers
// two requests: list installed extensions and enable/disable one, and it forwards install events.
// It never reads page content and never talks to the network.

const HOST_NAME = 'app.extwatch.host';
const RECONNECT_MS = 5000;
let port = null;
let reconnectTimer = null;

function browserHint() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands) || [];
  const names = brands.map((b) => b.brand);
  if (navigator.brave || names.some((n) => /brave/i.test(n))) return 'brave';
  if (names.some((n) => /edge/i.test(n))) return 'edge';
  if (names.some((n) => /opera/i.test(n))) return 'opera';
  if (names.some((n) => /vivaldi/i.test(n))) return 'vivaldi';
  if (names.some((n) => /google chrome/i.test(n))) return 'chrome';
  if (names.some((n) => /chromium/i.test(n))) return 'chromium';
  return 'chromium-based';
}

function summarize(info) {
  return {
    id: info.id,
    name: info.name,
    version: info.version,
    enabled: info.enabled,
    installType: info.installType,
    type: info.type,
    mayDisable: info.mayDisable,
  };
}

function send(message) {
  if (!port) return false;
  try {
    port.postMessage(message);
    return true;
  } catch (e) {
    return false;
  }
}

async function sendInventory(requestId) {
  const all = await chrome.management.getAll();
  send({
    type: 'list',
    id: requestId,
    browser: browserHint(),
    self: chrome.runtime.id,
    extensions: all.filter((e) => e.type === 'extension').map(summarize),
  });
}

async function handle(message) {
  if (!message || typeof message !== 'object') return;
  switch (message.type) {
    case 'ping':
      send({ type: 'pong', id: message.id });
      break;
    case 'list':
      await sendInventory(message.id);
      break;
    case 'setEnabled': {
      const reply = { type: 'result', id: message.id, extensionId: message.extensionId, browser: browserHint() };
      try {
        const info = await chrome.management.get(message.extensionId);
        if (!info.mayDisable) {
          reply.ok = false;
          reply.error = 'The browser does not allow this extension to be disabled (policy-installed).';
        } else {
          await chrome.management.setEnabled(message.extensionId, Boolean(message.enabled));
          reply.ok = true;
          reply.enabled = Boolean(message.enabled);
        }
      } catch (e) {
        reply.ok = false;
        reply.error = String((e && e.message) || e);
      }
      send(reply);
      break;
    }
    default:
      break;
  }
}

function connect() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(HOST_NAME);
  } catch (e) {
    port = null;
    scheduleReconnect();
    return;
  }
  port.onMessage.addListener((message) => {
    handle(message).catch(() => {});
  });
  port.onDisconnect.addListener(() => {
    port = null;
    scheduleReconnect();
  });
  send({
    type: 'hello',
    browser: browserHint(),
    self: chrome.runtime.id,
    companionVersion: chrome.runtime.getManifest().version,
  });
  sendInventory(0).catch(() => {});
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, RECONNECT_MS);
}

function forwardEvent(event, info) {
  send({ type: 'event', event, browser: browserHint(), extension: info ? summarize(info) : null });
}

chrome.management.onInstalled.addListener((info) => forwardEvent('installed', info));
chrome.management.onUninstalled.addListener((id) => forwardEvent('uninstalled', { id, name: '', version: '', enabled: false }));
chrome.management.onEnabled.addListener((info) => forwardEvent('enabled', info));
chrome.management.onDisabled.addListener((info) => forwardEvent('disabled', info));
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
connect();
