# ExtWatch Companion

A ~150-line Manifest V3 extension that gives the ExtWatch desktop app a one-click **Disable**
button and instant install/update events. It has the `management` and `nativeMessaging`
permissions only, never reads page content and never uses the network.

## Install (unpacked)

1. In ExtWatch, open **Settings → Companion → Set up**. This registers the native messaging host
   for every browser found on the machine and copies this folder to the ExtWatch data directory.
2. Open `chrome://extensions` (or `brave://extensions`, `edge://extensions`), turn on
   **Developer mode**, click **Load unpacked** and choose the folder ExtWatch opened.
3. The status in ExtWatch changes to "companion connected".

The `key` in `manifest.json` gives the unpacked extension a stable ID, which the native messaging
host manifest whitelists. The matching private key is not in the repository.

## Protocol

Native messaging (4-byte little-endian length + JSON). Messages from the app:
`{type: "ping"}`, `{type: "list", id}`, `{type: "setEnabled", id, extensionId, enabled}`,
`{type: "uninstall", id, extensionId}`. Messages to the app: `hello`, `pong`, `list`, `result`,
`event` (`installed`, `uninstalled`, `enabled`, `disabled`).
