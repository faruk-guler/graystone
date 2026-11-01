<p align="center">
  <img src="icon/gravel-logo.png" alt="Gravel logo" width="300" height="300" />
</p>

A PuTTY + WinSCP hybrid for Linux servers: the terminal, the file browser, transfers and tunnels in one small Windows app. Built with Go and [Wails](https://wails.io).

**Version:** 4.9.0

## Features

- **SSH terminal** — tabbed sessions, login asked in the terminal itself (`login as:` / password / OTP), select to copy and right-click to paste. A dead link is noticed, and can reconnect on its own.
- **SFTP browser** — docked beside the terminal: upload, download, rename, delete, chmod/chown, a text editor, and a pane that follows `cd`.
- **Drag and drop** — drop files from Explorer onto the pane to upload them; drop them onto the terminal to type their paths at the prompt.
- **Transfers** — queue with progress, speed and ETA; cancel, pause and resume from the exact byte, retry after a brief link failure, and a size check on the far side before a file is called done.
- **Tunnels** — local (`-L`), reverse (`-R`) and dynamic SOCKS5 (`-D`) forwards. One table, a blank row to add one, saved per server and started again on the next connect.
- **Host key trust** — checked on first use and stored per key type, with an explicit warning when a key really changes.
- **Saved sessions** — name, host, port, key file. Ordered by dragging, imported in bulk.
- **Settings** — theme, terminal font, conflict policy, outbound proxy, reconnect. *Save settings* keeps a copy in the config folder.
- **Logs** — every action in the Logs tab, plus one file per launch.

## Privacy

Passwords and key passphrases are never stored: they are typed when connecting and kept in memory for that run. Nothing leaves the machine — no telemetry, no cloud sync, no settings file to export.

## Build

```sh
wails build   # -> build/bin/Gravel.exe
wails dev     # live reload
```

Needs Go 1.26+, Node.js, the Wails CLI v2, and Windows with WebView2. `wails build` installs the frontend packages and produces `frontend/dist` by itself; run it once before plain `go build ./...` or `go test ./...`, because `main.go` embeds that folder. `go test ./internal/...` works without it.

## Files

Everything lives in `%APPDATA%\Gravel`. A folder left over from the earlier names (Genpilot, then Bedrock) is moved there on first run.

| File | Contents |
|------|----------|
| `sessions.json` | saved servers |
| `tunnels.json` | saved port forwards |
| `settings.json` | the settings pinned by *Save settings* |
| `known_hosts.json` | trusted host keys |
| `gravel-<timestamp>.log` | one log per launch |

A file that cannot be parsed is renamed `<name>.bad-<timestamp>` and reported instead of being treated as empty, so a save can never overwrite what it could not read. Only one Gravel window runs at a time.
