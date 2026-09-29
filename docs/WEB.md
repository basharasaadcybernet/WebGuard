# Local web interface

WebGuard ships its compiled React interface inside the Python package. One command starts both the
page and its stateless scan API on the same loopback origin:

```text
webguard web
```

No separate frontend server, API command, proxy configuration, hostname entry, environment file,
or Node.js installation is needed for normal use.

## Defaults

- Host: `127.0.0.1`.
- Port: an available local port selected at startup.
- Browser: opened automatically after startup.
- Lifetime: the server runs until `Ctrl+C` is pressed.
- Storage: targets and results remain in current process/page memory; there is no scan-history
  database.

The exact URL is printed before the server starts accepting requests. If the browser cannot be
opened automatically, copy that URL into any local browser.

## Options

```text
webguard web --port 8080
webguard web --no-open
webguard web --host 127.0.0.1
webguard web --host localhost --port 8080 --no-open
webguard web --host ::1
```

`--port` accepts values from 1 through 65535. When an explicit port is unavailable, WebGuard exits
with a short error instead of silently using another port. Omitting it restores automatic
selection.

`--host` is intentionally limited to loopback addresses. Binding to public or LAN interfaces is
rejected so this convenience command cannot accidentally expose an unauthenticated scanner.

`--no-open` leaves browser launch under the user's control and is useful for remote terminals,
automated checks, or preferred-browser workflows.

## Security behavior

The page calls only the same-origin `/api/v1/scans` endpoint. The local server disables proxy
header trust, raw access logs, interactive API documentation, and server-version headers. It keeps
the existing Host validation, request-size limit, duplicate-field rejection, rate limiting,
concurrency cap, scan timeout, response redaction, SSRF protection, and cancellation behavior.

API responses are non-cacheable. HTML is revalidated, fingerprinted assets may be cached, and the
server adds a restrictive Content Security Policy and other browser security headers.

## Troubleshooting

- If `webguard` is not recognized, activate the environment that contains it or call its executable
  directly.
- If the browser remains blank, confirm the terminal is still running and reopen the printed URL.
- If a fixed port is unavailable, omit `--port` or choose another value.
- If local firewall software asks about Python, access is needed only on the selected loopback
  address; public network exposure is not required.
- If the bundled page is reported missing, reinstall from an official source archive or Wheel; an
  incomplete development package was installed.

This local command is not a public hosting or multi-user deployment mechanism.
