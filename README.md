# CipherGate

Domain-fronted HTTP relay tunnel using Google Apps Script.

## Quick Start

```bash
# Edit config/config.json with your Google Script ID and auth key
go run .
```

Set `http_proxy=http://127.0.0.1:8080` or use SOCKS5 at `127.0.0.1:1080`.

## Build

```bash
go build -o CipherGate .
```

## Deploy Apps Script

1. Create a new Google Apps Script project
2. Copy `apps_script/Code.gs` into it
3. Deploy as "Execute as me" with "Anyone" access
4. Copy the Script ID into `config.json`

## Structure

```
src/
  core/       Config, constants, utilities
  relay/      Google Apps Script relay engine
  proxy/      HTTP/SOCKS5 proxy server
  admin/      Web admin panel
  tunnel/     TCP tunnel
  transport/  TLS transport helpers
apps_script/  Google Apps Script deployment
config/       Runtime configuration
scripts/      Build scripts
```
