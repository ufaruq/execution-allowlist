# execution-allowlist

A small, backend-neutral execution allowlist service with a Santa rule-download
endpoint. Rules are stored in a local JSON file, so the server can be run
without an external database or dependencies.

## Run

```sh
go run .
```

The server listens on `:8080` and stores rules in `data/rules.json` by default.
Set `ADDR` to change the listen address and `ALLOWLIST_DB` to choose another
rule file.

## Rule API

Rules use an identifier, a rule type, and an action:

```sh
curl -X POST http://localhost:8080/v1/rules \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"<binary-sha256>","type":"BINARY","action":"ALLOW"}'
curl http://localhost:8080/v1/rules
curl -X DELETE 'http://localhost:8080/v1/rules/<binary-sha256>?type=BINARY'
```

Supported rule types are `BINARY`, `CERTIFICATE`, `TEAMID`, `SIGNINGID`,
`CDHASH`, and `PATH`. Actions are `ALLOW` and `BLOCK`. The API is independent
of any particular endpoint agent; other operating-system integrations can
consume its normalized rule list.

## Santa

Santa's v1 JSON rule-download endpoint is available at
`POST /santa/v1/rule_download`. Send a JSON object containing `machine_id`; the
response contains the managed rules in Santa's `identifier`, `rule_type`, and
`policy` format. Actions map to `ALLOWLIST` and `BLOCKLIST`; `PATH` rules are
reserved for other integrations and are not included in Santa downloads.

This initial server implements rule management and rule download only; it does
not yet implement Santa event uploads, preflight, postflight, or newer
protobuf-based sync endpoints. Deploy behind HTTPS and restrict access to the
management API.

## Test

```sh
go test ./...
```
