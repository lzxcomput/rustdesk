# RustDesk audit consumer

This Go program tails RustDesk `sessions-*.jsonl` files, validates the SHA-256
chain, checkpoints each file offset, and suppresses duplicate `event_id` values
across restarts.

```powershell
go run . -dir "C:\ProgramData\RustDesk\audit"
```

```bash
go run . -dir /var/log/rustdesk/audit
```

Use `-once` for batch ingestion. Each validated record is emitted as one JSON
line on stdout; replace `JSONLineHandler` with an application-specific
`Handler` to send records to a database or remote API. The consumer never
deletes RustDesk audit files.
