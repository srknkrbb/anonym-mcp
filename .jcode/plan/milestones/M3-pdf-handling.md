---
id: M3
title: PDF handling
status: done
verify: cargo test --bin anonym-mcp pdf
evidence:
  at: 2026-09-05T13:59:16.944126Z
  command: cargo test --bin anonym-mcp pdf
  exit_code: 0
  summary: 'test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 0.04s'
  log_path: evidence/M3-20260905T135916Z.log
tasks:
- id: T5
  title: PDF text layer masked; scanned pages reported rather than silently passed through
  status: done
  verify: cargo test --bin anonym-mcp pdf
  evidence:
    at: 2026-09-05T13:57:22.776973Z
    command: cargo test --bin anonym-mcp pdf
    exit_code: 0
    summary: 'test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 0.03s'
    log_path: evidence/T5-20260905T135722Z.log
- id: T6
  title: a scanned PDF is never reported as clean, and page-cap truncation is disclosed
  status: done
  verify: cargo test --test pixel_formats
  evidence:
    at: 2026-09-05T13:59:10.875311Z
    command: cargo test --test pixel_formats
    exit_code: 0
    summary: 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.61s'
    log_path: evidence/T6-20260905T135910Z.log
---
