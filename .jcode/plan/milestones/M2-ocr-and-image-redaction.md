---
id: M2
title: OCR and image redaction
status: done
verify: cargo test --bin anonym-mcp ocr
evidence:
  at: 2026-09-05T13:59:13.860777Z
  command: cargo test --bin anonym-mcp ocr
  exit_code: 0
  summary: 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 68 filtered out; finished in 0.24s'
  log_path: evidence/M2-20260905T135913Z.log
tasks:
- id: T3
  title: Vision OCR through objc2, no Swift dependency, gated to macOS
  status: done
  verify: cargo test --bin anonym-mcp ocr
  evidence:
    at: 2026-09-05T13:57:19.243340Z
    command: cargo test --bin anonym-mcp ocr
    exit_code: 0
    summary: 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 68 filtered out; finished in 0.24s'
    log_path: evidence/T3-20260905T135719Z.log
- id: T4
  title: writes to pixel formats are refused with a reason instead of a UTF-8 error
  status: done
  verify: cargo test --test pixel_formats
  evidence:
    at: 2026-09-05T13:59:07.110488Z
    command: cargo test --test pixel_formats
    exit_code: 0
    summary: 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.63s'
    log_path: evidence/T4-20260905T135907Z.log
---
