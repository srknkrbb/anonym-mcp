---
id: M1
title: OOXML handler
status: done
verify: cargo test --bin anonym-mcp ooxml && cargo test --test ooxml_roundtrip
evidence:
  at: 2026-09-05T13:50:29.281724Z
  command: cargo test --bin anonym-mcp ooxml && cargo test --test ooxml_roundtrip
  exit_code: 0
  summary: 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 51 filtered out; finished in 0.00s'
  log_path: evidence/M1-20260905T135029Z.log
tasks:
- id: T1
  title: unzip, transform XML text nodes only, rezip; formatting and formulas survive
  status: done
  verify: cargo test --bin anonym-mcp ooxml
  evidence:
    at: 2026-09-05T13:50:09.581967Z
    command: cargo test --bin anonym-mcp ooxml
    exit_code: 0
    summary: 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 51 filtered out; finished in 0.00s'
    log_path: evidence/T1-20260905T135009Z.log
- id: T2
  title: 'docx/xlsx/pptx round trip: read masked, write restored, file still opens'
  status: done
  verify: cargo test --test ooxml_roundtrip
  evidence:
    at: 2026-09-05T13:50:12.963767Z
    command: cargo test --test ooxml_roundtrip
    exit_code: 0
    summary: 'test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s'
    log_path: evidence/T2-20260905T135012Z.log
---
