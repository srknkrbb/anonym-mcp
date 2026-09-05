# anonym-mcp

Opening a customer file with an AI agent sends that file's national IDs, IBANs
and passwords to the model. `anonym-mcp` reads the file instead: sensitive
values are replaced with stable placeholders (`TCKN_1`, `IBAN_2`, `SIFRE_3`)
before the agent sees anything, and a placeholder the agent writes back becomes
the real value again on disk.

The mapping table never leaves the machine.

It speaks [MCP](https://modelcontextprotocol.io) over stdio, so it works with
any MCP-capable agent: Claude Code, Cursor, jcode, or your own.

Handles plain text, Office documents, PDFs and images, including scans and
screenshots that carry their secrets as pixels.

```
agent:  ad,tckn,eposta
        Ali,TCKN_1,EPOSTA_1

disk:   ad,tckn,eposta
        Ali,10000000146,a.b@example.com
```

## Why a separate process

Patching an agent's own file-reading tool does not work: the `bash`, `grep` and
`multiedit` sitting next to it read the same file raw, and one `cat customer.csv`
walks around the whole thing.

As its own process the mapping table and the real bytes exist only here, and
`ANONYM_ROOTS` bounds what it will touch at all.

## Install

```bash
git clone https://github.com/srknkrbb/anonym-mcp
cd anonym-mcp
./scripts/install_anonym_mcp.sh
```

Installs to `~/.local/bin/anonym-mcp`, re-signs on macOS, and verifies that what
it installed actually runs.

## Configure

Point your agent at it. For jcode, in `.jcode/mcp.json`; for Claude Code, in
`.mcp.json`:

```json
{
  "mcpServers": {
    "anonym": {
      "command": "anonym-mcp",
      "env": {
        "ANONYM_ROOTS": "/path/to/sensitive/data",
        "ANONYM_WORDS": "Acme Holding,Client Name"
      }
    }
  }
}
```

Then just ask an ordinary question about a sensitive file. The agent reaches for
`read_anonymized` on its own; edits go back through `edit_restored`, so the round
trip does not corrupt the real data.

## Tools

| Tool | Use |
|---|---|
| `read_anonymized` | Read a file with sensitive values masked |
| `write_restored` | Write a file, turning placeholders back into real values |
| `edit_restored` | Replace a string; placeholders resolve on both the match and write side |
| `anonymize_text` | Mask a snippet before quoting it into a report or commit message |
| `restore_text` | Reveal real values into the conversation. **Hidden by default**, see below |

## Detectors

Passwords (`password:`, `şifre=`, and context-free credential-shaped tokens),
Turkish national IDs (checksum-validated), IBANs, credit cards (Luhn-validated),
e-mail addresses, phone numbers, person names, and your own word list.

A number that fails its checksum is left alone: masking it would teach you to
distrust the output.

| Variable | Default | Meaning |
|---|---|---|
| `ANONYM_MAPPINGS` | `~/.anonym-mcp/mappings.json` | Mapping table location (written `0600`) |
| `ANONYM_ROOTS` | *(unbounded)* | Colon-separated directories the server may touch |
| `ANONYM_WORDS` | *(empty)* | Comma-separated extra words to mask |
| `ANONYM_DETECTORS` | *(engine default)* | Comma-separated detector names |
| `ANONYM_ALLOW_REVEAL` | `0` | Also offer `restore_text` |

Detector names: `password`, `national_id`, `iban`, `credit_card`, `email`,
`phone`, `person_name`, `custom_word`. An unrecognised name falls back to the
default set rather than disabling everything, so a typo cannot silently unmask a
session.

`person_name` is off by default. Name detection is loose by nature ("Personel
Bilgi Formu" matches the same shape as a person), and there is no preview pane in
an agent session to confirm matches in.

## What it protects, and what it does not

Measured, not assumed.

**It does:** real values do not reach the model through its tools; a masked file
edited and written back is not corrupted; and the server will not reveal a value
into the conversation by default.

**It does not:** the agent's own `bash` can still read the file. Asked to run
`cat secret.csv` and paste the output, a live session did exactly that and the
real national ID reached the model. No server can prevent this, because the agent
has its own access to the file.

Two escape routes *are* closed, both found by testing rather than reasoning:

- `restore_text` is not advertised, and refuses if called anyway. A live session
  asked "show me the tckn" had otherwise read the file masked and then dutifully
  un-masked it.
- Restoring to a device path (`write_restored` with `/dev/stdout`) is refused. It
  used to put the real value straight into the JSON-RPC stream, which is the
  model's input.

### Making it an actual boundary

Run the server as its own user, so the agent's user cannot read the files at all:

```bash
sudo dscl . -create /Users/_anonym UserShell /usr/bin/false   # macOS
sudo chown -R _anonym /path/to/sensitive/data
sudo chmod -R 700 /path/to/sensitive/data
```

Set `"command": "sudo -u _anonym anonym-mcp"` in the MCP config, then measure it
rather than trusting it:

```bash
./scripts/check_anonym_isolation.sh _anonym /path/to/sensitive/data/file.csv
```

Exit `0` means isolation holds, `1` a check failed, `2` a check could not run
(a sudo password prompt, for instance) — which is not the same as passing.

`chmod 000` under a *single* account does not work: the server cannot read the
file either. Verified.

### Global versus project config

A project config overrides a same-named global entry. If the global entry has no
`ANONYM_ROOTS`, every directory without its own config gets an unbounded server.

## Formats

| Kind | How | Reversible |
|---|---|---|
| Text: `txt`, `csv`, `md`, `json`, `xml`, `yaml`, `log`, `env`, `sql`, ... | Direct | Yes |
| Office: `docx`, `xlsx`, `pptx` (+ `docm`, `xlsm`, `dotx`, ...) | XML text nodes only, so formatting, tables and formulas survive | Yes, via `edit_restored` |
| `pdf` with a text layer | Text extraction | No |
| Scanned `pdf` | Pages rendered and read with OCR | No |
| Images: `png`, `jpg`, `tiff`, `bmp`, `heic`, ... | Vision OCR | No |

Office documents are edited through their structure: `write_restored` is
refused for them, because writing a string over a `.docx` replaces a document
with a text file. `edit_restored` rewrites the document in place. Note that Word
splits text across runs, so a phrase spanning a formatting change will not match
as one string; the error says so rather than reporting a silent no-op.

Images and PDFs are **one-way**. Their text is pixels and layout, so there is
nothing to write a real value back into; both refuse writes with that reason.
`read_anonymized` still tells you what they contain.

Every OCR result says it came from OCR, because recognition is fallible and a
value it misread is a value it did not mask. A PDF with no readable text says
so loudly rather than reading as a clean document: an empty result is exactly
what a scan full of credentials looks like. Documents beyond the 50-page render
cap disclose that only part was examined.

OCR needs Apple's Vision framework, so images and scanned PDFs are macOS only.
Everything else works everywhere.

## Limits

Files above 256 KB are not embedded. The detectors are tuned for Turkish data (TCKN checksums, TR IBANs, TR phone
formats) plus formats that are the same everywhere (e-mail, credit cards,
password patterns). OCR is asked for Turkish first, then English.

## Development

```bash
cargo test
```

98 tests: detectors, the mapping store, the MCP protocol layer, OOXML round
trips against real Word and Excel output, PDF and OCR classification, the CLI,
the install upgrade path, and the isolation checker.

## License

MIT
