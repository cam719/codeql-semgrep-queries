# codeql-semgrep-queries

Static-analysis queries and rules for hunting memory-safety and logic
vulnerabilities in C/C++, Python, and Java codebases. These are
pattern-detection rules written during source-code audits; they flag
candidate sites for manual review, not confirmed bugs.

Two engines are covered:

- **CodeQL** — semantic queries over a compiled database (`codeql/`).
- **Semgrep** — syntactic/structural rules, many in `generic` mode so they
  run without a build (`semgrep/`).

## Layout

```
codeql/    CodeQL queries + pack manifest (custom/vuln-hunting)
semgrep/   Semgrep rule files, grouped by audit theme
```

## CodeQL queries

The `codeql/` directory is a CodeQL pack (`qlpack.yml`, depends on
`codeql/cpp-all`). Build a database and run the pack:

```bash
codeql database create db --language=cpp --command="make"
codeql database analyze db codeql/ --format=sarif-latest --output=results.sarif
```

| Query | Detects | Severity |
| --- | --- | --- |
| `missing-widening-cast.ql` | `int * int` multiplication assigned to a 64-bit (or `sf_count_t`) destination with no widening cast — overflow before assignment | error (8.0) |
| `sign-error-copy-size.ql` | `memcpy`/`memmove` size using addition where subtraction was intended (CVE-2026-7270 pattern) | error (9.0) |
| `mixed-arith-copy-size.ql` | Copy-size expression mixing `+` and `-` on variables, needing per-operator sign review | warning (7.0) |
| `unbounded-memcpy-from-token.ql` | `memcpy` length from a parsed field or pointer subtraction with no max check | error (8.5) |
| `unbounded-hex-decode.ql` | Hex decode using `strlen` length into a fixed buffer with no prior bounds check | error (9.0) |
| `assert-only-bounds.ql` | Array access guarded only by `assert`, which is removed in release builds | error (8.0) |

## Semgrep rules

Run all rule files against a tree:

```bash
semgrep --config semgrep/ path/to/source
```

| File | Theme | Rules |
| --- | --- | --- |
| `memory-corruption.yaml` | Integer-overflow and allocation-size bugs in C/C++ | `int-multiply-assigned-to-wide-type`, `frames-int-multiply`, `malloc-unchecked-arithmetic`, `memcpy-length-from-subtraction` |
| `regex-fallback.yaml` | Build-free (`generic`) versions of the overflow/alloc patterns | `unsigned-multiply-assign`, `strlen-to-copy-function`, `alloc-multiply-parsed-fields`, `int-size-param-with-sizeof`, `assert-only-guard` |
| `freebsd-exec-audit.yaml` | Copy-size sign errors and off-by-one in exec paths | `copy-size-sign-error`, `memmove-mixed-arithmetic-size`, `bcopy-into-begin-argv`, `copystr-stringspace-bounds`, `exec-offset-arithmetic`, `strlen-plus-one-mismatch` |
| `libde265-audit.yaml` | Bitstream-driven overflow and OOB in video decoders | `uvlc-no-range-check`, `array-index-from-bitstream`, `width-height-multiply`, `ctb-addr-no-bounds` |
| `hashcat-audit.yaml` | Hex-decode and bounds-bypass in C/C++ | `hex-decode-unbounded`, `hex-decode-unbounded-alt`, `hex-decode-no-output-bounds`, `conditional-bypass-bounds-check`, `strtoul-to-array-index`, `stack-buffer-2x-expansion` |
| `hashcat-regex.yaml` | Build-free versions of the hashcat patterns | `hex-to-binary-unbounded`, `data-type-conditional-bypass`, `memcpy-from-token-unbounded`, `arr-2x-expansion-write` |
| `logic-rce.yaml` | Code-exec and deserialization sinks in Python/Java | `python-dynamic-execution-sink`, `fastapi-code-exec-route-missing-active-user`, `python-import-from-user-controlled-ast`, `tomcat-partial-put-path-derived-temp-file`, `tomcat-file-store-session-deserialization`, `java-session-attribute-readobject` |

## Case study: GStreamer integer-overflow class

The `memory-corruption.yaml` integer-multiply rules and
`missing-widening-cast.ql` describe the same unchecked-multiplication class as
**CVE-2026-39044** (WAV cue parser, `ncues * 24`). Used as an audit seed, the
pattern surfaced a wider family of unchecked `offset + size` arithmetic across
the GStreamer buffer, memory, and allocator APIs.

## Status and caveats

These rules favor recall over precision and produce false positives by design;
every hit needs manual confirmation. They are provided as-is for research and
defensive use.
