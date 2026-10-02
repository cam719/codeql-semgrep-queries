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
tests/     Vulnerable and fixed code used to validate the CVE queries
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
| `unparenthesized-subtract-add.ql` | `a - b + c` with a non-constant `c`, where `a - (b + c)` was likely meant. Generalizes **CVE-2026-39043** | warning (8.1) |
| `unchecked-mul-in-bounds-check.ql` | Bounds check whose limit contains an unchecked 32-bit multiply of a non-constant value. Generalizes **CVE-2026-39044** | error (7.5) |
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
| `size-arithmetic.yaml` | Precedence and overflow bugs in size calculations (CVE-2026-39043, CVE-2026-39044) | `unparenthesized-subtract-add`, `unchecked-mul-in-bounds-check` |
| `memory-corruption.yaml` | Integer-overflow and allocation-size bugs in C/C++ | `int-multiply-assigned-to-wide-type`, `frames-int-multiply`, `malloc-unchecked-arithmetic`, `memcpy-length-from-subtraction` |
| `regex-fallback.yaml` | Build-free (`generic`) versions of the overflow/alloc patterns | `unsigned-multiply-assign`, `strlen-to-copy-function`, `alloc-multiply-parsed-fields`, `int-size-param-with-sizeof`, `assert-only-guard` |
| `freebsd-exec-audit.yaml` | Copy-size sign errors and off-by-one in exec paths | `copy-size-sign-error`, `memmove-mixed-arithmetic-size`, `bcopy-into-begin-argv`, `copystr-stringspace-bounds`, `exec-offset-arithmetic`, `strlen-plus-one-mismatch` |
| `libde265-audit.yaml` | Bitstream-driven overflow and OOB in video decoders | `uvlc-no-range-check`, `array-index-from-bitstream`, `width-height-multiply`, `ctb-addr-no-bounds` |
| `hashcat-audit.yaml` | Hex-decode and bounds-bypass in C/C++ | `hex-decode-unbounded`, `hex-decode-unbounded-alt`, `hex-decode-no-output-bounds`, `conditional-bypass-bounds-check`, `strtoul-to-array-index`, `stack-buffer-2x-expansion` |
| `hashcat-regex.yaml` | Build-free versions of the hashcat patterns | `hex-to-binary-unbounded`, `data-type-conditional-bypass`, `memcpy-from-token-unbounded`, `arr-2x-expansion-write` |
| `logic-rce.yaml` | Code-exec and deserialization sinks in Python/Java | `python-dynamic-execution-sink`, `fastapi-code-exec-route-missing-active-user`, `python-import-from-user-controlled-ast`, `tomcat-partial-put-path-derived-temp-file`, `tomcat-file-store-session-deserialization`, `java-session-attribute-readobject` |

## Case studies: GStreamer CVE-2026-39043 and CVE-2026-39044

I found both bugs in GStreamer's `gst-plugins-good` and wrote the upstream
fixes. Each one has a query here that generalizes the bug class, and a
regression test in `tests/` that pairs the vulnerable code with the shipped fix.
I later used both patterns to seed an audit of GStreamer core.

### CVE-2026-39043: Matroska bz2 heap buffer overflow

The Matroska demuxer tracks bzip2 output as two 32-bit halves. It computed the
remaining output space as:

```c
bzstream.avail_out = new_size - ((guint64) bzstream.total_out_hi32 << 32) +
    bzstream.total_out_lo32;
```

C parses this as `(new_size - hi) + lo`, so `avail_out` comes out too large by
`2 * total_out_lo32` and bzip2 writes past the end of the heap buffer. The fix
adds the missing parentheses: `new_size - ((hi << 32) + lo)`.

- **Advisory:** [GStreamer-SA-2026-0022](https://gstreamer.freedesktop.org/security/sa-2026-0022.html), fixed in gst-plugins-good 1.28.2
- **Fix:** [merge request 11248](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/11248), commit [`8647118624`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/8647118624fd14983507edbb509d0e534a0353a9), 1.28 backport [`6db6dd058e`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/6db6dd058ebc3607452311b7dc47b0359b40b293)
- **Queries:** `codeql/unparenthesized-subtract-add.ql` and the `unparenthesized-subtract-add` rule in `semgrep/size-arithmetic.yaml`

`sign-error-copy-size.ql` covers a related shape: wrong-sign arithmetic inside a
`memcpy`/`memmove` size argument, the CVE-2026-7270 FreeBSD pattern. It does not
fire on 39043, which is a plain assignment.

### CVE-2026-39044: WAV cue chunk integer overflow

The WAV parser validated the cue chunk with:

```c
if (size < 4 + ncues * 24)
```

`ncues` comes from the file. A large count makes `ncues * 24` wrap in 32 bits,
the check passes, and the parse loop reads past the end of the chunk. The fix
computes the product with `g_uint_checked_mul` and rejects the chunk on
overflow.

- **Advisory:** [GStreamer-SA-2026-0021](https://gstreamer.freedesktop.org/security/sa-2026-0021.html), fixed in gst-plugins-good 1.28.2
- **Fix:** [merge request 11247](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/merge_requests/11247), commit [`83becc83ea`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/83becc83eac477ecb97171f8278b0047dd7b6d5f), 1.28 backport [`35a905a92f`](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/commit/35a905a92f4cfc85941c6c820009ac9219f755b2)
- **Queries:** `codeql/unchecked-mul-in-bounds-check.ql` and the `unchecked-mul-in-bounds-check` rule in `semgrep/size-arithmetic.yaml`

### Validation

| Check | 39043 rule | 39044 rule |
| --- | --- | --- |
| CodeQL on the reduced test case, vulnerable code | flagged | flagged |
| CodeQL on the reduced test case, shipped fix and benign idioms | clean | clean |
| Semgrep on the real upstream source before the fix | flagged, both lines\* | flagged |
| Semgrep on the real upstream source after the fix | clean | clean |

\* The bz2 code sits in an `#ifdef HAVE_BZ2` block that splits an `else if`
chain, which Semgrep's C parser skips. With the directive lines stripped, the
rule flags both the `avail_out` assignment and the matching `g_assert`. CodeQL
analyzes preprocessed code and is not affected by this, but it was validated on
the reduced test cases only.

Reproduce the CodeQL check:

```bash
codeql pack install codeql
codeql database create tests/_db --language=cpp --source-root=tests --command=./build.sh
codeql database analyze tests/_db codeql/unparenthesized-subtract-add.ql \
  codeql/unchecked-mul-in-bounds-check.ql --format=csv --output=results.csv
```

Each query should report one result, on the statement marked `expect: flagged`.

## Status and caveats

These rules favor recall over precision and produce false positives by design;
every hit needs manual confirmation. Semgrep ignores parentheses, so the
`unparenthesized-subtract-add` Semgrep rule also matches an intentional
`(a - b) + c`; the CodeQL query of the same name does not. The rules are
provided as-is for research and defensive use.
