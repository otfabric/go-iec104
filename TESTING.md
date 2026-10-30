# Testing

How to run each test tier of go-iec104. What is implemented and at which evidence level: [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md). Interop results: [INTEROPERABILITY.md](INTEROPERABILITY.md#verification-status).

## Tiers

| Tier | Command | Prerequisites | Runs in CI |
|---|---|---|---|
| Unit and package tests, race detector | `make test` | none | CI workflow, Go 1.23 to 1.26 |
| End-to-end, on loopback TCP | `make e2e` (also part of `make test`) | none | CI workflow |
| Coverage gate | `make coverage-check` | none | CI workflow |
| Fuzz | `make fuzz` | none | CI workflow, 10s per discovered target |
| Benchmarks | `make bench` | none | no |
| Examples | `make examples` | none | CI workflow, job Examples |
| Cross-compilation | `make cross` | none | no |
| Interop with reference images | `make interop` | Docker | Interop workflow, every push and pull request |
| IEC 62351-5 against cB-Sigma/iec60870, in process | `make test-cbsigma` | Go 1.26 (`interop/cbsigma` is a module of its own) | Interop workflow, job cB-Sigma |

`make check` is the local gate: format, lint, vet, vulnerability scan, tests, coverage and examples. It needs `staticcheck`, `golangci-lint` and `govulncheck` on the `PATH`. It does not fail on the coverage floor; `make coverage-check` does.

No workflow runs on a schedule, so there is no long fuzz or soak run in CI.

## What each suite does

- **Package tests**: `apci`, `asdu`, `sec` and `internal/link` test the codecs and the protocol machine; `internal/link` also runs against scripted peers, for what a correct peer never sends.
- **`e2e`**: go-iec104 client against go-iec104 server.
  - `e2e_test.go` runs the station scenarios on the baseline fixture (`internal/station/baseline.json`) over plain TCP, TLS, `k = w = 1`, IEC 62351-5 with HMAC, and IEC 62351-5 with AES-256-GCM over TLS.
  - `matrix_test.go` sends every type identification through both codecs and both protocol machines, repeats this with other field sizes, and wraps the sequence numbers.
  - `features_test.go` covers states, logs, metrics, retries, admission, the event queue and failing requests.
  - `statemachine_test.go` covers start, stop, close and switchover races.
  - `chaos_test.go` runs seeded random operations while connections are cut.
- **`interop`** (build tag `interop`): go-iec104 as client and as server against the images of [otfabric/iec104-interop](https://github.com/otfabric/iec104-interop). The images are pinned by digest in `interop/harness.go`, the Makefile and `.github/workflows/interop.yml`; keep the three in step.
- **`interop/cbsigma`**: `sec` against cB-Sigma/iec60870 in memory.

## Options

| Variable or flag | Effect |
|---|---|
| `E2E_CHAOS_SECONDS` | Duration of each chaos seed, default 2 |
| `E2E_CHAOS_SEEDS` | Number of chaos seeds, default 3 |
| `-short` | Reduces chaos to one seed of one second, skips the 40,000-frame sequence wrap, and reduces the rounds of the crosstalk test in `client` |
| `FUZZTIME` | Duration of each fuzz target in `make fuzz`, default 30s |
| `IEC104_INTEROP_ADAPTERS` | Comma-separated subset of `lib60870`, `openmuc`, `wendy512`, `cbsigma` |
| `IEC104_INTEROP_<ADAPTER>_IMAGE` | Image of that reference, to test another build |

## Skips

There is no `*_REQUIRE_*` switch. The tests that can skip are:

- Interop tests skip what a reference image does not declare in `print-capabilities`, and the read cases of j60870 listed as a known bug. Those cases fail when the bug no longer reproduces ([INTEROPERABILITY.md](INTEROPERABILITY.md#verification-status)).
- Three tests in `client` skip when their port cannot be bound again.
- `make interop` without Docker fails; it does not skip.

## Coverage policy

The gate is 90% of statements in total, the same value as `coverage-min` in `.github/workflows/ci.yml` and `COVER_MIN` in the Makefile. `TEST_PKGS` in the Makefile and `test-exclude-regex` in the workflow define the same packages. Excluded:

| Package | Why |
|---|---|
| `examples/...` | Programs, run by `make examples` |
| `internal/testutil` | Test helpers, no production code |
| `internal/station` | Test station for the suites, no production code |

`interop` is outside the default build by its build tag, and `interop/cbsigma` is another module.

## Fuzz regressions

The targets are `FuzzParse` in `apci`, `FuzzDecode` in `asdu` and `FuzzDecode` in `sec`. A new decoder gets a target; add it to the `fuzz` recipe in the Makefile too, which lists them by name.

When a target fails, `go test` writes the input to `testdata/fuzz/<Target>/` in the package; CI uploads the same directory as the artifact `fuzz-failures`. To keep it as a regression test:

1. Copy the file into `testdata/fuzz/<Target>/` if it came from CI.
2. Reproduce it: `go test -run '<Target>/<file>' ./<package>`.
3. Fix the decoder and commit the file with the fix. Plain `go test` then runs it on every push.
