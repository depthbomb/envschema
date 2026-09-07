# Performance

Performance measurements use representative schemas rather than isolated parser microbenchmarks. The original reference results below were collected with Go 1.26 on Windows/amd64 and an Intel i7-9700K. Timings are medians from repeated runs; scheduler, filesystem-cache, and antivirus activity can affect results.

## September 2026 runtime pass

Measured on Go 1.27.1, Windows/amd64, Intel i7-9700K. Each result is the median of five samples.
The existing-workload baseline is revision 2e2bd07; optimized code is 4442d14.

| Workload | Before | After | Time reduction |
| --- | ---: | ---: | ---: |
| Mixed 100-variable load | 29.80 us | 25.84 us | 13.3% |
| 100 variables, 99 presence constraints | 30.02 us | 20.32 us | 32.3% |
| 1,000 variables, 999 presence constraints | 367.71 us | 249.31 us | 32.2% |
| Plain 4 KiB string | 10.23 us | 0.33 us | 96.8% |
| Subset of two 100-item string lists | 168.64 us | 9.03 us | 94.6% |
| Subset of two 1,000-item string lists | 15.36 ms | 88.28 us | 99.4% |

The 1,000-variable constraint workload fell from 168,656 to 98,048 bytes per load, and from 2,011 to 1,006 allocations.
Completed loads now supply presence directly to constraints, avoiding repeated source reads and unnecessary variable indexes.
Loading traverses variable definitions by pointer. String parsing skips rune scans unless a character policy requires one and
reuses unchanged string values. Primitive collection relationships use direct comparisons for small inputs and membership
indexes for larger inputs; structured values retain deep comparison semantics.

Existing workloads use 400ms samples. The new text and relationship baselines used 300ms samples immediately before their
targeted optimizations, after pointer traversal had been introduced; final samples use 400ms. Benchmarks ran separately from
race tests. Generated-example timing and pattern initialization changed by less than 10%; no meaningful timing improvement
is claimed for them.

Reproduce the added workloads with:

```shell
go test -run '^$' -bench '^BenchmarkConstraints' -benchmem -benchtime=400ms -count=5 .
go test -run '^$' -bench '^BenchmarkTextLoadFrom' -benchmem -benchtime=400ms -count=5 .
go test -run '^$' -bench '^BenchmarkCollectionRelationships' -benchmem -benchtime=400ms -count=5 .
```

## Original runtime results

| Benchmark                                     | Time     | Memory   | Allocations |
|-----------------------------------------------|---------:|---------:|------------:|
| Mixed 10-variable `LoadFrom`                  |  3.08 µs |  1,064 B |          24 |
| Mixed 100-variable `LoadFrom`                 |  29.8 µs |  8,952 B |         204 |
| Generated seven-variable `LoadFrom`           |  2.59 µs |    448 B |          30 |
| JSON schema initialization, 10 variables      |   122 µs | 92,338 B |         501 |
| Native schema initialization, 10 variables    |  14.6 µs | 27,251 B |          46 |
| Advanced eight-variable runtime               |  5.68 µs |  1,520 B |          43 |
| Policy-rich 15-variable runtime               |  13.2 µs |  3,723 B |          75 |
| Binary-adjacent `.env` and `.env.local` load  |  86.2 µs |  3,179 B |          50 |

The advanced workload exercises a cached regular-expression constraint, restricted URL, IPv4 CIDR, endpoint, unsigned numeric constraints, typed duration bounds, typed map, unique hostname list, and a cross-variable constraint.

The policy-rich workload covers string content, structured JSON, ordered collections, URI, IP/CIDR/endpoint classification, UUID, bounded SemVer, decoded Base64 length, timestamp precision, arbitrary-precision integer/decimal comparison, media type, MAC address, and a cross-variable value constraint.

The generated example has seven variables, including a custom `encoding.TextUnmarshaler` type.

Runtime characteristics relevant to interpreting the results include:

- schemas created by `Must`, `New`, or generated code carry validated state;
- generated loaders call typed `Read` operations directly;
- generated packages construct native Go schema expressions;
- compiled patterns and parsed semantic-version bounds are cached;
- primitive collection results are materialized directly as typed slices;
- duplicate JSON object keys are checked with an allocation-light scanner after decoding;
- constraint evaluation reuses parsed values;
- `.env` files are read concurrently and merged in deterministic precedence order;
- arbitrary-precision comparisons operate directly on `big.Int` and `big.Rat` values.

The `.env` benchmark uses `.env` and `.env.local` with seven representative application variables per file. Operating-system file calls dominate that workload.

## Generator results

| Benchmark                              | Time       | Memory   |
|----------------------------------------|-----------:|---------:|
| Generate source, 10 variables          |     334 µs | 71.8 KiB |
| Generate source, 250 variables         |    7.12 ms | 1.93 MiB |
| Discover and execute Go schema package |    1.40 s  |  244 MiB |

Full package loading is dominated by `go/packages` type checking and the temporary `go run`. Go's build cache substantially influences this benchmark.

## Reproduce

```shell
go test -run '^$' -bench 'BenchmarkLoadFrom(10|100)$' -benchmem -count=7 .
go test -run '^$' -bench '^BenchmarkAdvancedLoadFrom$' -benchmem -count=7 .
go test -run '^$' -bench '^BenchmarkPolicyRichLoadFrom$' -benchmem -count=7 .
go test -run '^$' -bench '^BenchmarkLookupEnvFiles$' -benchmem -count=7 .
go test -run '^$' -bench '^BenchmarkGeneratedLoadFrom$' -benchmem -count=7 ./example/config
go test -run '^$' -bench '^BenchmarkSchemaInitialization' -benchmem -count=5 .
go test -run '^$' -bench '^BenchmarkSource' -benchmem -count=7 ./generate
go test -run '^$' -bench '^BenchmarkLoadPackage$' -benchmem -benchtime=2x -count=5 ./generate
```

Run benchmarks on an otherwise idle machine and compare samples collected with equivalent warm or cold Go build-cache state.
