# Evidence behind the browser walkthrough

The browser presentation replays prepared outputs from the authoritative native
Rust checker and the existing cooperative two-worker experiment. It is not live
verification, exhaustive observation or a containment boundary.

The reproducible source experiment is [the two-worker example](../../examples/counterexample/run.py);
its [case study](../../docs/COUNTEREXAMPLE.md) explains the outside harness.
[Benchmark methods](../../benchmarks/README.md) and [frozen aggregate results](../../benchmarks/reference/results.json)
remain separate, unchanged research evidence.

Original REALM generated evidence, MIT OR Apache-2.0. No external dataset or
private research trace is used.

The shipped JSON files are exact native reports; the `.realm` files are actual
inputs. `paired-result.json` records both real task tests; `outside-observation.json`
is a separate harness sidecar. `manifest.json` pins their bytes, checker and source.
[Reproduce and deploy](../../docs/DEPLOY_WALKTHROUGH.md).
