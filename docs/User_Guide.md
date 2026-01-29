# User Guide

This is the user guide for practitioners. For general project information, see the README.md.

## Core Concepts

Yara-Gen generates YARA rules by identifying textual patterns that are common in adversarial samples and rare in benign samples.

You always work with two datasets:
- Adversarial data: Inputs you want to detect.
- Benign data: Control data used to suppress false positives.

The generator extracts candidate signatures from adversarial samples, scores them against the benign corpus, and emits only patterns that are both distinctive and stable.

### Data Model

Internally, Yara-Gen operates on structured Pydantic models that represent normalized text samples. Both prepare and generate accept multiple input formats through adapters.

JSONL is the default and recommended format for generation because it:
- Avoids repeated downloads or streaming of large datasets
- Reduces preprocessing overhead during iteration
- Makes datasets easy to inspect and debug

Other formats are supported, but may incur additional cost when reused across runs.

### Engine Model

Yara-Gen uses a modular engine architecture. Engines define how features are extracted from text and how candidate signatures are scored against benign data.

The default engine is ngram, which extracts character n-grams and ranks them based on adversarial prevalence and benign suppression. The surrounding workflow and configuration are engine-agnostic, allowing additional engines to be introduced without changing how the tool is used.

### Determinism and Reproducibility

Given the same inputs, configuration, and rule date, Yara-Gen produces identical rules. This supports auditing, versioning, and CI-driven rule generation.


## Recommended Workflow

For most use cases, a simple two-step pipeline works best.

First, normalize your datasets using `ygen prepare`. This converts raw inputs into a reusable representation and avoids repeated downloads or expensive parsing. Preparation is especially useful when working with large files, remote datasets, or when you plan to iterate on generation parameters.

Once the data is prepared, run `ygen generate` to extract signatures and emit YARA rules. Generation can consume prepared files or stream inputs directly, applies benign suppression, and writes a ready-to-use `.yar` file.

In practice, rule generation is iterative. You typically prepare data once, generate rules, adjust thresholds or engine parameters, and regenerate. Re-run prepare only when the underlying data changes.


## Data Preparation with ygen prepare

The prepare command normalizes raw input data into a reusable representation. While optional, it is recommended whenever the source data is large, remote, or expensive to parse. Preparation is a standalone preprocessing step and does not read generation_config.yaml.

During preparation, Yara-Gen loads data through an adapter, extracts the relevant text, and emits one normalized sample per line. The output is typically written as JSONL, which can be reused across multiple generation runs without re-downloading or re-parsing the original source.

In most cases, adapters are selected automatically. Non-local inputs default to the Hugging Face adapter, local `.csv` files use the generic CSV adapter, and other local files are treated as raw text. Auto-detection is sufficient for standard datasets and common formats.

When auto-detection is not appropriate, you can force an adapter explicitly. This is useful when file extensions are misleading or when a dataset requires a specific parsing strategy.

```bash
ygen prepare data.xyz --output clean.jsonl --adapter raw-text
```
The Hugging Face adapter supports streaming directly from the Hub. Adapter-specific parameters such as `split` and `config_name` can be passed using `--set`. Preparing a dataset once avoids repeated streaming during rule generation and significantly improves iteration speed.

```bash
ygen prepare "rubend18/ChatGPT-Jailbreak-Prompts" \
  --output jailbreaks.jsonl \
  --set adapter.split=train \
  --set adapter.config_name=default
```
All adapters support row-level filtering via the `--filter` flag. Filters use a simple column=value syntax and are applied before normalization. Filtering early reduces noise, speeds up downstream processing, and improves rule quality.

```bash
ygen prepare data.csv --output clean.jsonl --filter "label=jailbreak"
```

## Rule Generation with ygen generate

The generate command extracts signatures from adversarial data, suppresses them against a benign control set, and emits YARA rules. This is the primary command you will use once datasets are prepared.

Generation accepts the same input formats as prepare, but using prepared JSONL files is recommended when iterating. Streaming remote datasets during generation is supported, but may incur repeated download or parsing costs across runs.

A minimal invocation requires adversarial input and an output path. A benign dataset is strongly recommended for any real-world use, as it directly controls false positives.

```bash
ygen generate jailbreaks.jsonl --benign benign.jsonl --output rules.yar
```

During generation, the engine extracts candidate features from adversarial samples, scores them against the benign corpus, and retains only patterns that meet the configured thresholds. The resulting rules are written directly to a standard `.yar` file and can be loaded into any YARA-compatible engine.

### Benign Control Sets

The benign dataset defines what the generator should ignore. High-quality benign data is more important than sheer volume. A small but representative control set often outperforms a large, noisy one.

Benign datasets are typically prepared once and reused across multiple generation runs. This allows you to iterate on adversarial inputs and engine parameters without reprocessing the control data.

### CLI Overrides

Generation defaults are read from `generation_config.yaml`. Any CLI flags or `--set` overrides take precedence and apply only to the current run. This makes it easy to experiment without modifying committed configuration files.

### Iterative Tuning

Rule generation is inherently iterative. You generate an initial rule set, inspect the output, adjust sensitivity or engine parameters, and regenerate. Prepared datasets make this loop fast and predictable.


## Finding Hyperparameters with Optimize

Tuning generation parameters manually—specifically thresholds and penalties—can be inefficient. The `optimize` command automates this by performing a grid search over a defined search space.

It automatically splits your adversarial and benign data into "Train" (for rule generation) and "Dev" (for evaluation) sets. It then runs generation for every combination of parameters defined in your config, evaluates the resulting rules against the held-out Dev set, and reports the configuration that yields the best performance.

### The Optimization Configuration

Optimization is controlled by a YAML configuration file (default: `optimization_config.yaml`). This file defines three key areas: the search space, selection criteria, and data splitting.

#### Search Space

The `search_space` section defines the parameters to iterate over. For the default `ngram` engine, the key parameters are:

- **min_ngram / max_ngram**: Controls the size of the extracted patterns. Shorter n-grams increase recall but are noisier; longer n-grams are specific but brittle.
- **score_threshold**: The primary sensitivity knob. Lower values keep more candidate rules (higher coverage), while higher values filter out everything but the strongest signals.
- **benign_penalty_weight**: Controls how aggressively the engine suppresses patterns that appear in benign text. Higher values force the engine to reject anything remotely looking like safe text.
- **min_document_frequency**: The minimum percentage of adversarial samples a pattern must appear in. This filters out "one-off" anomalies to focus on systemic attack patterns.

```yaml
search_space:
  type: "ngram"
  
  # Iterates over these lists (Grid Search)
  min_ngram: [3, 4]
  max_ngram: [6]
  
  score_threshold: [0.05, 0.1, 0.2]
  benign_penalty_weight: [1.0, 2.0]
  min_document_frequency: [0.01] # 1% of documents
```

#### Selection Criteria

The `selection` section determines how the "best" run is automatically chosen from the results.

`target_metric`: The primary metric to maximize (e.g. recall, precision, f1_score).

Constraints: Hard limits for acceptance. For example, setting `max_false_positives: 0` ensures that the recommended configuration generates zero false positives on the evaluation se

```yaml
selection:
  target_metric: "recall"
  min_precision: 0.95
  max_false_positives: 0
```

### Running the Optimizer

The optimizer requires both adversarial and benign datasets. It is recommended to use prepared JSONL files for performance.

```bash
ygen optimize attacks.jsonl \
  --benign-dataset control.jsonl \
  --config optimization_config.yaml
```

The tool will cache the Train/Dev splits in a local `.optimize` folder to ensure that subsequent runs (with different grid parameters) remain comparable.

### Interpreting Results

The command outputs a summary of the best run found, including the specific metrics achieved on the held-out Dev set. Crucially, it prints a copy-pasteable CLI snippet for the generate command using the `--set` override syntax.

```text
BEST RUN: Iteration #5
   Score (recall): 0.8500
   Metrics: TP=85 FP=0 Prec=1.000 Rec=0.850
   Parameters: {'min_ngram': 3, 'score_threshold': 0.1, ...}
------------------------------------------------------------
To generate rules with this configuration:
ygen generate ... --set engine.min_ngram=3 --set engine.score_threshold=0.1 ...
```

You can then copy that line to generate your final production rules using the full dataset (Train + Dev).


### Visualizing Results

Raw JSON data can be difficult to interpret. Yara-Gen includes a standalone visualization script to generate charts from your optimization results.

First, ensure you have the visualization dependencies installed:

```bash
uv sync --group plots
```

**Note:** Currenlty, the scripts dir is not included in the package, so you must clone the repo in order to get them.

Then run the visualizer on your results file:

```bash
uv run --group plots python scripts/plot_optimization_results.py \
  optimization_results_20260128.json \
  --metric f1_score
```

This generates a folder in `data/plots/` containing three key visualizations.

#### 1. The Pareto Frontier (Precision vs. Recall)

This is your primary tool for decision-making. It visualizes the trade-offs available to your engine.

- X-Axis (Recall): How many attacks were caught.
- Y-Axis (Precision): How "pure" the alerts are (lack of false positives).

**What to look for:**

- The "Sweet Spot": Look for points in the top-right corner. These configurations have high detection rates with few false alarms.

- The "Cliff": You may see a point where Recall increases slightly, but Precision drops massively. This gap indicates where the engine becomes "too loose" and starts flagging benign noise.

#### 2. Parameter Correlation Matrix

This heatmap helps you understand which parameters actually matter.

- Red (+1.0): Strong positive correlation. Increasing this parameter increases the metric.
- Blue (-1.0): Strong negative correlation. Increasing this parameter decreases the metric.
- Gray (0.0): No correlation. Changing this parameter has no effect on performance. Use this to identify which "knobs" are worth tuning and which can be ignored.

#### 3. Best Run Summary & Confusion Matrix
The script identifies the single best configuration based on your chosen metric (default: `f1_score`) and generates a specific Confusion Matrix for it.

**How to read the matrix:**
- Top-Right (False Positives): Safe inputs that were incorrectly flagged. High numbers here mean user frustration.
- Bottom-Left (False Negatives): Attacks that slipped through. High numbers here mean security risks.
- Diagonal (TN/TP): Correct predictions. You want these numbers to be as high as possible.

The folder also contains `summary.txt`, which lists the exact parameter values (e.g. `score_threshold=0.15`) used to achieve this result.



## Configuration and Overrides

Rule generation behavior is controlled through a combination of defaults, a configuration file, and CLI overrides. This model is designed to support both reproducible builds and rapid experimentation.

The `generation_config.yaml` file defines default settings for the generate command only. It is ignored by prepare. The file is typically checked into version control to make rule generation auditable and repeatable.

When generating rules, configuration is resolved in the following order: built-in defaults, values from `generation_config.yaml`, and finally any CLI flags or `--set` overrides. CLI values always take precedence and apply only to the current run.

### Configuration Structure

The configuration file is organized into four logical areas: output settings, metadata, data adapters, and the engine.

Output settings define where rules are written and how they are annotated. Metadata such as tags and rule dates are applied uniformly to all generated rules.

Adapter sections describe how adversarial and benign data should be loaded when not specified on the CLI. This includes the adapter type and any adapter-specific parameters.

The engine section controls how features are extracted and scored. While engine implementations may vary, the configuration interface remains consistent.

### Example Configuration

A typical configuration might look like this:

```yaml
output_path: "rules.yar"

tags:
  - "generated"
  - "prompt_injection"

metadata:
  author: "Deconvolute Labs"
  generator: "yara_gen"
  category: "prompt_injection"
  confidence: "high"
  source_dataset: "dataset"

adversarial_adapter:
  type: "jsonl"

benign_adapter:
  type: "jsonl"

engine:
  type: "ngram"
  score_threshold: 0.1
  max_rules_per_run: 50
  rule_date: "2025-10-27"
  min_ngram: 3
  max_ngram: 10
  min_document_frequency: 0.01
  benign_penalty_weight: 1.0
```

This file establishes stable defaults while still allowing targeted overrides during experimentation.

### CLI Overrides with --set

The `--set` flag allows you to override any configuration value using dot notation. Nested structures are created automatically, and values are type-inferred at runtime.

```bash
ygen generate input.jsonl --set engine.score_threshold=0.8
```

Overrides are ephemeral by design. They are ideal for tuning sensitivity, testing adapter parameters, or experimenting with engine behavior without modifying the base configuration.

## Engine Tuning and Sensitivity

Engine parameters control how aggressively Yara-Gen generates rules. Tuning is primarily about balancing coverage against false positives, and small changes can have a large impact on the resulting rule set.

The most important parameter is the score threshold. Higher values produce fewer, more specific rules with lower false-positive risk. Lower values increase sensitivity and coverage but may introduce weaker or more generic signatures. In practice, tuning usually starts by adjusting this value before touching other parameters.

N-gram settings control the size and stability of extracted patterns. Shorter n-grams increase recall but are more likely to collide with benign text. Longer n-grams are more specific but may overfit to narrow phrasing. Default ranges are chosen to work well for most text-based adversarial datasets and rarely need aggressive adjustment.

Document frequency thresholds determine how common a pattern must be across adversarial samples to be considered stable. Increasing this value favors broadly representative attacks, while decreasing it allows rules to capture rarer but potentially important patterns.

The benign penalty weight controls how strongly common benign patterns are suppressed. Increasing it makes the generator more conservative, especially when benign and adversarial language overlap.

Generation also includes safety and reproducibility controls. The maximum rule count prevents runaway outputs during experimentation, and fixed rule dates ensure deterministic builds suitable for audits and CI pipelines.

## Advanced Overrides with --set

The `--set` flag provides fine-grained control over configuration values at runtime. It allows you to override any configuration field using dot notation without modifying `generation_config.yaml`.

Overrides are resolved after the configuration file is loaded and always take precedence. This makes `--set` suitable for experimentation, one-off runs, and parameter sweeps, while keeping the base configuration stable and versioned.

Dot notation uses the form `key.subkey=value`. Nested structures are created automatically if they do not already exist. Values are parsed using type inference, so numbers and booleans do not need to be quoted.

```bash
ygen generate input.jsonl --set engine.min_ngram=5
```
Type inference follows simple rules. Boolean values use true or false. Numeric values are interpreted as integers or floats. All other values are treated as strings. Quoting is only required when the value itself contains spaces or special characters.

The same mechanism is used to pass adapter-specific parameters, such as authentication tokens or dataset subsets, without introducing additional CLI flags.

```bash
ygen generate input.jsonl \
  --set adversarial_adapter.config_name=red_team_v2 \
  --set adversarial_adapter.token=hf_123456789
```
Because overrides are ephemeral, they do not affect subsequent runs. For long-lived or shared settings, prefer updating the configuration file instead.



## Metadata and Rule Management

Yara-Gen allows adding metadata to every generated rule, providing context for audits, versioning, and operational workflows. Common metadata includes tags and rule dates.

Tags can classify rules by category, source, or purpose. They are applied uniformly to all rules in a generation run and can be specified in the configuration file or via the CLI using `--tag`.

```bash
ygen generate input.jsonl --tag "experimental" --tag "v1"
```
The rule date ensures deterministic builds and supports reproducible auditing. It is set in the configuration or overridden with `--rule-date`.

```bash
ygen generate input.jsonl --rule-date "2025-01-01"
```
Using consistent metadata makes it easier to integrate generated rules with existing YARA rulebases, version control, and automated deployment pipelines.

## Advanced Workflows

Experienced users typically treat rule generation as an iterative process. The most common workflow is:
1.	Prepare datasets once and reuse them for multiple runs.
2.	Generate an initial rule set.
3.	Adjust engine parameters, thresholds, or filters based on output.
4.	Regenerate and inspect results.

For large adversarial datasets, streaming directly from remote sources is supported, while keeping a local benign dataset prepared. This avoids repeated downloads for the control set while still processing new adversarial data efficiently.

Existing rulebases can be supplied as a baseline to avoid regenerating already-covered signatures. This enables incremental updates to rule sets without overwriting previous work.

By combining prepared data, CLI overrides, and incremental generation, practitioners can rapidly iterate while maintaining reproducibility and control over false positives.

## Performance and Scaling Considerations

Yara-Gen is optimized for large datasets but certain practices improve speed and reduce resource usage. Prepared JSONL datasets are faster to process than repeatedly streaming or parsing raw inputs.

Memory usage grows with the size of the adversarial and benign datasets, and with the number of candidate patterns extracted. Iterating on thresholds or n-gram ranges can produce more or fewer rules, which also affects runtime.

Streaming remote adversarial datasets is supported, but repeated streaming adds overhead. Keeping a local copy for iterative generation is recommended. Similarly, reusing a prepared benign dataset avoids repeated processing and ensures consistent scoring.

For very large corpora, breaking input into smaller batches or increasing system resources can help maintain predictable performance without affecting rule quality.

## Debugging and Common Failure Modes

Most issues arise from dataset configuration or parameter choices. Common failure modes include:
- Empty rule outputs: Usually caused by overly strict thresholds, an empty or misconfigured adversarial dataset, or excessive suppression from the benign corpus. Lower the score threshold or verify input data.
- Too many trivial rules: Often the result of low thresholds, short n-grams, or sparse benign data. Increase thresholds or adjust n-gram length.
- Benign data leakage: Occurs when benign inputs contain adversarial patterns, leading to suppressed rules. Check that the control set is clean and representative.
- Adapter misconfiguration: Incorrect adapter types or parameters can produce malformed outputs. Confirm adapter selection, especially for uncommon formats or Hugging Face streams.

Inspect prepared JSONL outputs and use small test datasets to verify behavior before scaling up. CLI overrides with `--set` are useful for tuning without modifying configuration files.

## Output, Validation, and Integration

Yara-Gen produces standard .yar files that can be loaded into any YARA-compatible engine. The output is immediately usable in scanning pipelines, rulebases, or automation workflows.

Validating generated rules before deployment is recommended. Quick checks include scanning representative benign data to confirm low false positives and sampling adversarial inputs to ensure coverage. Prepared datasets simplify this process by making test data consistent and repeatable.

Generated rules can be integrated into existing rulebases or versioned independently. Metadata such as tags and rule dates supports auditing and deterministic builds. For automated deployments, rules can be loaded directly into detection frameworks, including the Deconvolute SDK, without additional runtime dependencies.


```python
from deconvolute import scan

result = scan("Sample input text")
if result.threat_detected:
    print(f"Threat detected: {result.component}")
```
Using consistent metadata, prepared datasets, and controlled generation parameters ensures reliable, repeatable, and auditable rule deployment.
