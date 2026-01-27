# User Guide

## 1. Preferred Workflow

Use a two-step pipeline for best results.

1.  **Prepare:** Convert raw data (CSV, Hugging Face) into clean JSONL files.
2.  **Generate:** Run the rule generator on the clean JSONL files.

The generator works best with JSONL. This format allows faster processing and easier inspection.

## 2. Configuration (`generation_config.yaml`)

The `generation_config.yaml` file controls defaults exclusively for the `generate` command. It is ignored by the `prepare` command. The file lives in the project root.

### Structure
The file has three main sections:
* **adversarial_adapter:** Where attack data comes from.
* **benign_adapter:** Where control data comes from.
* **engine:** Algorithm settings (e.g. N-gram thresholds).

### Complete Example

```yaml
# Global Output
output_path: "rules.yar"

# Tags for rules
tags:
  - "generated"
  - "category:injection"

# Adversarial Data Source
adversarial_adapter:
  type: "jsonl" # Default: Expects local JSONL (e.g. from 'prepare' command)
  
  # To use Hugging Face directly during generation:
  # type: "huggingface"
  # config_name: "subset_name"
  # split: "train"

# Benign Data Source
benign_adapter:
  type: "jsonl"

# Engine Configuration
engine:
  type: "ngram"

  # General Settings
  score_threshold: 0.1       # Lower = more rules (looser). Higher = fewer rules (stricter).
  max_rules_per_run: 50      # Safety limit.
  rule_date: "2025-10-27"    # Fixed date for reproducible builds.

  # N-Gram Specifics
  min_ngram: 3
  max_ngram: 10
  min_document_frequency: 0.01
  benign_penalty_weight: 1.0 # Higher values aggressively penalize common words.
```

## 3. Command: `prepare`
Normalizes large datasets into JSONL. 

Note: This command is strictly CLI-driven and does not use the config file.


#### Smart Auto-Detection

You generally do not need to specify an adapter. The tool detects it based on your input:

- Hugging Face: If the input is not a local file (e.g. user/repo), it defaults to huggingface.
- CSV: If the input is a local file ending in .csv, it defaults to generic-csv.
- Raw Text: Any other local file defaults to raw-text.


**Usage Examples**

Hugging Face (Auto-Detected):

```bash
ygen prepare "rubend18/ChatGPT-Jailbreak-Prompts" --output jailbreaks.jsonl
```

Manual Override: You can force a specific adapter using `--adapter` (or -a).

```bash
# Force 'raw-text' parsing for a file with a weird extension
ygen prepare data.xyz --output clean.jsonl --adapter raw-text
```

**Advanced: Hugging Face Arguments**

Download and stream directly from the Hub. Use `--set` to pass specific arguments like `config_name` or `split`.

```bash
ygen prepare "rubend18/ChatGPT-Jailbreak-Prompts" \
  --output jailbreaks.jsonl \
  --set adapter.split=train \
  --set adapter.config_name=default
```


#### Universal Filtering

Filter rows for all adapters using `--filter`. Format: `column=value`.

```bash
# Only process rows where 'label' is 'jailbreak'
ygen prepare data.csv --output clean.jsonl --filter "label=jailbreak"
```

## 4. Command: generate
Extracts signatures and writes YARA rules. 

**Note:** This command reads defaults from `generation_config.yaml`.

Basic Usage:
```bash
ygen generate jailbreaks.jsonl --benign benign.jsonl --output rules.yar
```

### CLI Overrides

CLI arguments always override `generation_config.yaml`.

- `--output`: Sets the destination file.
- `--engine`: Switches the algorithm (e.g. ngram).
- `--adapter`: Overrides the configured adapter type.

### Tuning Sensitivity

Adjust strictness without editing the config file.

Strict Mode (Fewer False Positives): Increase the score threshold.

```bash
ygen generate input.jsonl --set engine.score_threshold=0.8
```

Loose Mode (Higher Sensitivity): Decrease the threshold.

```bash
ygen generate input.jsonl --set engine.score_threshold=0.05
```

#### Metadata
Metadata

Add context to your rules.

- `--tag`: Adds tags to every generated rule.

- `--rule-date`: Sets a fixed date in the metadata.

```bash
ygen generate input.jsonl --tag "experimental" --tag "v1" --rule-date "2023-01-01"
```

## 5. Advanced Configuration (--set)
The `--set` flag overrides configuration values using dot notation. It creates nested structures automatically.

Syntax: `key.subkey=value`

#### Type Inference: The tool automatically detects types:

- `true` / `false` → Boolean
- `123` → Integer
- `0.5` → Float
- `Other` → String

### Examples:

Change N-gram length:

```bash
--set engine.min_ngram_length=5
```

Pass a Hugging Face token:

```bash
--set adversarial_adapter.token=hf_123456789
```
Switch Hugging Face config subset:

```bash
--set adversarial_adapter.config_name=red_team_v2
```

Example streaming from huggingface for adversarial and local benign:

```bash
ygen generate TrustAIRLab/in-the-wild-jailbreak-prompts --adversarial-adapter huggingface --benign-dataset benign.jsonl --set adversarial_adapter.config_name=jailbreak_2023_05_07
```
