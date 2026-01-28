"""
Optimization Results Visualizer for Yara-Gen

Reads the JSON output from `ygen optimize` and generates analysis plots:
1. Precision-Recall Scatter (The Pareto Frontier)
2. Hyperparameter Correlation Heatmap
3. Confusion Matrix of the Best Run

Usage:
    uv run --group plots python scripts/plot_optimization_results.py optimization_results_X.json
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import pandas as pd
    import seaborn as sns
except ImportError as e:
    print("\n" + "!" * 60)
    print("MISSING VISUALIZATION DEPENDENCIES")
    print("!" * 60)
    print(f"Error: {e}")
    print("\nTo run this script, please install the 'plots' dependency group:")
    print("    uv sync --group plots")
    print("    # Or run directly:")
    print("    uv run --group plots python scripts/plot_optimization_results.py ...")
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Visualize Yara-Gen optimization results."
    )
    parser.add_argument(
        "input", type=Path, help="Path to the optimization results JSON file."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        help="Directory to save plots. Defaults to ./data/plots/<input_name>_<timestamp>",
    )
    parser.add_argument(
        "--metric",
        type=str,
        default="f1_score",
        choices=["f1_score", "recall", "precision"],
        help="Metric used to select the 'Best Run' for detailed analysis.",
    )
    return parser.parse_args()


def load_data(input_path: Path) -> pd.DataFrame:
    """Loads JSON and flattens it into a Pandas DataFrame."""
    if not input_path.exists():
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    with open(input_path, "r") as f:
        data = json.load(f)

    runs = data.get("runs", [])
    if not runs:
        print("Error: No runs found in the provided JSON file.")
        sys.exit(1)

    # Flatten structure: metrics + parameters + run metadata
    flattened_data = []
    for run in runs:
        item = {
            "iteration": run.get("iteration"),
            "duration": run.get("duration_seconds"),
        }
        # Unpack metrics
        metrics = run.get("metrics", {})
        item.update(metrics)  # tp, fp, precision, recall, f1_score ...

        # Unpack parameters (prefix them to avoid collisions)
        params = run.get("parameters", {})
        for k, v in params.items():
            item[f"param_{k}"] = v

        flattened_data.append(item)

    return pd.DataFrame(flattened_data)


def setup_plotting_style() -> None:
    sns.set_theme(style="whitegrid", context="talk")
    plt.rcParams["figure.figsize"] = (10, 6)
    plt.rcParams["axes.titlesize"] = 16


def plot_pareto_frontier(df: pd.DataFrame, output_dir: Path) -> None:
    """Scatter plot of Precision vs Recall."""
    plt.figure(figsize=(10, 8))

    # Create a local copy and round the hue column (f1_score) 
    # This forces the legend to show clean labels (e.g. 0.85 instead of 0.851234)
    plot_df = df.copy()
    plot_df["f1_score"] = plot_df["f1_score"].round(2)
    
    # Color by F1 Score to highlight the "sweet spot"
    scatter = sns.scatterplot(
        data=plot_df,
        x="recall",
        y="precision",
        hue="f1_score",
        palette="viridis",
        size="fp",  # Larger points = more false positives (bad)
        sizes=(50, 200),
        alpha=0.8,
        edgecolor="k"
    )

    plt.title("Optimization Landscape: Precision vs Recall")
    plt.xlabel("Recall (Detection Rate)")
    plt.ylabel("Precision (Avoidance of False Positives)")
    plt.xlim(-0.05, 1.05)
    plt.ylim(-0.05, 1.05)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', title="Metrics")
    plt.tight_layout()
    
    out_file = output_dir / "pareto_precision_recall.png"
    plt.savefig(out_file, dpi=150)
    print(f"Saved: {out_file}")
    plt.close()


def plot_param_correlations(df: pd.DataFrame, output_dir: Path) -> None:
    """Heatmap showing correlation between parameters and performance metrics."""
    # Select only numeric columns (metrics + numeric params)
    # Filter out columns that don't vary (std dev == 0) to keep chart clean
    numeric_df = df.select_dtypes(include=["number"])
    
    # Drop columns that are constant (e.g., if min_ngram was 4 for ALL runs)
    valid_cols = [c for c in numeric_df.columns if numeric_df[c].std() > 0]
    
    if len(valid_cols) < 2:
        print("Skipping correlation plot: Not enough variance in parameters.")
        return

    corr_matrix = numeric_df[valid_cols].corr()

    plt.figure(figsize=(18, 16))
    sns.heatmap(
        corr_matrix,
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        center=0,
        square=True,
        linewidths=0.5,
        annot_kws={"size": 10}
    )
    plt.title("Correlation Matrix: Parameters vs Metrics")
    plt.tight_layout()

    out_file = output_dir / "parameter_correlations.png"
    plt.savefig(out_file, dpi=150)
    print(f"Saved: {out_file}")
    plt.close()


def plot_confusion_matrix(best_run: pd.Series, output_dir: Path) -> None:
    """Visualizes TP/FP/TN/FN for the best run."""
    # Extract confusion values
    tp = int(best_run.get("tp", 0))
    fp = int(best_run.get("fp", 0))
    fn = int(best_run.get("fn", 0))
    tn = int(best_run.get("tn", 0))

    matrix = [[tn, fp], [fn, tp]]
    labels = [["TN", "FP"], ["FN", "TP"]]

    plt.figure(figsize=(6, 5))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Predicted Benign", "Predicted Attack"],
        yticklabels=["Actual Benign", "Actual Attack"],
        annot_kws={"size": 20, "weight": "bold"}
    )
    
    # Add text labels (TN, FP ...) manually to be clear
    for i in range(2):
        for j in range(2):
            plt.text(j + 0.5, i + 0.2, labels[i][j], 
                     ha="center", va="center", color="gray", fontsize=10)

    plt.title(f"Confusion Matrix (Best Run #{int(best_run['iteration'])})")
    plt.tight_layout()

    out_file = output_dir / "best_run_confusion_matrix.png"
    plt.savefig(out_file, dpi=150)
    print(f"Saved: {out_file}")
    plt.close()

def save_summary_text(best_run: pd.Series, metric: str, output_dir: Path) -> None:
    """Saves key stats of the best run to a summary text file."""
    out_file = output_dir / "summary.txt"
    
    # Filter parameters for cleaner display
    params = {k.replace("param_", ""): v for k, v in best_run.items() if k.startswith("param_")}
    
    with open(out_file, "w") as f:
        f.write("=" * 40 + "\n")
        f.write(f"OPTIMIZATION SUMMARY\n")
        f.write("=" * 40 + "\n")
        f.write(f"Selected Best Run by Metric: {metric.upper()}\n")
        f.write(f"Iteration ID: {int(best_run['iteration'])}\n")
        f.write(f"Generated at: {datetime.now().isoformat()}\n")
        f.write("-" * 40 + "\n")
        f.write("METRICS:\n")
        f.write(f"  F1 Score:  {best_run['f1_score']:.4f}\n")
        f.write(f"  Precision: {best_run['precision']:.4f}\n")
        f.write(f"  Recall:    {best_run['recall']:.4f}\n")
        f.write(f"  TP: {int(best_run['tp'])}\n")
        f.write(f"  FP: {int(best_run['fp'])}\n")
        f.write(f"  FN: {int(best_run['fn'])}\n")
        f.write("-" * 40 + "\n")
        f.write("PARAMETERS:\n")
        for k, v in params.items():
            f.write(f"  {k}: {v}\n")
        f.write("=" * 40 + "\n")

    print(f"Saved: {out_file}")

def get_best_run(df: pd.DataFrame, metric: str) -> pd.Series:
    """
    Selects the best run based on the metric with smart tie-breaking.
    
    Logic:
    - If metric is 'fp' or 'fn': Minimize it. Break ties with max F1.
    - If metric is others: Maximize it. Break ties with min FP.
    """
    lower_is_better = ["fp", "fn"]
    
    if metric in lower_is_better:
        # Sort: Primary (asc), Secondary (desc)
        # e.g. Lowest FP, then Highest F1
        sorted_df = df.sort_values(by=[metric, "f1_score"], ascending=[True, False])
    else:
        # Sort: Primary (desc), Secondary (asc)
        # e.g. Highest Recall, then Lowest FP
        # Note: We can't use simple [False, True] if we mix directions
        # So we use nlargest logic or explicit sort
        sorted_df = df.sort_values(by=[metric, "fp"], ascending=[False, True])
        
    return sorted_df.iloc[0]


def main() -> None:
    args = parse_args()
    
    # Determine Output Directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        # Default: ./data/plots/<filename_stem>_<metric>_<timestamp>
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("data/plots") / f"{args.input.stem}_{args.metric}_{ts}"

    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Processing: {args.input}")
    print(f"Output Directory: {output_dir}")

    # Load Data
    df = load_data(args.input)
    print(f"Loaded {len(df)} runs.")

    setup_plotting_style()

    # 1. Pareto Frontier (Precision vs Recall)
    plot_pareto_frontier(df, output_dir)

    # 2. Parameter Correlations
    plot_param_correlations(df, output_dir)

    # 3. Best Run Confusion Matrix
    best_run = get_best_run(df, args.metric)

    print("-" * 40)
    print(f"Best Run (based on {args.metric}):")
    print(f"  Iteration: {best_run['iteration']}")
    print(f"  F1 Score:  {best_run['f1_score']:.4f}")
    print(f"  Precision: {best_run['precision']:.4f}")
    print(f"  Recall:    {best_run['recall']:.4f}")
    print("-" * 40)
    
    plot_confusion_matrix(best_run, output_dir)

    # 4. Summary Text File
    save_summary_text(best_run, args.metric, output_dir)
    
    print("\nVisualization Complete.")


if __name__ == "__main__":
    main()