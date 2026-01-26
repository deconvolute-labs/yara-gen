import argparse
import json
import sys
from pathlib import Path


def merge_jsonl(input_paths, output_path):
    print(f"Merging {len(input_paths)} files into {output_path}...")

    total_written = 0

    try:
        with open(output_path, "w", encoding="utf-8") as outfile:
            for file_path in input_paths:
                path = Path(file_path)
                if not path.exists():
                    print(f"Error: Input file not found: {path}")
                    sys.exit(1)

                print(f"Processing {path.name}...")
                line_count = 0

                with open(path, encoding="utf-8") as infile:
                    for line_num, line in enumerate(infile, 1):
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError as e:
                            print(
                                f"Error: Invalid JSON in {path.name} at line {line_num}: {e}"
                            )
                            sys.exit(1)

                        # VALIDATION: Check for 'text' field
                        if "text" not in data:
                            raise ValueError(
                                f"Missing 'text' field in {path.name} at line {line_num}.\n"
                                f"Content: {str(data)[:100]}..."
                            )

                        # If valid, write it to the master file
                        outfile.write(line + "\n")
                        line_count += 1

                print(f"  -> Added {line_count} samples.")
                total_written += line_count

    except ValueError as e:
        print(f"\nFATAL ERROR: {e}")
        # Optionally delete the partial output file so you don't use bad data
        Path(output_path).unlink(missing_ok=True)
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)

    print(f"\nSuccess! Merged {total_written} total samples to '{output_path}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Merge and validate JSONL datasets.")
    parser.add_argument("inputs", nargs="+", help="Input JSONL files to merge")
    parser.add_argument(
        "--output", "-o", required=True, help="Path to output merged JSONL"
    )

    args = parser.parse_args()

    merge_jsonl(args.inputs, args.output)
