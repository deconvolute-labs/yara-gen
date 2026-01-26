import json
import sys

from langdetect import LangDetectException, detect


def clean_jsonl(input_path, output_path):
    print(f"Processing {input_path}...")
    kept = 0
    dropped = 0

    with (
        open(input_path, encoding="utf-8") as infile,
        open(output_path, "w", encoding="utf-8") as outfile,
    ):
        for line in infile:
            if not line.strip():
                continue

            data = json.loads(line)
            text = data.get("text", "")

            try:
                # Detect language. If text is too short/ambiguous, we skip or default.
                # 'en' = English.
                lang = detect(text)

                if lang == "en":
                    outfile.write(line)
                    kept += 1
                else:
                    dropped += 1
            except LangDetectException:
                # If detection fails (e.g. symbols only), drop it to be safe
                dropped += 1

    print(f"Done. Kept {kept} English samples. Dropped {dropped} non-English samples.")
    print(f"Clean file saved to: {output_path}")


if __name__ == "__main__":
    # Usage: python clean_dataset.py input.jsonl output.jsonl
    if len(sys.argv) != 3:
        print("Usage: python clean_dataset.py <input_file> <output_file>")
        sys.exit(1)

    clean_jsonl(sys.argv[1], sys.argv[2])
