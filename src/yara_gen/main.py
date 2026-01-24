import json
import sys

from yara_gen.adapters import get_adapter
from yara_gen.cli import parse_args
from yara_gen.extraction.factory import get_extractor
from yara_gen.generation.writer import YaraWriter
from yara_gen.models.config import BaseExtractorConfig, NgramConfig
from yara_gen.models.text import DatasetType
from yara_gen.utils.logger import setup_logger


def main() -> None:
    """
    Main application orchestrator.
    """
    args = parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger(level=log_level)
    logger.debug(f"Logger initialized in {log_level} mode")

    # Dispatch logic
    if args.command == "prepare":
        logger.info(
            f"Preparing data from {args.input_path} using adapter '{args.adapter}'..."
        )
        # Initialize Adapter (forcing RAW type)
        try:
            adapter = get_adapter(args.adapter, DatasetType.RAW)
            stream = adapter.load(args.input_path)
        except Exception as e:
            logger.error(f"Failed to initialize adapter: {e}")
            sys.exit(1)

        # Open Output & Stream
        count = 0
        try:
            # Ensure parent dir exists
            args.output.parent.mkdir(parents=True, exist_ok=True)

            with args.output.open("w", encoding="utf-8") as f:
                for sample in stream:
                    line = json.dumps(sample.to_dict(), ensure_ascii=False)
                    f.write(line + "\n")
                    count += 1

                    if count % 5000 == 0:
                        logger.debug(f"Processed {count} samples...")

            logger.info(f"Successfully wrote {count} samples to {args.output}")

        except Exception as e:
            logger.error(f"Failed during preparation: {e}")
            sys.exit(1)

    elif args.command == "generate":
        logger.info(f"Starting generation in {args.mode} mode...")
        # Build the specific Configuration based on Engine selection
        extractor_config: BaseExtractorConfig

        if args.engine == "ngram":
            logger.debug("Configuring N-Gram Engine parameters...")
            extractor_config = NgramConfig(
                score_threshold=0.8,  # Could map from args.mode
                min_ngram_length=args.min_ngram,
                max_ngram_length=args.max_ngram,
            )
        else:
            # Fallback or error
            raise ValueError(f"Engine '{args.engine}' is not yet supported.")

        # Input Adapters
        # Note: We pass the string arg directly to the loader
        logger.info(f"Loading adversarial data from: {args.input_path}")
        adv_adapter = get_adapter(args.adapter, DatasetType.ADVERSARIAL)
        adv_stream = adv_adapter.load(args.input_path)

        logger.info(f"Loading benign data from: {args.benign}")
        benign_adapter = get_adapter(args.benign_adapter, DatasetType.BENIGN)
        benign_stream = benign_adapter.load(args.benign)

        # Extraction
        logger.info(f"Initializing extraction engine: {args.engine}")
        extractor = get_extractor(args.engine, extractor_config)
        rules = extractor.extract(adversarial=adv_stream, benign=benign_stream)

        # Output Generation
        writer = YaraWriter()
        writer.write(rules, args.output)

        logger.info("Generation complete.")


if __name__ == "__main__":
    main()
