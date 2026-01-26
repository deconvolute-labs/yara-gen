import json
import sys

from yara_gen.adapters import get_adapter
from yara_gen.cli import parse_args, parse_filter_arg
from yara_gen.extraction.factory import get_extractor
from yara_gen.generation.writer import YaraWriter
from yara_gen.models.config import BaseExtractorConfig, NgramConfig
from yara_gen.models.text import DatasetType
from yara_gen.utils.logger import setup_logger
from yara_gen.utils.stream import filter_stream


def main() -> None:
    """
    Main application orchestrator.
    """
    args = parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger(level=log_level)
    logger.debug(f"Logger initialized in {log_level} mode")

    try:
        filter_col, filter_val = parse_filter_arg(args.filter)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # Dispatch logic
    if args.command == "prepare":
        logger.info(
            f"Preparing data from {args.input_path} using adapter '{args.adapter}'..."
        )
        # Initialize Adapter (forcing RAW type)
        try:
            adapter = get_adapter(args.adapter, DatasetType.RAW)
            stream = adapter.load(args.input_path, config_name=args.config_name)

            # Apply Universal Filter
            if filter_col and filter_val:
                stream = filter_stream(stream, filter_col, filter_val)
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

                    if args.limit and count >= args.limit:
                        logger.info(f"Reached limit of {args.limit} samples.")
                        break

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
                score_threshold=0.8 if args.mode == "strict" else 0.4,
                min_ngram_length=args.min_ngram,
                max_ngram_length=args.max_ngram,
            )
        else:
            raise ValueError(f"Engine '{args.engine}' is not yet supported.")
        try:
            # Adversarial Stream
            logger.info(f"Loading adversarial data from: {args.input_path}")
            adv_adapter = get_adapter(args.adapter, DatasetType.ADVERSARIAL)
            adv_stream = adv_adapter.load(args.input_path, config_name=args.config_name)

            # Apply Universal Filter (Only to adversarial for now, usually)
            if filter_col and filter_val:
                adv_stream = filter_stream(adv_stream, filter_col, filter_val)

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

            if rules:
                logger.info(f"Generation complete. Created {len(rules)} rules.")
            else:
                logger.warning("Generation complete, but NO rules were created.")
        except Exception as e:
            logger.error(f"Generation failed: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
