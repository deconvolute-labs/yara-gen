from datetime import datetime
from pathlib import Path

from jinja2 import Template

from yara_gen.generation.templates import YARA_TEMPLATE
from yara_gen.models.text import GeneratedRule
from yara_gen.utils.logger import get_logger

logger = get_logger()


class YaraWriter:
    """
    Serializes GeneratedRule objects into valid YARA rule files using Jinja2 templates.
    """

    def __init__(self, template_str: str = YARA_TEMPLATE):
        """
        Initialize the writer.

        Args:
            template_str: Custom Jinja2 template string. Defaults to the standard
                template.
        """
        self.template = Template(template_str)

    def write(self, rules: list[GeneratedRule], output_path: Path) -> None:
        """
        Renders the rules and writes them to the specified output path.

        Args:
            rules: List of generated rules to serialize.
            output_path: Destination file path.
        """
        if not rules:
            logger.warning(
                "No rules provided to writer. Output file will not be created."
            )
            return

        logger.debug(f"Rendering {len(rules)} rules via Jinja2 template...")

        # We need to ensure strings are safe for YARA (escape quotes/backslashes)
        sanitized_rules = self._sanitize_for_rendering(rules)

        rendered_content = self.template.render(
            rules=sanitized_rules,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            f.write(rendered_content)

        logger.info(f"Successfully wrote {len(rules)} rules to {output_path}")

    def _sanitize_for_rendering(
        self, rules: list[GeneratedRule]
    ) -> list[GeneratedRule]:
        """
        Prepares rules for the template by escaping special characters in strings.

        This prevents broken YARA syntax if a prompt contains quotes like:
        "ignore "previous" instructions" -> "ignore \"previous\" instructions"
        """
        for rule in rules:
            for s in rule.strings:
                # Escape backslashes first, then quotes
                safe_val = s.value.replace("\\", "\\\\").replace('"', '\\"')
                s.value = safe_val

            # Sanitize metadata values too
            for k, v in rule.metadata.items():
                rule.metadata[k] = str(v).replace('"', '\\"')

        return rules
