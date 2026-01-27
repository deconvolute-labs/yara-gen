from pydantic import BaseModel


class AdapterConfig(BaseModel):
    """
    Generic configuration for adapters.
    """

    type: str = "jsonl"

    # Allows passing in adapter-specific args directly
    model_config = {"extra": "allow"}
