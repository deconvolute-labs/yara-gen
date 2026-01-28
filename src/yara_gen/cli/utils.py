def parse_filter_arg(filter_str: str | None) -> tuple[str | None, str | None]:
    """Helper to parse 'col=val' string."""
    if not filter_str:
        return None, None
    if "=" not in filter_str:
        raise ValueError("Filter must be in 'column=value' format (e.g. 'label=1')")
    key, val = filter_str.split("=", 1)
    return key.strip(), val.strip()
