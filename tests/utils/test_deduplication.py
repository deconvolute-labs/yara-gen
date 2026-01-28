from yara_gen.generation.deduplication import parse_existing_rules


def test_parse_non_existent_file(tmp_path):
    """It should return an empty set if the file does not exist."""
    fake_file = tmp_path / "ghost.yar"
    result = parse_existing_rules(fake_file)
    assert result == set()


def test_parse_empty_file(tmp_path):
    """It should return an empty set for an empty file."""
    f = tmp_path / "empty.yar"
    f.write_text("", encoding="utf-8")
    result = parse_existing_rules(f)
    assert result == set()


def test_parse_simple_strings(tmp_path):
    """It should extract standard alphanumeric strings."""
    content = """
    rule TestRule {
        strings:
            $s1 = "hello world"
            $s2 = "malicious_payload"
        condition:
            any of them
    }
    """
    f = tmp_path / "simple.yar"
    f.write_text(content, encoding="utf-8")

    result = parse_existing_rules(f)
    assert "hello world" in result
    assert "malicious_payload" in result
    assert len(result) == 2


def test_parse_escaped_quotes(tmp_path):
    """It should correctly handle strings containing escaped quotes."""
    # In YARA file: "command \"execute\" now"
    # In Python logic: command "execute" now
    content = r"""
    rule Escaped {
        strings:
            $a = "command \"execute\" now"
            $b = "path\\to\\file"
    }
    """
    f = tmp_path / "escaped.yar"
    f.write_text(content, encoding="utf-8")

    result = parse_existing_rules(f)

    # Check for the unescaped version
    assert 'command "execute" now' in result
    assert r"path\to\file" in result


def test_parse_messy_formatting(tmp_path):
    """It should handle weird whitespace around the assignment."""
    content = """
    rule Messy {
        strings:
            $var1= "tight"
            $var2   =    "loose"
    }
    """
    f = tmp_path / "messy.yar"
    f.write_text(content, encoding="utf-8")

    result = parse_existing_rules(f)
    assert "tight" in result
    assert "loose" in result
