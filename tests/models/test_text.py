from yara_gen.models.text import DatasetType, GeneratedRule, RuleString, TextSample


class TestTextSample:
    def test_initialization(self):
        """Test basic initialization of TextSample."""
        sample = TextSample(
            text="malicious code",
            source="file.txt",
            dataset_type=DatasetType.ADVERSARIAL,
            metadata={"id": 1},
        )
        assert sample.text == "malicious code"
        assert sample.source == "file.txt"
        assert sample.dataset_type == DatasetType.ADVERSARIAL
        assert sample.metadata == {"id": 1}

    def test_to_dict(self):
        """Test serialization to dictionary."""
        sample = TextSample(
            text="hello world", source="test.csv", dataset_type=DatasetType.BENIGN
        )
        data = sample.to_dict()
        assert data["text"] == "hello world"
        assert data["source"] == "test.csv"
        assert data["dataset_type"] == "benign"  # Should be string value
        assert data["metadata"] == {}

    def test_hash_eq(self):
        """Test hashing and equality for deduplication."""
        s1 = TextSample(text="same", source="a", dataset_type=DatasetType.RAW)
        s2 = TextSample(text="same", source="b", dataset_type=DatasetType.RAW)
        s3 = TextSample(text="diff", source="a", dataset_type=DatasetType.RAW)

        # Equality is based only on text content
        assert s1 == s2
        assert s1 != s3

        # Hashing logic
        assert hash(s1) == hash(s2)
        assert len({s1, s2, s3}) == 2  # Set should dedup s1 and s2


class TestGeneratedRule:
    def test_defaults(self):
        """Test default values for GeneratedRule."""
        rule_string = RuleString(value="bad_string", score=0.9)
        rule = GeneratedRule(name="TestRule", score=0.95, strings=[rule_string])

        assert rule.tags == []
        assert rule.metadata == {}
        assert rule.created_at is not None
        assert rule.strings[0].modifiers == ["nocase", "wide", "ascii"]

    def test_full_initialization(self):
        """Test initialization with all fields."""
        rule_string = RuleString(value="bad", score=1.0, modifiers=["ascii"])
        rule = GeneratedRule(
            name="ComplexRule",
            tags=["trojan", "stealer"],
            score=0.8,
            strings=[rule_string],
            metadata={"author": "me"},
        )

        assert "trojan" in rule.tags
        assert rule.metadata["author"] == "me"
        assert rule.strings[0].modifiers == ["ascii"]
