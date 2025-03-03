# test_validation.py
import pytest
from multidict import MultiDict
from pydantic import BaseModel
from src.core import InputValidator, SanitizationConfig
from src.models import ValidationResult

class TestUser(BaseModel):
    name: str
    friends: list[int]
    active: bool = True
    bio: str = ""

@pytest.fixture
def strict_config():
    return SanitizationConfig(
        tags=None,
        attributes={'a': {'href', 'title'}},
        clean_content_tags={'script', 'style'},
        max_field_size=256
    )

@pytest.mark.asyncio
async def test_valid_input_with_multidict(strict_config):
    data = MultiDict([
        ("name", "<b>John</b>"),
        ("friends", "2"),
        ("friends", "3"),
        ("active", "false")
    ])
    
    validator = InputValidator(TestUser, strict_config)
    result = await validator.validate(data)
    
    assert result.is_valid
    assert result.model.name == "John"
    assert result.model.friends == [2, 3]
    assert result.model.active is False
    assert "b" in result.sanitized_data['name']

@pytest.mark.asyncio
async def test_xss_sanitization(strict_config):
    data = MultiDict([
        ("name", "<script>alert(1)</script>John"),
        ("friends", "2"),
        ("bio", "<a href='javascript:alert(1)'>malicious</a>")
    ])
    
    validator = InputValidator(TestUser, strict_config)
    result = await validator.validate(data)
    
    assert result.is_valid
    assert "script" not in result.sanitized_data['name']
    assert "javascript" not in result.sanitized_data['bio']

@pytest.mark.asyncio
async def test_invalid_type_conversion():
    data = MultiDict([
        ("name", "John"),
        ("friends", "invalid"),
        ("active", "not_bool")
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    result = await validator.validate(data)
    
    assert not result.is_valid
    assert len(result.errors) == 2
    assert any(e.field == 'friends' for e in result.errors)
    assert any(e.field == 'active' for e in result.errors)

@pytest.mark.asyncio
async def test_missing_required_field():
    data = MultiDict([
        ("friends", "2"),
        ("active", "true")
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    result = await validator.validate(data)
    
    assert not result.is_valid
    assert any(e.field == 'name' for e in result.errors)

@pytest.mark.asyncio
async def test_list_field_handling():
    data = MultiDict([
        ("name", "Alice"),
        ("friends", "1"),
        ("friends", "2")
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    result = await validator.validate(data)
    
    assert result.is_valid
    assert result.model.friends == [1, 2]

@pytest.mark.asyncio
async def test_max_length_validation(strict_config):
    long_name = "A" * 300
    data = MultiDict([
        ("name", long_name),
        ("friends", "1")
    ])
    
    validator = InputValidator(TestUser, strict_config)
    result = await validator.validate(data)
    
    assert not result.is_valid
    assert any("exceeds maximum size" in e.message for e in result.errors)
