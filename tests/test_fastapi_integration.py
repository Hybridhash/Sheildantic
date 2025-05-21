import decimal
import enum
import datetime
from typing import Tuple, Set, Dict, Any, List, Optional
import pytest
from multidict import MultiDict
from pydantic import BaseModel, Field
from src.core import InputValidator, SanitizationConfig
from src.models import ValidationResult

# --- Additional types for testing ---

class Color(enum.Enum):
    RED = "red"
    GREEN = "green"
    BLUE = "blue"

class CustomClass:
    def __init__(self, x):
        self.x = x

class StructLike(BaseModel):
    a: int
    b: float

class AllTypesModel(BaseModel):
    string_field: str
    int_field: int
    float_field: float
    bool_field: bool
    none_field: Optional[str] = None
    list_field: List[int]
    tuple_field: Tuple[int, float]
    set_field: Set[str]
    dict_field: Dict[str, Any]
    custom_obj: Dict[str, Any]
    struct_field: StructLike
    enum_field: Color
    short_int: int
    long_int: int
    decimal_field: decimal.Decimal
    float_precision: float
    bytes_field: bytes
    date_field: datetime.date
    datetime_field: datetime.datetime
    time_field: datetime.time

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

@pytest.mark.asyncio
async def test_all_types_handling():
    now = datetime.datetime(2025, 5, 21, 12, 34, 56)
    today = now.date()
    t = now.time()
    struct = StructLike(a=5, b=2.5)
    custom_obj = CustomClass(42)
    data = {
        "string_field": "<b>hello</b>",
        "int_field": "42",
        "float_field": "3.14",
        "bool_field": "yes",
        "none_field": None,
        "list_field": ["1", "2", "3"],
        "tuple_field": [1, 2.5],
        "set_field": ["a", "b", "a"],
        "dict_field": {"key": "value", "nested": {"x": 1}},
        "custom_obj": {"x": 42},
        "struct_field": {"a": 5, "b": 2.5},
        "enum_field": "red",
        "short_int": 7,
        "long_int": 12345678901234567890,
        "decimal_field": "10.55",
        "float_precision": "2.7182818284",
        "bytes_field": b"abc",
        "date_field": today.isoformat(),
        "datetime_field": now.isoformat(),
        "time_field": t.isoformat(),
    }
    validator = InputValidator(AllTypesModel, SanitizationConfig())
    result = await validator.validate(data)
    assert result.is_valid
    assert result.model.string_field == "hello"
    assert result.model.int_field == 42
    assert abs(result.model.float_field - 3.14) < 1e-6
    assert result.model.bool_field is True
    assert result.model.none_field is None
    assert result.model.list_field == [1, 2, 3]
    assert result.model.tuple_field == (1, 2.5)
    assert set(result.model.set_field) == {"a", "b"}
    assert result.model.dict_field["key"] == "value"
    assert result.model.dict_field["nested"]["x"] == 1
    assert result.model.custom_obj["x"] == 42
    assert result.model.struct_field.a == 5
    assert result.model.struct_field.b == 2.5
    assert result.model.enum_field == Color.RED
    assert result.model.short_int == 7
    assert result.model.long_int == 12345678901234567890
    assert result.model.decimal_field == decimal.Decimal("10.55")
    assert abs(result.model.float_precision - 2.7182818284) < 1e-9
    assert result.model.bytes_field == b"abc"
    assert result.model.date_field == today
    assert result.model.datetime_field == now
    assert result.model.time_field == t

@pytest.mark.asyncio
async def test_bytes_and_none():
    class BytesModel(BaseModel):
        data: Optional[bytes] = None
    validator = InputValidator(BytesModel, SanitizationConfig())
    result = await validator.validate({"data": None})
    assert result.is_valid
    assert result.model.data is None
    result2 = await validator.validate({"data": b"xyz"})
    assert result2.is_valid
    assert result2.model.data == b"xyz"

@pytest.mark.asyncio
async def test_enum_strictness():
    class EnumModel(BaseModel):
        color: Color
    validator = InputValidator(EnumModel, SanitizationConfig())
    result = await validator.validate({"color": "green"})
    print(result.errors)
    assert result.is_valid
    assert result.model.color == Color.GREEN
    result2 = await validator.validate({"color": "notacolor"})
    print(result2.errors)
    assert not result2.is_valid
    assert any("color" in e.message.lower() for e in result2.errors)
