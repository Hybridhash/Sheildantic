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
async def test_multidict_vs_dict_behavior():
    """Compare behavior between regular dict and MultiDict for list fields"""
    # Test with standard dict
    dict_data = {
        "name": "John",
        "friends": [1, 2, 3]  # Standard Python list
    }
    
    # Test with MultiDict
    multi_data = MultiDict([
        ("name", "John"),
        ("friends", "1"),
        ("friends", "2"),
        ("friends", "3")
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    dict_result = await validator.validate(dict_data)
    multi_result = await validator.validate(multi_data)
    
    assert dict_result.is_valid and multi_result.is_valid
    assert dict_result.model.friends == multi_result.model.friends == [1, 2, 3]

@pytest.mark.asyncio
async def test_multidict_empty_values():
    """Test MultiDict with empty values for list fields"""
    data = MultiDict([
        ("name", "Jane"),
        ("friends", ""),  # Empty string
        ("friends", None)  # None value
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    result = await validator.validate(data)
    
    # The validation should fail since empty strings can't be converted to integers
    assert not result.is_valid
    assert any("friends" in e.field for e in result.errors)

@pytest.mark.asyncio
async def test_multidict_mixed_types():
    """Test MultiDict with mixed valid/invalid types in a list field"""
    class MixedModel(BaseModel):
        items: list[str]
    
    data = MultiDict([
        ("items", "text"),
        ("items", "<script>alert(1)</script>"),
        ("items", "<b>bold</b>")
    ])
    
    validator = InputValidator(MixedModel, SanitizationConfig())
    result = await validator.validate(data)
    
    assert result.is_valid
    assert len(result.model.items) == 3
    assert "script" not in result.model.items[1]
    assert result.model.items[2] == "bold"  # HTML tags stripped in model

@pytest.mark.asyncio
async def test_multidict_complex_structure():
    """Test MultiDict with more complex form structure"""
    class ComplexForm(BaseModel):
        name: str
        interests: list[str]
        skills: list[int]  # Rating 1-5
        
    data = MultiDict([
        ("name", "Alice"),
        ("interests", "programming"),
        ("interests", "music"),
        ("interests", "hiking"),
        ("skills", "5"),
        ("skills", "3"),
        ("skills", "4")
    ])
    
    validator = InputValidator(ComplexForm, SanitizationConfig())
    result = await validator.validate(data)
    
    assert result.is_valid
    assert result.model.interests == ["programming", "music", "hiking"]
    assert result.model.skills == [5, 3, 4]

@pytest.mark.asyncio
async def test_multidict_partial_invalid_list():
    """Test MultiDict with some invalid values in a list field"""
    data = MultiDict([
        ("name", "Bob"),
        ("friends", "1"),
        ("friends", "invalid"),  # Invalid int
        ("friends", "3")
    ])
    
    validator = InputValidator(TestUser, SanitizationConfig())
    result = await validator.validate(data)
    
    assert not result.is_valid
    assert any("friends" in e.field and "invalid" in e.message for e in result.errors)

@pytest.mark.asyncio
async def test_multidict_large_list():
    """Test MultiDict with a large number of list items"""
    class LargeListModel(BaseModel):
        items: list[int]
    
    data = MultiDict([("items", str(i)) for i in range(100)])
    
    validator = InputValidator(LargeListModel, SanitizationConfig())
    result = await validator.validate(data)
    
    assert result.is_valid
    assert len(result.model.items) == 100
    assert result.model.items == list(range(100))

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

@pytest.mark.asyncio
async def test_deeply_nested_dict_structure():
    """Test deeply nested dictionary structure with InputValidator"""
    from pydantic import BaseModel
    class Coordinates(BaseModel):
        lat: float
        lng: float
    class Address(BaseModel):
        city: str
        zip: str
        coordinates: Coordinates
    class Phone(BaseModel):
        type: str
        number: str
    class Item(BaseModel):
        product_id: int
        quantity: int
    class Order(BaseModel):
        id: int
        items: list[Item]
        status: str
    class Notifications(BaseModel):
        email: bool
        sms: bool
    class Preferences(BaseModel):
        newsletter: bool
        notifications: Notifications
    class UserModel(BaseModel):
        name: str
        email: str
        address: Address
        phones: list[Phone]
        preferences: Preferences
        orders: list[Order]
    class RootModel(BaseModel):
        user: UserModel

    data = {
        "user": {
            "name": "John",
            "email": "john@example.com",
            "address": {
                "city": "New York",
                "zip": "10001",
                "coordinates": {
                    "lat": 40.7128,
                    "lng": -74.0060
                }
            },
            "phones": [
                {"type": "mobile", "number": "123-456-7890"},
                {"type": "home", "number": "555-555-5555"}
            ],
            "preferences": {
                "newsletter": True,
                "notifications": {
                    "email": True,
                    "sms": False
                }
            },
            "orders": [
                {
                    "id": 1,
                    "items": [
                        {"product_id": 101, "quantity": 2},
                        {"product_id": 202, "quantity": 1}
                    ],
                    "status": "shipped"
                },
                {
                    "id": 2,
                    "items": [
                        {"product_id": 303, "quantity": 4}
                    ],
                    "status": "processing"
                }
            ]
        }
    }

    validator = InputValidator(RootModel, SanitizationConfig())
    result = await validator.validate(data)
    assert result.is_valid
    assert result.model.user.name == "John"
    assert result.model.user.address.city == "New York"
    assert result.model.user.phones[0].type == "mobile"
    assert result.model.user.preferences.newsletter is True
    assert result.model.user.orders[0].items[1].product_id == 202
    assert result.model.user.orders[1].status == "processing"
