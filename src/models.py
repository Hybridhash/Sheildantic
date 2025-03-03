# models.py
from typing import Any, Generic, TypeVar
from pydantic import BaseModel, ConfigDict


T = TypeVar('T', bound=BaseModel)

class ValidationErrorDetail(BaseModel):
    field: str
    message: str
    input_value: Any
    sanitized_value: Any | None = None

class ValidationResult(BaseModel, Generic[T]):
    is_valid: bool
    model: T | None = None
    errors: list[ValidationErrorDetail] = []
    sanitized_data: dict[str, Any] = {}

class SanitizationConfig(BaseModel):
    tags: set[str] | None = None
    attributes: dict[str, set[str]] | None = None
    url_schemes: set[str] | None = None
    strip_comments: bool = True
    link_rel: str | None = 'noopener noreferrer'
    clean_content_tags: set[str] | None = None
    generic_attribute_prefixes: set[str] | None = None
    # Remove max_field_size from ammonia config
    # Keep it for your own validation
    max_field_size: int = 1024

    model_config = ConfigDict(frozen=True)
