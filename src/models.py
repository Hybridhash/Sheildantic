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
    """
    Configuration for HTML sanitization using nh3.clean().

    By default, nh3 uses:
        - tags: ALLOWED_TAGS
        - attributes: ALLOWED_ATTRIBUTES
        - url_schemes: ALLOWED_URL_SCHEMES
    You can import these from this module to customize your config.

    Examples:
        # Remove the <b> tag from allowed tags
        tags = nh3.ALLOWED_TAGS - {"b"}
        nh3.clean("<b><i>yeah</i></b>", tags=tags)
        # Output: '<i>yeah</i>'

        # Add a custom attribute to <img> tags
        from copy import deepcopy
        attributes = deepcopy(nh3.ALLOWED_ATTRIBUTES)
        attributes["img"].add("data-invert")
        nh3.clean("<img src='example.jpeg' data-invert=true>", attributes=attributes)
        # Output: '<img src="example.jpeg" data-invert="true">'

        # Remove 'tel' from allowed URL schemes
        url_schemes = nh3.ALLOWED_URL_SCHEMES - {'tel'}
        nh3.clean('<a href="tel:+1">Call</a> or <a href="mailto:contact@me">email</a> me.', url_schemes=url_schemes)
        # Output: '<a rel="noopener noreferrer">Call</a> or <a href="mailto:contact@me" rel="noopener noreferrer">email</a> me.'
    """
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
