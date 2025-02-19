from typing import Any, Generic, TypeVar
from pydantic import BaseModel, ConfigDict

T = TypeVar('T', bound=BaseModel)

class ValidationErrorDetail(BaseModel):
    """
    Represents details of a single validation error.

    Attributes:
        field (str): The name of the field that caused the error.
        message (str): A descriptive error message.
        input_value (Any): The original input value that caused the error.
        sanitized_value (Any | None): The value after sanitization, if available.
    """
    field: str
    message: str
    input_value: Any
    sanitized_value: Any | None = None

class ValidationResult(BaseModel, Generic[T]):
    """
    Represents the outcome of validating input data against a model.

    Attributes:
        is_valid (bool): Indicates whether the input data is valid.
        model (T | None): The validated Pydantic model instance if the input is valid.
        errors (list[ValidationErrorDetail]): A list of validation error details, if any.
        sanitized_data (dict[str, Any]): Dictionary containing sanitized input data.
    """
    is_valid: bool
    model: T | None = None
    errors: list[ValidationErrorDetail] = []
    sanitized_data: dict[str, Any] = {}

class SanitizationConfig(BaseModel):
    """
    Holds configuration settings for sanitizing input data, particularly HTML.

    Attributes:
        tags (set[str] | None): Allowed HTML tags.
        attributes (dict[str, set[str]] | None): Allowed HTML attributes for each tag.
        url_schemes (set[str] | None): Permitted URL schemes in HTML links.
        strip_comments (bool): Whether HTML comments should be stripped out.
        link_rel (str | None): Value of the 'rel' attribute for links, enhancing security.
        clean_content_tags (set[str] | None): Tags for which inner content should be cleaned.
        generic_attribute_prefixes (set[str] | None): Allowed prefixes for generic HTML attributes.
    """
    tags: set[str] | None = None
    attributes: dict[str, set[str]] | None = None
    url_schemes: set[str] | None = None
    strip_comments: bool = True
    link_rel: str | None = 'noopener noreferrer'
    clean_content_tags: set[str] | None = None
    generic_attribute_prefixes: set[str] | None = None

    model_config = ConfigDict(frozen=True)  # Replace the Config class with model_config
