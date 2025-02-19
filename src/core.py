# security_validation/core.py (Slightly stricter test SanitizationConfig)

from typing import Type, TypeVar, Generic, Any, Annotated, Mapping
from pydantic import BaseModel, ValidationError, Field, field_validator
from pydantic.functional_validators import AfterValidator
from multidict import MultiDict
import nh3
import json

from .models import ValidationResult, ValidationErrorDetail, SanitizationConfig

T = TypeVar('T', bound=BaseModel)

def html_sanitizer(value: str, config: SanitizationConfig) -> str:
    """
    Sanitize an HTML string according to the provided configuration.

    Args:
        value: The HTML string to be sanitized.
        config: A SanitizationConfig instance containing sanitization settings.

    Returns:
        A sanitized version of the input HTML string.
    """
    return nh3.clean(
        value,
        tags=config.tags,
        attributes=config.attributes,
        url_schemes=config.url_schemes,
        strip_comments=config.strip_comments,
        link_rel=config.link_rel,
        clean_content_tags=config.clean_content_tags,
        generic_attribute_prefixes=config.generic_attribute_prefixes
    )

def validate_sanitized_string(value: str) -> str:
    """
    Validate that the value is a string. Intended to be used as a post-validation step.

    Args:
        value: The value to validate.

    Raises:
        ValueError: If the provided value is not a string.

    Returns:
        The original string if valid.
    """
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    return value

SanitizedString = Annotated[str, AfterValidator(validate_sanitized_string)]

class InputValidator(Generic[T]):
    """
    A generic input validator and sanitizer for Pydantic models.

    This class takes a Pydantic model and a sanitization configuration. It provides
    asynchronous methods to sanitize input data and validate it against the model.
    """

    def __init__(self, model: Type[T], config: SanitizationConfig):
        """
        Initialize the InputValidator.

        Args:
            model: A Pydantic model class to validate against.
            config: A SanitizationConfig instance for sanitizing input values.
        """
        self.model = model
        self.config = config
        self.field_names = model.model_fields.keys()

    async def sanitize_input(self, raw_data: Mapping[str, Any]) -> dict[str, Any]:
        """
        Sanitize the raw input data.

        Iterates over model fields, sanitizes each value using _sanitize_value,
        and returns a sanitized data dictionary.

        Args:
            raw_data: A mapping of field names to their raw input values.

        Returns:
            A dictionary of sanitized data.
        """
        sanitized = {}
        for field in self.field_names:
            value = raw_data.get(field)
            if value is None:
                continue

            if isinstance(value, list):
                sanitized[field] = [self._sanitize_value(v) for v in value]
            else:
                sanitized[field] = self._sanitize_value(value)
        return sanitized

    def _sanitize_value(self, value: Any) -> Any:
        """
        Recursively sanitize a single value.

        Depending on the type of value, the function will:
        - Sanitize strings using html_sanitizer.
        - Recursively process lists and dictionaries.
        - Return the original value for other types.

        Args:
            value: The value to sanitize.

        Returns:
            The sanitized value.
        """
        if isinstance(value, str):
            return html_sanitizer(value, self.config)
        if isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        return value

    async def validate(self, raw_data: Mapping[str, Any]) -> ValidationResult[T]:
        """
        Validate the sanitized input data against the provided Pydantic model.

        This method sanitizes the raw data, attempts to create a model instance,
        and records any validation errors found.

        Args:
            raw_data: A mapping of field names to raw input values.

        Returns:
            A ValidationResult instance containing the model instance, sanitized data,
            and any validation errors.
        """
        result = ValidationResult[T](is_valid=False)
        try:
            sanitized = await self.sanitize_input(raw_data)
            result.sanitized_data = sanitized
            model_instance = self.model(**sanitized)
            result.model = model_instance
            result.is_valid = True
        except ValidationError as e:
            self._process_errors(e, result, raw_data, sanitized)
        return result

    def _process_errors(self, e: ValidationError, 
                        result: ValidationResult[T],
                        raw_data: Mapping[str, Any],
                        sanitized: dict[str, Any]) -> None:
        """
        Process validation errors and populate the ValidationResult.

        Iterates over the errors produced by Pydantic and appends a corresponding
        ValidationErrorDetail for each error to the result.

        Args:
            e: The ValidationError exception raised by Pydantic.
            result: The ValidationResult instance to be updated.
            raw_data: The original raw input data.
            sanitized: The sanitized version of the input data.
        """
        for error in e.errors():
            field = error['loc'][0]
            result.errors.append(ValidationErrorDetail(
                field=str(field),
                message=error['msg'],
                input_value=raw_data.get(str(field)),
                sanitized_value=sanitized.get(str(field))
            ))

