"""Input validation and sanitization for Pydantic models with HTML cleaning."""

import decimal
import datetime
import enum
import re
from typing import Type, TypeVar, Mapping, Any, get_origin

import nh3
from multidict import MultiDict
from pydantic import BaseModel, ValidationError

from src.models import ValidationResult, SanitizationConfig, ValidationErrorDetail

T = TypeVar('T', bound=BaseModel)


class InputValidator:
    """
    Validates and sanitizes input data for Pydantic models.
    
    Supports HTML sanitization, type conversion, and special handling for MultiDict
    (commonly used in web forms for multi-value fields like checkboxes).
    """
    
    # Valid boolean string representations
    VALID_BOOLEAN_STRINGS = {"true", "1", "yes", "false", "0", "no"}
    
    # Boolean string to boolean value mapping
    BOOLEAN_MAP = {
        "true": True, "1": True, "yes": True,
        "false": False, "0": False, "no": False
    }

    def __init__(self, model: Type[T], config: SanitizationConfig):
        """
        Initialize the validator.
        
        Args:
            model: Pydantic model class to validate against
            config: Sanitization configuration
        """
        self.model = model
        self.config = config
        self.list_fields = self._identify_list_fields()

    def _identify_list_fields(self) -> set[str]:
        """
        Identify fields that are list types in the model.
        
        Returns:
            Set of field names that are list types
        """
        list_fields = set()
        for field_name, field in self.model.model_fields.items():
            if get_origin(field.annotation) is list:
                list_fields.add(field_name)
        return list_fields

    def _parse_bool(self, value: Any) -> bool | str:
        """
        Parse various value types to boolean or return as string for error reporting.
        
        Args:
            value: Input value to parse
            
        Returns:
            Parsed boolean value or original string if parsing fails
        """
        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower in self.BOOLEAN_MAP:
                return self.BOOLEAN_MAP[value_lower]
            return str(value)  # Invalid string, return as-is for error reporting
        
        if isinstance(value, (int, bool)):
            return bool(value)
            
        return str(value)  # Non-standard types, return as string

    async def sanitize_input(self, raw_data: Mapping[str, Any]) -> dict[str, Any]:
        """
        Sanitize input data while preserving structure for validation.
        
        Args:
            raw_data: Raw input data from form or API
            
        Returns:
            Sanitized data dictionary
        """
        sanitized = {}
        for field in self.model.model_fields:
            if field in self.list_fields:
                values = self._get_multi_values(raw_data, field)
                sanitized[field] = [self._sanitize_value(v) for v in values]
            elif field in raw_data:
                value = raw_data.get(field)
                if value is not None:
                    if self.model.model_fields[field].annotation is bool:
                        sanitized[field] = self._parse_bool(value)
                    else:
                        sanitized[field] = self._sanitize_value(value)
        return sanitized

    def _get_multi_values(self, data: Mapping[str, Any], field: str) -> list:
        """
        Extract multi-values for a field from data, handling both MultiDict and regular dict.
        
        Args:
            data: Input data mapping
            field: Field name to extract values for
            
        Returns:
            List of values for the field
        """
        if isinstance(data, MultiDict):
            return data.getall(field, [])
        value = data.get(field)
        return value if isinstance(value, list) else [value] if value is not None else []

    def _sanitize_value(self, value: Any) -> Any:
        """
        Sanitize a single value based on its type.
        
        Args:
            value: The value to sanitize
            
        Returns:
            Sanitized value
        """
        if value is None:
            return None
            
        if isinstance(value, str):
            return self._sanitize_string(value)
            
        if isinstance(value, (int, float, decimal.Decimal, bool)):
            return value
            
        if isinstance(value, (bytes, bytearray)):
            return value
            
        if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
            return value
            
        if isinstance(value, enum.Enum):
            return value.value
            
        if isinstance(value, (list, tuple, set)):
            return self._sanitize_iterable(value)
            
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
            
        if hasattr(value, '__dict__'):
            return {k: self._sanitize_value(v) for k, v in value.__dict__.items()}
            
        return value

    def _sanitize_string(self, value: str) -> str:
        """
        Sanitize a string value using nh3.
        
        Args:
            value: String to sanitize
            
        Returns:
            Sanitized string
            
        Raises:
            ValueError: If field exceeds maximum size
        """
        ammonia_params = self.config.model_dump()
        max_field_size = ammonia_params.pop('max_field_size', None)
        sanitized = nh3.clean(value, **ammonia_params)
        
        if max_field_size and len(sanitized) > max_field_size:
            raise ValueError(f"Field exceeds maximum size {max_field_size}")
            
        return sanitized

    def _sanitize_iterable(self, value):
        """
        Sanitize an iterable (list, tuple, set) by sanitizing each element.
        
        Args:
            value: Iterable to sanitize
            
        Returns:
            Sanitized iterable of the same type
        """
        sanitized_items = [self._sanitize_value(v) for v in value]
        
        if isinstance(value, tuple):
            return tuple(sanitized_items)
        elif isinstance(value, set):
            return set(sanitized_items)
        return sanitized_items
        
    def _clean_for_model(self, value: Any) -> Any:
        """
        Clean HTML for model but preserve structure.
        
        Args:
            value: Value to clean
            
        Returns:
            Cleaned value with HTML tags stripped
        """
        if isinstance(value, str):
            # For model data, we strip all HTML tags
            return nh3.clean(value, tags=set())
        if isinstance(value, list):
            return [self._clean_for_model(v) for v in value]
        if isinstance(value, dict):
            return {k: self._clean_for_model(v) for k, v in value.items()}
        return value

    async def validate(self, raw_data: Mapping[str, Any]) -> ValidationResult[T]:
        """
        Validate and sanitize input data.
        
        Args:
            raw_data: Raw input data to validate
            
        Returns:
            ValidationResult with validation status, errors, and sanitized data
        """
        result = ValidationResult[T](is_valid=False)
        
        try:
            # First pass - sanitize but preserve HTML structure
            sanitized = await self.sanitize_input(raw_data)
            result.sanitized_data = sanitized
            
            # Check for validation errors before creating the model
            self._validate_field_types(sanitized, raw_data, result)
            
            if result.errors:
                return result
                
            # Second pass - clean all HTML for the model
            model_data = {k: self._clean_for_model(v) for k, v in sanitized.items()}
            
            # Check for missing required fields
            self._check_missing_required_fields(model_data, result)
            if result.errors:
                return result
            
            # Create model instance
            model_instance = self.model(**model_data)
            result.model = model_instance
            result.is_valid = True
            
        except (ValidationError, ValueError) as e:
            result.sanitized_data = sanitized if 'sanitized' in locals() else {}
            self._process_validation_errors(e, raw_data, result, sanitized if 'sanitized' in locals() else {})
        
        return result

    def _validate_field_types(self, sanitized: dict, raw_data: Mapping[str, Any], result: ValidationResult[T]):
        """
        Validate field types before model creation.
        
        Args:
            sanitized: Sanitized data
            raw_data: Original raw data
            result: ValidationResult to populate with errors
        """
        for field_name, field in self.model.model_fields.items():
            if field_name not in sanitized:
                continue
                
            value = sanitized[field_name]
            
            # Check boolean fields
            if field.annotation is bool and isinstance(value, str):
                if value.lower() not in self.VALID_BOOLEAN_STRINGS:
                    result.errors.append(ValidationErrorDetail(
                        field=field_name,
                        message=f"Value '{value}' could not be parsed to a boolean",
                        input_value=raw_data.get(field_name),
                        sanitized_value=value
                    ))
                    
            # Check list fields
            elif get_origin(field.annotation) is list and isinstance(value, list):
                self._validate_list_field(field_name, field, value, raw_data, result)

    def _validate_list_field(self, field_name: str, field, value: list, raw_data: Mapping[str, Any], result: ValidationResult[T]):
        """
        Validate a list field's items.
        
        Args:
            field_name: Name of the field
            field: Field definition
            value: List value to validate
            raw_data: Original raw data
            result: ValidationResult to populate with errors
        """
        if not hasattr(field.annotation, '__args__') or not field.annotation.__args__:
            return
            
        inner_type = field.annotation.__args__[0]
        
        for i, item in enumerate(value):
            if inner_type is int and not isinstance(item, int):
                try:
                    int(item)  # Try conversion
                except (ValueError, TypeError):
                    result.errors.append(ValidationErrorDetail(
                        field=field_name,
                        message=f"Value '{item}' at index {i} could not be parsed to an integer",
                        input_value=raw_data.get(field_name),
                        sanitized_value=value
                    ))

    def _process_validation_errors(self, e: Exception, raw_data: Mapping[str, Any], result: ValidationResult[T], sanitized: dict):
        """
        Process validation errors from Pydantic or other sources.
        
        Args:
            e: Exception that occurred
            raw_data: Original raw data
            result: ValidationResult to populate with errors
            sanitized: Sanitized data
        """
        if isinstance(e, ValueError):
            # Handle max length errors
            result.errors.append(ValidationErrorDetail(
                field="general",
                message=str(e),
                input_value=None,
                sanitized_value=None
            ))
        else:
            # Process errors from Pydantic
            for error in e.errors():
                field_name = self._extract_field_name(error)
                
                result.errors.append(ValidationErrorDetail(
                    field=field_name,
                    message=error.get('msg', ''),
                    input_value=raw_data.get(field_name.split('.')[0]) if field_name != "general" else None,
                    sanitized_value=sanitized.get(field_name.split('.')[0]) if field_name != "general" else None
                ))

    def _extract_field_name(self, error: dict) -> str:
        """
        Extract field name from Pydantic error.
        
        Args:
            error: Pydantic error dictionary
            
        Returns:
            Field name or "general" if not found
        """
        field_name = "general"
        current_loc = error.get('loc')
        
        if current_loc:
            if isinstance(current_loc, (list, tuple)) and current_loc:
                field_name = ".".join(str(part) for part in current_loc)
            else:
                field_name = str(current_loc)
                if not field_name:
                    field_name = "general"
        
        # If field_name is still "general", try to extract from message
        if field_name == "general" or not current_loc:
            msg_for_regex = error.get('msg', '')
            match = re.search(r"\n(\w+)\n", msg_for_regex)
            if match:
                field_name = match.group(1)
                
        return field_name

    def _check_missing_required_fields(self, data: dict, result: ValidationResult[T]):
        """
        Check for missing required fields and add them to errors.
        
        Args:
            data: Data dictionary to check
            result: ValidationResult to populate with errors
        """
        for field_name, field in self.model.model_fields.items():
            # Check if field is required and missing
            if field.is_required() and field_name not in data:
                result.errors.append(ValidationErrorDetail(
                    field=field_name,
                    message="Field required",
                    input_value=None,
                    sanitized_value=None
                ))
