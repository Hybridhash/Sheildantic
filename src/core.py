# core.py
from typing import Type, TypeVar, Mapping, Any, get_origin
from pydantic import BaseModel, ValidationError
from multidict import MultiDict
import nh3
from src.models import ValidationResult, SanitizationConfig, ValidationErrorDetail

T = TypeVar('T', bound=BaseModel)

class InputValidator:
    def __init__(self, model: Type[T], config: SanitizationConfig):
        self.model = model
        self.config = config
        self.list_fields = self._identify_list_fields()

    def _identify_list_fields(self) -> set:
        list_fields = set()
        for field_name, field in self.model.model_fields.items():
            if get_origin(field.annotation) is list:
                list_fields.add(field_name)
        return list_fields

    async def sanitize_input(self, raw_data: Mapping[str, Any]) -> dict[str, Any]:
        sanitized = {}
        for field in self.model.model_fields:
            if field in self.list_fields:
                values = self._get_multi_values(raw_data, field)
                sanitized[field] = [self._sanitize_value(v) for v in values]
            elif field in raw_data:
                value = raw_data.get(field)
                if value is not None:
                    if self.model.model_fields[field].annotation is bool:
                        # Explicitly convert to bool with strict validation
                        if isinstance(value, str):
                            value_lower = value.lower()
                            if value_lower in ("true", "1", "yes"):
                                sanitized[field] = True
                            elif value_lower in ("false", "0", "no"):
                                sanitized[field] = False
                            else:
                                # For invalid boolean values, store as string to force validation error
                                sanitized[field] = str(value)
                        elif isinstance(value, int) or isinstance(value, bool):
                            sanitized[field] = bool(value)
                        else:
                            sanitized[field] = str(value)  # Force string for non-boolean types
                    else:
                        sanitized[field] = self._sanitize_value(value)
        return sanitized

    def _get_multi_values(self, data: Mapping[str, Any], field: str) -> list:
        if isinstance(data, MultiDict):
            return data.getall(field, [])
        value = data.get(field)
        return value if isinstance(value, list) else [value] if value is not None else []

    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            # For sanitized_data, we preserve HTML but filter unsafe elements
            ammonia_params = self.config.model_dump()
            max_field_size = ammonia_params.pop('max_field_size', None)
            
            sanitized = nh3.clean(value, **ammonia_params)
            
            # Add max length validation
            if max_field_size and len(sanitized) > max_field_size:
                raise ValueError(f"Field exceeds maximum size {max_field_size}")
            return sanitized
        if isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        return value
        
    def _clean_for_model(self, value: Any) -> Any:
        """Clean HTML for model but preserve structure"""
        if isinstance(value, str):
            # For model data, we strip all HTML tags
            return nh3.clean(value, tags=set())
        if isinstance(value, list):
            return [self._clean_for_model(v) for v in value]
        if isinstance(value, dict):
            return {k: self._clean_for_model(v) for k, v in value.items()}
        return value

    async def validate(self, raw_data: Mapping[str, Any]) -> ValidationResult[T]:
        result = ValidationResult[T](is_valid=False)
        try:
            # First pass - sanitize but preserve HTML structure
            sanitized = await self.sanitize_input(raw_data)
            result.sanitized_data = sanitized
            
            # Check for invalid boolean values BEFORE model validation
            for field_name, field in self.model.model_fields.items():
                if field_name in sanitized:
                    value = sanitized[field_name]
                    if field.annotation is bool:
                        if isinstance(value, str):  # Any string value not in accepted bool values is an error
                            valid_bools = {"true", "1", "yes", "false", "0", "no"}
                            if value.lower() not in valid_bools:
                                result.errors.append(ValidationErrorDetail(
                                    field=field_name,
                                    message=f"Value '{value}' could not be parsed to a boolean",
                                    input_value=raw_data.get(field_name),
                                    sanitized_value=value
                                ))
                    elif get_origin(field.annotation) is list and isinstance(value, list):
                        # Check list items match the expected type
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
            
            # If we already found errors, stop processing
            if result.errors:
                return result
                
            # Second pass - clean all HTML for the model
            model_data = {k: self._clean_for_model(v) for k, v in sanitized.items()}
            
            # Check for missing required fields before validation
            self._check_missing_required_fields(model_data, result)
            if result.errors:
                return result
            
            model_instance = self.model(**model_data)
            result.model = model_instance
            result.is_valid = True
        except (ValidationError, ValueError) as e:
            result.sanitized_data = sanitized if 'sanitized' in locals() else {}
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
                    if not error['loc']:
                        field_name = "general"
                    else:
                        field_path = error['loc'][0]
                        field_name = str(field_path).split('.')[0]
                    
                    result.errors.append(ValidationErrorDetail(
                        field=field_name,
                        message=error['msg'],
                        input_value=raw_data.get(field_name) if field_name != "general" else None,
                        sanitized_value=sanitized.get(field_name) if field_name != "general" else None
                    ))
        
        return result

    def _check_missing_required_fields(self, data: dict, result: ValidationResult[T]):
        """Check for missing required fields and add them to errors"""
        for field_name, field in self.model.model_fields.items():
            # Check if field is required and missing
            if field.is_required() and field_name not in data:
                result.errors.append(ValidationErrorDetail(
                    field=field_name,
                    message=f"Field required",
                    input_value=None,
                    sanitized_value=None
                ))

    def _process_errors(self, e: ValidationError, result: ValidationResult[T], 
                       raw_data: Mapping, sanitized: dict):
        """Process validation errors from Pydantic"""
        for error in e.errors():
            # Extract the field name from the location
            if not error['loc']:
                field_name = "general"
            else:
                # Handle both simple fields and nested fields like friends.0
                field_name = str(error['loc'][0])
            
            # Create the error detail
            input_value = raw_data.get(field_name) if field_name != "general" else None
            sanitized_value = sanitized.get(field_name) if field_name != "general" else None
            
            # Special handling for list field errors (e.g., friends.0)
            if '.' in field_name and field_name.split('.')[0] in self.list_fields:
                base_field = field_name.split('.')[0]
                input_value = raw_data.get(base_field) if base_field in raw_data else None
                sanitized_value = sanitized.get(base_field) if base_field in sanitized else None
                # Use the base field name for the error
                field_name = base_field
            
            # Always add the specific field error
            result.errors.append(ValidationErrorDetail(
                field=field_name,
                message=error['msg'],
                input_value=input_value,
                sanitized_value=sanitized_value
            ))