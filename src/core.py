# core.py
from typing import Type, TypeVar, Mapping, Any, get_origin
from pydantic import BaseModel, ValidationError
from multidict import MultiDict
import nh3
from src.models import ValidationResult, SanitizationConfig, ValidationErrorDetail
import decimal
import enum
import datetime
import re

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

    def _parse_bool(self, value: Any) -> bool | str:
        # Map string representations to booleans
        bool_map = {
            "true": True, "1": True, "yes": True,
            "false": False, "0": False, "no": False
        }
        if isinstance(value, str):
            value_lower = value.lower()
            if value_lower in bool_map:
                return bool_map[value_lower]
            return str(value)  # Invalid string, return as-is for error reporting
        if isinstance(value, (int, bool)):
            return bool(value)
        return str(value)  # Non-standard types, return as string

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
                        sanitized[field] = self._parse_bool(value)
                    else:
                        sanitized[field] = self._sanitize_value(value)
        return sanitized

    def _get_multi_values(self, data: Mapping[str, Any], field: str) -> list:
        if isinstance(data, MultiDict):
            return data.getall(field, [])
        value = data.get(field)
        return value if isinstance(value, list) else [value] if value is not None else []

    def _sanitize_value(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            ammonia_params = self.config.model_dump()
            max_field_size = ammonia_params.pop('max_field_size', None)
            sanitized = nh3.clean(value, **ammonia_params)
            if max_field_size and len(sanitized) > max_field_size:
                raise ValueError(f"Field exceeds maximum size {max_field_size}")
            return sanitized
        if isinstance(value, (int, float, decimal.Decimal)):
            return value
        if isinstance(value, bool):
            return value
        if isinstance(value, (bytes, bytearray)):
            return value
        if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
            return value
        if isinstance(value, enum.Enum):
            return value.value
        if isinstance(value, (list, tuple, set)):
            sanitized_iterable = [self._sanitize_value(v) for v in value]
            if isinstance(value, tuple):
                return tuple(sanitized_iterable)
            elif isinstance(value, set):
                return set(sanitized_iterable)
            return sanitized_iterable
        if isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        if hasattr(value, '__dict__'):
            return {k: self._sanitize_value(v) for k, v in value.__dict__.items()}
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
                    
                    field_name = "general"
                    
                    
                    current_loc = error.get('loc')
                    error_msg_content = error.get('msg', '')
                    print(f"DEBUG: Processing Pydantic error. error['loc'] = {repr(current_loc)}")
                    print(f"DEBUG: error['msg'] for regex = {repr(error_msg_content)}")
                    

                    if current_loc: 
                        if isinstance(current_loc, (list, tuple)) and current_loc: 
                            field_name = ".".join(str(part) for part in current_loc)
                        else: # If loc is a string or other truthy non-list/tuple, or empty list/tuple was handled by outer if
                            field_name = str(current_loc) 
                            if not field_name: # If str(current_loc) resulted in empty string
                                field_name = "general" 
                    
                    # If field_name is still "general", it means loc didn't yield a field name
                    if field_name == "general" or not current_loc : # Added 'not current_loc' to ensure fallback if loc was initially None/empty
                        
                        msg_for_regex = error.get('msg', '')
                        
                        match = re.search(r"\n(\w+)\n", msg_for_regex)
                        # ---- START DEBUG ----
                        if match:
                            print(f"DEBUG: Regex matched. Groups: {match.groups()}")
                        else:
                            print(f"DEBUG: Regex did NOT match on msg: {repr(msg_for_regex)}")
                        # ---- END DEBUG ----
                        if match:
                            field_name = match.group(1)
                            
                    result.errors.append(ValidationErrorDetail(
                        field=field_name,
                        message=error.get('msg', ''), # Use error.get('msg', '') directly here
                        input_value=raw_data.get(field_name.split('.')[0]) if field_name != "general" else None,
                        sanitized_value=sanitized.get(field_name.split('.')[0]) if field_name != "general" else None
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

 