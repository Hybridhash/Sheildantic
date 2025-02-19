# security_validation/fastapi.py
from fastapi import Depends, Request, HTTPException
from typing import Type, TypeVar
from pydantic import BaseModel
from .core import InputValidator, SanitizationConfig, ValidationResult

T = TypeVar('T', bound=BaseModel)

class ValidationDependency:
    """
    FastAPI dependency class that handles request validation and sanitization.
    
    Attributes:
        model (Type[T]): Pydantic model to validate against
        config (SanitizationConfig): HTML sanitization configuration
    """
    
    def __init__(self, model: Type[T], config: SanitizationConfig):
        """
        Initialize the dependency with validation rules.
        
        Args:
            model: Pydantic model class for validation
            config: Sanitization configuration for HTML cleaning
        """
        self.model = model
        self.config = config

    async def __call__(self, request: Request) -> ValidationResult[T]:
        """
        Execute full validation pipeline for incoming requests.
        
        Args:
            request: FastAPI request object
            
        Returns:
            ValidationResult containing sanitized data and validation status
        """
        data = await get_request_data(request)
        validator = InputValidator(self.model, self.config)
        return await validator.validate(data)

async def get_request_data(request: Request) -> dict:
    """
    Extract and normalize request data from different content types.
    
    Handles:
    - JSON payloads (application/json)
    - Form data (x-www-form-urlencoded)
    - Multipart form data (multipart/form-data)
    
    Args:
        request: FastAPI request object
        
    Returns:
        dict: Normalized request data
    """
    content_type = request.headers.get('content-type', '')
    
    if content_type.startswith('application/json'):
        return await request.json()
    
    if content_type.startswith(('application/x-www-form-urlencoded', 'multipart/form-data')):
        form_data = await request.form()
        return dict(form_data)
    
    return {}

def validation_dependency(
    model: Type[T],
    config: SanitizationConfig = SanitizationConfig()
) -> Depends:
    """
    Create FastAPI dependency for request validation.
    
    Usage:
    @app.post("/endpoint")
    async def create_item(result: ValidationResult[Model] = validation_dependency(Model)):
        ...
        
    Args:
        model: Pydantic model class
        config: Sanitization configuration
        
    Returns:
        FastAPI dependency
    """
    return Depends(ValidationDependency(model, config))
