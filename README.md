# Sheildantic

A Python package that combines Pydantic validation with HTML sanitization for secure form handling in web applications.

## Overview

Sheildantic provides a seamless way to sanitize and validate user input from web forms, protecting against XSS attacks while leveraging Pydantic's powerful validation capabilities. It's framework-agnostic and works with any web framework that can provide form data as a dictionary or MultiDict.

## Key Features

- **HTML Sanitization**: Safely handles user-provided HTML content using the NH3 library
- **Pydantic Integration**: Validates sanitized data against your Pydantic models
- **MultiDict Support**: Properly handles multi-value form fields (like checkboxes or multi-selects)
- **Framework Agnostic**: Works with FastAPI, Flask, Django, or any Python web framework
- **Detailed Error Reporting**: Provides comprehensive validation error details
- **Configurable Sanitization**: Customize allowed HTML tags, attributes, and more

## Installation

```bash
pip install sheildantic
```

## Usage

### Basic Example

```python
from pydantic import BaseModel
from multidict import MultiDict
from sheildantic.core import InputValidator
from sheildantic.models import SanitizationConfig

# Define your Pydantic model
class BlogPost(BaseModel):
    title: str
    content: str
    tags: list[str] = []
    published: bool = False

# Create sanitization config
config = SanitizationConfig(
    tags={"p", "br", "strong", "em"},  # Allow only these HTML tags
    attributes={},  # No attributes allowed
    max_field_size=10000  # Maximum field size
)

# Create a validator instance
validator = InputValidator(BlogPost, config)

# Example form data (this could come from a web request)
form_data = MultiDict([
    ("title", "<script>alert('XSS')</script>My Blog Post"),
    ("content", "<p>This is <strong>valid</strong> content</p><iframe src='evil.com'></iframe>"),
    ("tags", "python"),
    ("tags", "security"),
    ("published", "true")
])

# Validate the input
result = await validator.validate(form_data)

if result.is_valid:
    # Access the sanitized and validated data
    blog_post = result.model
    print(f"Title: {blog_post.title}")
    print(f"Content: {blog_post.content}")
    print(f"Tags: {blog_post.tags}")
    print(f"Published: {blog_post.published}")
    
    # You can also access the sanitized data directly 
    # (this preserves allowed HTML elements)
    sanitized_content = result.sanitized_data["content"]
else:
    # Handle validation errors
    for error in result.errors:
        print(f"Error in field '{error.field}': {error.message}")
```

### Integration with FastAPI

```python
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from sheildantic.core import InputValidator
from sheildantic.models import SanitizationConfig, ValidationResult

app = FastAPI()

class UserComment(BaseModel):
    username: str
    comment: str

async def get_request_data(request: Request):
    """Extract form data from the request"""
    form_data = await request.form()
    return form_data

@app.post("/comments")
async def create_comment(request: Request):
    # Get form data
    data = await get_request_data(request)
    
    # Configure validation
    config = SanitizationConfig(
        tags={"p", "br", "a"},
        attributes={"a": {"href", "title"}},
        url_schemes={"http", "https"},
        link_rel="noopener noreferrer"
    )
    
    # Validate and sanitize
    validator = InputValidator(UserComment, config)
    result = await validator.validate(data)
    
    if not result.is_valid:
        raise HTTPException(
            status_code=400, 
            detail=[err.dict() for err in result.errors]
        )
    
    # Process the valid and sanitized comment
    user_comment = result.model
    # Save to database, etc.
    
    return {
        "status": "success",
        "comment": user_comment.dict()
    }
```

## Code Flow

Sheildantic follows this processing flow:

1. **Input Collection**: Receives input data as a dict or MultiDict
2. **Sanitization**: 
   - Processes the input through NH3 sanitizer
   - Handles MultiDict fields (converting to lists when needed)
   - Applies max field size limits
3. **Validation**:
   - Runs sanitized data through Pydantic validation
   - Produces detailed validation errors
4. **Result**: Returns a ValidationResult containing:
   - Validation status
   - Sanitized data (with allowed HTML preserved)
   - Validated Pydantic model instance
   - Detailed error information

## Configuration Options

The `SanitizationConfig` class allows you to customize sanitization:

```python
config = SanitizationConfig(
    # Allowed HTML tags (None = use NH3 defaults)
    tags={"p", "br", "strong", "em", "a", "ul", "li"},
    
    # Allowed attributes for specific tags
    attributes={"a": {"href", "title"}},
    
    # Allowed URL schemes
    url_schemes={"http", "https"},
    
    # Strip HTML comments
    strip_comments=True,
    
    # Add rel attribute to links
    link_rel="noopener noreferrer",
    
    # Tags to clean content from
    clean_content_tags={"script", "style"},
    
    # Maximum field size
    max_field_size=10000
)
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.