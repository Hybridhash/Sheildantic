import pytest
from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from src.core import SanitizationConfig
from src.fastapi import validation_dependency
from src.models import ValidationResult, ValidationErrorDetail
from multidict import MultiDict
import json

# Custom JSON Encoder to handle ValidationErrorDetail
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ValidationErrorDetail):
            return o.model_dump() # Use pydantic's model_dump() for serialization
        return super().default(o)


# Test Pydantic Model
class TestUser(BaseModel):
    name: str = Field(..., min_length=3)
    bio: str = Field("", max_length=100)
    age: int = Field(..., gt=0)

# Security Configuration (Stricter for testing)
test_config = SanitizationConfig(
    tags={"b", "i"},  # Allow bold and italic
    attributes={"a": {"href"}},  # Only href attribute for links
    url_schemes={"https"}, # Only HTTPS links
    strip_comments=True,
    link_rel='noopener noreferrer',
    clean_content_tags={'script', 'style'}
)

# Test FastAPI App
@pytest.fixture
def test_app():
    app = FastAPI()

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Custom exception handler for JSON serialization"""
        return JSONResponse(
            content={"detail": [CustomJSONEncoder().default(e) for e in exc.detail]}, # JSON serialize ValidationErrorDetail
            status_code=exc.status_code,
            encoder_class=CustomJSONEncoder # Register the encoder
        )

    @app.post("/test-endpoint")
    async def test_route(result: ValidationResult[TestUser] = validation_dependency(TestUser, test_config)):
        if not result.is_valid:
            raise HTTPException(400, detail=result.errors)
        return result.model

    return app

@pytest.fixture
def client(test_app):
    return TestClient(test_app)

def test_valid_form_submission(client):
    """Test valid form data with HTML content"""
    response = client.post("/test-endpoint", data={
        "name": "<b>John Doe</b>",
        "bio": "<a href='https://example.com'>Link</a>",
        "age": "25"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "<b>John Doe</b>"  # Stripped tags
    assert data["bio"] == '<a href="https://example.com" rel="noopener noreferrer">Link</a>' #  Kept Allowed HTML
    assert data["age"] == 25


def test_xss_attempt(client):
    """Test XSS injection in form data"""
    response = client.post("/test-endpoint", data={
        "name": "<script>alert(1)</script>Alice",
        "bio": "<img src=x onerror=alert(1)>",
        "age": "30"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 400
    errors = response.json()
    assert any(e["field"] == "name" and "Value must be a string" in e["message"] for e in errors)


def test_json_payload_handling(client):
    """Test JSON payload validation"""
    response = client.post("/test-endpoint", json={
        "name": "Jane Smith",
        "bio": "Regular bio",
        "age": 28
    }, headers={"Content-Type": "application/json"})

    assert response.status_code == 200
    data = response.json()
    assert data["age"] == 28

def test_missing_required_field(client):
    """Test validation with missing required field"""
    response = client.post("/test-endpoint", data={
        "bio": "Test bio",
        "age": "25"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 400
    errors = response.json()
    assert any(e["field"] == "name" for e in errors)

def test_invalid_age_value(client):
    """Test invalid type conversion"""
    response = client.post("/test-endpoint", data={
        "name": "Bob",
        "bio": "Test bio",
        "age": "invalid"
    }, headers={"Content-Type": "application/x-www-form-urlencoded"})

    assert response.status_code == 400
    errors = response.json()
    assert any(e["field"] == "age" for e in errors)

