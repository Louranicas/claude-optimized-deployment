"""
Parameter validation utilities for Circle of Experts.

Provides standardized validation patterns for all module functions.
"""

from typing import Any, Optional, List, Dict, Type, Union, TypeVar
from datetime import datetime, timedelta
import logging

from src.circle_of_experts.models.query import QueryPriority, QueryType
from src.circle_of_experts.models.response import ExpertType
__all__ = [
    "validate_not_none",
    "validate_string",
    "validate_enum",
    "validate_list",
    "validate_dict",
    "validate_number",
    "validate_datetime",
    "validate_deadline_hours",
    "validate_query_parameters",
    "validate_response_collection_parameters"
]

from src.core.exceptions import (
    ValidationError,
    TypeValidationError,
    RangeValidationError,
    FormatValidationError,
    RequiredFieldError,
    ConstraintValidationError
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


def validate_not_none(value: Any, field_name: str) -> Any:
    """
    Validate that a value is not None.
    
    Args:
        value: Value to validate
        field_name: Name of the field for error messages
        
    Returns:
        The validated value
        
    Raises:
        RequiredFieldError: If value is None
    """
    if value is None:
        raise RequiredFieldError(field_name)
    return value


def validate_string(
    value: Optional[str], 
    field_name: str, 
    required: bool = True,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None
) -> Optional[str]:
    """
    Validate a string value.
    
    Args:
        value: String to validate
        field_name: Name of the field
        required: Whether the field is required
        min_length: Minimum length
        max_length: Maximum length
        pattern: Regex pattern to match
        
    Returns:
        Validated string or None
        
    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        if required:
            raise RequiredFieldError(field_name)
        return None
    
    if not isinstance(value, str):
        raise TypeValidationError(field_name, value, str)
    
    # Strip whitespace
    value = value.strip()
    
    if required and not value:
        raise RequiredFieldError(field_name)
    
    if min_length is not None and len(value) < min_length:
        raise RangeValidationError(field_name, len(value), min_value=min_length)
    
    if max_length is not None and len(value) > max_length:
        raise RangeValidationError(field_name, len(value), max_value=max_length)
    
    if pattern is not None:
        import re
        if not re.match(pattern, value):
            raise FormatValidationError(field_name, value, f"pattern: {pattern}")
    
    return value


def validate_enum(
    value: Optional[Union[str, T]], 
    field_name: str, 
    enum_class: Type[T],
    required: bool = True
) -> Optional[T]:
    """
    Validate an enum value.
    
    Args:
        value: Value to validate
        field_name: Name of the field
        enum_class: Enum class to validate against
        required: Whether the field is required
        
    Returns:
        Validated enum value or None
        
    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        if required:
            raise RequiredFieldError(field_name)
        return None
    
    # If already an enum instance, return it
    if isinstance(value, enum_class):
        return value
    
    # Try to convert string to enum
    if isinstance(value, str):
        try:
            return enum_class(value)
        except ValueError:
            valid_values = [e.value for e in enum_class]
            raise ConstraintValidationError(
                field_name, 
                value, 
                f"Must be one of: {', '.join(valid_values)}"
            )
    
    raise TypeValidationError(
        field_name, 
        value, 
        f"{enum_class.__name__} or string"
    )


def validate_list(
    value: Optional[List[T]], 
    field_name: str,
    item_type: Optional[Type[T]] = None,
    min_items: Optional[int] = None,
    max_items: Optional[int] = None,
    unique: bool = False
) -> List[T]:
    """
    Validate a list value.
    
    Args:
        value: List to validate
        field_name: Name of the field
        item_type: Expected type of items
        min_items: Minimum number of items
        max_items: Maximum number of items
        unique: Whether items must be unique
        
    Returns:
        Validated list (never None)
        
    Raises:
        ValidationError: If validation fails
    """
    # Convert None to empty list
    if value is None:
        return []
    
    if not isinstance(value, list):
        raise TypeValidationError(field_name, value, list)
    
    # Validate list size
    if min_items is not None and len(value) < min_items:
        raise RangeValidationError(field_name, len(value), min_value=min_items)
    
    if max_items is not None and len(value) > max_items:
        raise RangeValidationError(field_name, len(value), max_value=max_items)
    
    # Validate item types
    if item_type is not None:
        for i, item in enumerate(value):
            if not isinstance(item, item_type):
                raise TypeValidationError(
                    f"{field_name}[{i}]", 
                    item, 
                    item_type
                )
    
    # Check uniqueness
    if unique and len(value) != len(set(value)):
        raise ConstraintValidationError(field_name, value, "Items must be unique")
    
    return value


def validate_dict(
    value: Optional[Dict[str, Any]], 
    field_name: str,
    required_keys: Optional[List[str]] = None,
    allowed_keys: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validate a dictionary value.
    
    Args:
        value: Dictionary to validate
        field_name: Name of the field
        required_keys: Keys that must be present
        allowed_keys: Only these keys are allowed
        
    Returns:
        Validated dictionary (never None)
        
    Raises:
        ValidationError: If validation fails
    """
    # Convert None to empty dict
    if value is None:
        return {}
    
    if not isinstance(value, dict):
        raise TypeValidationError(field_name, value, dict)
    
    # Check required keys
    if required_keys:
        missing_keys = set(required_keys) - set(value.keys())
        if missing_keys:
            raise ConstraintValidationError(
                field_name, 
                value, 
                f"Missing required keys: {', '.join(missing_keys)}"
            )
    
    # Check allowed keys
    if allowed_keys:
        extra_keys = set(value.keys()) - set(allowed_keys)
        if extra_keys:
            raise ConstraintValidationError(
                field_name, 
                value, 
                f"Unknown keys: {', '.join(extra_keys)}"
            )
    
    return value


def validate_number(
    value: Optional[Union[int, float]], 
    field_name: str,
    required: bool = True,
    min_value: Optional[Union[int, float]] = None,
    max_value: Optional[Union[int, float]] = None,
    allow_float: bool = True
) -> Optional[Union[int, float]]:
    """
    Validate a numeric value.
    
    Args:
        value: Number to validate
        field_name: Name of the field
        required: Whether the field is required
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        allow_float: Whether to allow float values
        
    Returns:
        Validated number or None
        
    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        if required:
            raise RequiredFieldError(field_name)
        return None
    
    if allow_float:
        if not isinstance(value, (int, float)):
            raise TypeValidationError(
                field_name, 
                value, 
                "number (int or float)"
            )
    else:
        if not isinstance(value, int):
            raise TypeValidationError(
                field_name, 
                value, 
                int
            )
    
    if min_value is not None and value < min_value:
        raise RangeValidationError(field_name, value, min_value=min_value)
    
    if max_value is not None and value > max_value:
        raise RangeValidationError(field_name, value, max_value=max_value)
    
    return value


def validate_datetime(
    value: Optional[datetime], 
    field_name: str,
    required: bool = True,
    future_only: bool = False,
    past_only: bool = False
) -> Optional[datetime]:
    """
    Validate a datetime value.
    
    Args:
        value: Datetime to validate
        field_name: Name of the field
        required: Whether the field is required
        future_only: Only allow future dates
        past_only: Only allow past dates
        
    Returns:
        Validated datetime or None
        
    Raises:
        ValidationError: If validation fails
    """
    if value is None:
        if required:
            raise RequiredFieldError(field_name)
        return None
    
    if not isinstance(value, datetime):
        raise TypeValidationError(
            field_name, 
            value, 
            datetime
        )
    
    now = datetime.utcnow()
    
    if future_only and value <= now:
        raise ConstraintValidationError(field_name, value, "Must be in the future")
    
    if past_only and value >= now:
        raise ConstraintValidationError(field_name, value, "Must be in the past")
    
    return value


def validate_deadline_hours(
    hours: Optional[float], 
    field_name: str = "deadline_hours"
) -> Optional[datetime]:
    """
    Validate deadline hours and convert to datetime.
    
    Args:
        hours: Number of hours until deadline
        field_name: Name of the field
        
    Returns:
        Datetime representing the deadline or None
        
    Raises:
        ValidationError: If validation fails
    """
    if hours is None:
        return None
    
    validated_hours = validate_number(
        hours, 
        field_name, 
        required=False, 
        min_value=0.1, 
        max_value=168  # Max 1 week
    )
    
    if validated_hours is not None:
        return datetime.utcnow() + timedelta(hours=validated_hours)
    
    return None


def validate_query_parameters(
    title: str,
    content: str,
    requester: str,
    query_type: Optional[QueryType] = None,
    priority: Optional[QueryPriority] = None,
    context: Optional[Dict[str, Any]] = None,
    constraints: Optional[List[str]] = None,
    deadline_hours: Optional[float] = None,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validate all parameters for creating a query.
    
    Returns:
        Dictionary of validated parameters
    """
    return {
        "title": validate_string(title, "title", required=True, min_length=1, max_length=200),
        "content": validate_string(content, "content", required=True, min_length=10, max_length=10000),
        "requester": validate_string(requester, "requester", required=True, min_length=1),
        "query_type": validate_enum(query_type, "query_type", QueryType, required=False) or QueryType.GENERAL,
        "priority": validate_enum(priority, "priority", QueryPriority, required=False) or QueryPriority.MEDIUM,
        "context": validate_dict(context, "context"),
        "constraints": validate_list(constraints, "constraints", item_type=str),
        "deadline": validate_deadline_hours(deadline_hours),
        "tags": validate_list(tags, "tags", item_type=str, unique=True)
    }


def validate_response_collection_parameters(
    query_id: str,
    timeout: float = 300.0,
    min_responses: int = 1,
    required_experts: Optional[List[ExpertType]] = None
) -> Dict[str, Any]:
    """
    Validate parameters for response collection.
    
    Returns:
        Dictionary of validated parameters
    """
    return {
        "query_id": validate_string(query_id, "query_id", required=True),
        "timeout": validate_number(timeout, "timeout", min_value=1.0, max_value=3600.0),
        "min_responses": validate_number(min_responses, "min_responses", min_value=0, max_value=20, allow_float=False),
        "required_experts": validate_list(required_experts, "required_experts", item_type=ExpertType)
    }