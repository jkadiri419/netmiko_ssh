from typing import Dict, List, Optional, Union
from pydantic import BaseModel, ValidationError, validator, EmailStr, conint, constr
from datetime import date
import re

class Address(BaseModel):
    street: str
    city: str
    state: constr(min_length=2, max_length=2)  # Exactly 2 letter state code
    zip_code: constr(regex=r'^\d{5}(?:[-\s]\d{4})?$')  # US zip code pattern

class ProductItem(BaseModel):
    product_id: conint(gt=0)  # Positive integer
    name: constr(min_length=1, max_length=100)
    price: float
    quantity: conint(ge=1)  # At least 1
    in_stock: bool = True

class UserOrder(BaseModel):
    """Data model for validating order dictionary input"""
    order_id: str
    customer: Dict[str, Union[str, EmailStr]]  # Name and email
    order_date: date
    shipping_address: Address  # Nested model
    products: List[ProductItem]  # List of products
    payment_method: constr(regex='^(credit|debit|paypal)$')
    discount_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @validator('order_id')
    def order_id_must_start_with_prefix(cls, v):
        if not v.startswith('ORD-'):
            raise ValueError('order_id must start with "ORD-"')
        if not v[4:].isdigit():
            raise ValueError('order_id must end with numbers')
        return v
    
    @validator('discount_code')
    def validate_discount_format(cls, v):
        if v is not None and not re.match(r'^DISC-\d{3}[A-Z]{2}$', v):
            raise ValueError('Discount code must be in format DISC-123AB')
        return v

def validate_dict_input(input_dict: Dict[str, Any]) -> Union[Dict[str, Any], List[str]]:
    """Validate dictionary input against our data model"""
    try:
        validated_data = UserOrder(**input_dict).dict()
        return validated_data
    except ValidationError as e:
        errors = [f"{err['loc'][0]}: {err['msg']}" for err in e.errors()]
        return errors

# Example usage with dictionary input
if __name__ == "__main__":
    # Valid input dictionary
    valid_order = {
        "order_id": "ORD-12345",
        "customer": {
            "name": "John Doe",
            "email": "john.doe@example.com"
        },
        "order_date": "2023-12-01",
        "shipping_address": {
            "street": "123 Main St",
            "city": "New York",
            "state": "NY",
            "zip_code": "10001"
        },
        "products": [
            {
                "product_id": 101,
                "name": "Wireless Mouse",
                "price": 29.99,
                "quantity": 2
            },
            {
                "product_id": 205,
                "name": "Keyboard",
                "price": 59.99,
                "quantity": 1,
                "in_stock": True
            }
        ],
        "payment_method": "credit",
        "discount_code": "DISC-123AB"
    }
    
    # Invalid input dictionary
    invalid_order = {
        "order_id": "INVALID123",
        "customer": {
            "name": "",
            "email": "not-an-email"
        },
        "order_date": "2023-13-01",  # Invalid date
        "shipping_address": {
            "street": "",
            "city": "A",
            "state": "New York",  # Should be 2 letters
            "zip_code": "1234"
        },
        "products": [
            {
                "product_id": 0,  # Should be > 0
                "name": "A" * 101,  # Too long
                "price": -10.99,  # Negative price
                "quantity": 0  # Should be >= 1
            }
        ],
        "payment_method": "bitcoin"  # Not allowed
    }
    
    # Test validation
    print("Valid order validation:")
    result = validate_dict_input(valid_order)
    if isinstance(result, dict):
        print("Validation passed! Clean data:")
        print(result)
    else:
        print("Validation errors:", result)
    
    print("\nInvalid order validation:")
    result = validate_dict_input(invalid_order)
    if isinstance(result, dict):
        print("Validation passed! Clean data:")
        print(result)
    else:
        print("Validation errors:")
        for error in result:
            print(f"- {error}")