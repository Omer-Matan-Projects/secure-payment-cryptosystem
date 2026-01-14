import re


def validate_username(value: str) -> bool:
    return len(value.strip()) >= 3


def validate_password(value: str) -> bool:
    return len(value) >= 4


def validate_transaction_id(value: str) -> bool:
    return len(value.strip()) > 0


def validate_amount(value: float) -> bool:
    return value > 0


def validate_currency(value: str) -> bool:
    return value.isalpha() and len(value) == 3


def validate_card_number(value: str) -> bool:
    return value.isdigit() and len(value) == 16


def validate_expiry_date(value: str) -> bool:
    return bool(re.match(r"^(0[1-9]|1[0-2])/\d{2}$", value))


def validate_cvv(value: str) -> bool:
    return value.isdigit() and len(value) == 3