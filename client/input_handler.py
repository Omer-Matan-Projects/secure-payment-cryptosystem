from client.payment_data import PaymentData
from client import validation
from client.random_input_generator import generate_random_payment


def _prompt_until_valid(prompt: str, parse_func, validate_func):
    """
    Prompt the user until valid input is received.
    """
    while True:
        try:
            value = parse_func(input(prompt))
            if validate_func(value):
                return value
            print("Invalid input. Please try again.")
        except ValueError:
            print("Invalid format. Please try again.")


def _manual_input() -> PaymentData:
    """
    Collect payment data via manual input.
    """
    transaction_id = _prompt_until_valid(
        "Transaction ID: ",
        str,
        validation.validate_transaction_id
    )

    amount = _prompt_until_valid(
        "Amount: ",
        float,
        validation.validate_amount
    )

    currency = _prompt_until_valid(
        "Currency (3-letter code): ",
        str,
        validation.validate_currency
    )

    card_number = _prompt_until_valid(
        "Card Number (16 digits): ",
        str,
        validation.validate_card_number
    )

    expiry_date = _prompt_until_valid(
        "Expiry Date (MM/YY): ",
        str,
        validation.validate_expiry_date
    )

    cvv = _prompt_until_valid(
        "CVV (3 digits): ",
        str,
        validation.validate_cvv
    )

    return PaymentData(
        transaction_id=transaction_id,
        amount=amount,
        currency=currency.upper(),
        card_number=card_number,
        expiry_date=expiry_date,
        cvv=cvv
    )


def collect_credentials() -> tuple[str, str]:
    """
    Collect username and password from user input.
    """

    print("=== User Login ===")

    username = _prompt_until_valid(
        "Username: ",
        str,
        validation.validate_username
    )

    password = _prompt_until_valid(
        "Password: ",
        str,
        validation.validate_password
    )

    return username, password


def collect_payment_data() -> PaymentData:
    """
    Collect payment data either manually or via random generation.
    """
    print("Select input mode:")
    print("1. Manual input")
    print("2. Random valid payment generation")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        return _manual_input()
    elif choice == "2":
        print("Generating random valid payment data...")
        return generate_random_payment()
    else:
        print("Invalid choice. Please try again.\n")
        return collect_payment_data()