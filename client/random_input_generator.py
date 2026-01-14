import random
from client.payment_data import PaymentData


def generate_random_payment(username: str) -> PaymentData:
    """
    Generates random payment data.
    """
    transaction_id = f"TX{random.randint(100000, 999999)}"
    amount = round(random.uniform(1.0, 5000.0), 2) # Amount with two decimal places, uniformly distributed between 1.0 and 5000.0
    currency = random.choice(["USD", "EUR", "ILS"])

    card_number = "".join(str(random.randint(0, 9)) for _ in range(16))

    month = random.randint(1, 12)
    year = random.randint(26, 30)
    expiry_date = f"{month:02d}/{year}"

    cvv = "".join(str(random.randint(0, 9)) for _ in range(3))

    return PaymentData(
        transaction_id=transaction_id,
        payer=username,
        amount=amount,
        currency=currency,
        card_number=card_number,
        expiry_date=expiry_date,
        cvv=cvv
    )