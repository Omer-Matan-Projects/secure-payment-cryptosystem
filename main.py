from client.input_handler import collect_payment_data
from client.payment_data import PaymentData


def main():
    print("=== Secure Payment Client ===")
    payment = collect_payment_data()

    print("\nPayment data ready for processing:")
    print(payment)

    raw_bytes = payment.to_bytes()
    print("\nSerialized bytes:")
    print(raw_bytes)


if __name__ == "__main__":
    main()