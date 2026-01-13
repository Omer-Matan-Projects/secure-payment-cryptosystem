from client.client import Client
from server.server import Server


def main():
    print("=== Secure Payment Protocol Demo ===")

    server = Server()
    client = Client()

    # ---- Server setup ----
    server_public_rsa = server.initialize()

    # ---- Client receives server key ----
    client.receive_server_public_key(server_public_rsa)

    # ---- Client identity ----
    client_ec_public = client.initialize_identity()

    # ---- Server registers client ----
    server.register_client_ec_key(client_ec_public)

    payment = client.collect_payment()

    package = client.prepare_payment_package(payment)
    print("\n[Main] Client -> Server: sending payment package...\n")

    print("\n[Main] Server processing package...\n")
    recovered_payment = server.process_payment_package(package)

    print("\n[Main] Payment accepted:")
    print(recovered_payment)

    print("\n=== Integrity Verification ===")

    original_bytes = payment.to_bytes()
    recovered_bytes = recovered_payment.to_bytes()

    if original_bytes == recovered_bytes:
        print("[Main] SUCCESS: Decrypted payment data matches the original.")
    else:
        print("[Main] ERROR: Decrypted payment data DOES NOT match the original!")

        print("\nOriginal payment bytes:")
        print(original_bytes.hex())

        print("\nRecovered payment bytes:")
        print(recovered_bytes.hex())


if __name__ == "__main__":
    main()