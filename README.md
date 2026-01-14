# Secure Payment Cryptosystem

A secure payment system implemented in Python, demonstrating a hybrid cryptographic protocol that combines:

- Symmetric encryption using **GOST in CTR mode**
- Secure symmetric key delivery using **RSA (PKCS#1 v1.5)**
- Message authentication and integrity using **EC El-Gamal digital signatures**
- A simple client–server interaction model with user authentication

---

## Requirements

- **Python 3.11 or higher**
- Pip (Python package manager)

---

## Setup

Install dependencies once:
```bash
pip install -r requirements.txt
```

Run the main simulation script:
```bash
python main.py
```

---

## User Authentication

Before performing a payment, the system simulates a simple user login phase.
User credentials are stored on the server side in a JSON file: `server/users.json`.
Example users provided with the project:

User | Password
---- | --------
alice | 1234
bob   | 1234
eve | 1234