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