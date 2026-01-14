from dataclasses import dataclass


@dataclass
class PaymentData:
    transaction_id: str
    payer: str
    amount: float
    currency: str
    card_number: str
    expiry_date: str
    cvv: str

    def to_bytes(self) -> bytes:
        """
        Serialize the payment data into bytes for encryption by concatenating the
        fields with a '|' delimiter and encoding the result using UTF-8, which
        converts the textual data into a deterministic byte sequence.
        """
        data_str = (
            f"{self.transaction_id}|{self.payer}|{self.amount}|{self.currency}|"
            f"{self.card_number}|{self.expiry_date}|{self.cvv}"
        )
        return data_str.encode("utf-8")

    @staticmethod
    def from_bytes(data: bytes) -> "PaymentData":
        """
        Deserialize bytes back into a PaymentData object.
        """
        decoded = data.decode("utf-8")
        fields = decoded.split("|")

        return PaymentData(
            transaction_id=fields[0],
            payer=fields[1],
            amount=float(fields[2]),
            currency=fields[3],
            card_number=fields[4],
            expiry_date=fields[5],
            cvv=fields[6]
        )