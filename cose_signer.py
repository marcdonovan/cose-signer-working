import sys
from pycose.messages import Sign1Message
from pycose.algorithms import Es256
from pycose.headers import Algorithm, KID
from pycose.keys.ec2 import EC2Key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 cose_signer.py <payload_file> <output_file>")
        sys.exit(1)

    payload_path, output_path = sys.argv[1], sys.argv[2]

    # Generate a new EC private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Save public key
    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # Prepare the COSE key
    private_numbers = private_key.private_numbers()
    public_numbers = private_key.public_key().public_numbers()
    x = public_numbers.x.to_bytes(32, "big")
    y = public_numbers.y.to_bytes(32, "big")
    d = private_numbers.private_value.to_bytes(32, "big")

    cose_key = EC2Key(crv="P_256", x=x, y=y, d=d)

    # Load payload
    with open(payload_path, "rb") as f:
        payload = f.read()

    msg = Sign1Message(
        phdr={Algorithm: Es256, KID: b"01"},
        payload=payload,
        key=cose_key,
    )

    with open(output_path, "wb") as f:
        f.write(msg.encode())

    print("✅ Signed COSE message written to:", output_path)
    print("✅ Public key written to: public_key.pem")

if __name__ == "__main__":
    main()
