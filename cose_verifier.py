import sys
from pycose.messages import CoseMessage
from pycose.keys.ec2 import EC2Key
from cryptography.hazmat.primitives import serialization
from pycose.keys.curves import P256

def load_public_key(pem_path):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def main():
    if len(sys.argv) != 3:
        print("Usage: python cose_verifier.py <signed_file.cose> <public_key.pem>")
        sys.exit(1)

    signed_file, public_key_file = sys.argv[1:3]

    # Load signed COSE message
    with open(signed_file, "rb") as f:
        data = f.read()

    msg = CoseMessage.decode(data)
    if msg.__class__.__name__ != "Sign1Message":
        print("❌ Not a COSE_Sign1 message.")
        sys.exit(1)

    # print(f"Decoded message class: {msg.__class__.__name__}")
    # print(f"Protected headers: {msg.phdr}")
    # print(f"Unprotected headers: {msg.uhdr}")
    # print(f"Payload (raw): {msg.payload}")

    # Load public key and convert to COSE key
    public_key = load_public_key(public_key_file)
    public_numbers = public_key.public_numbers()
    x = public_numbers.x.to_bytes(32, byteorder="big")
    y = public_numbers.y.to_bytes(32, byteorder="big")
    cose_key = EC2Key(crv=P256, x=x, y=y)

    # Assign key and verify
    msg.key = cose_key
    try:
        if msg.verify_signature():
            print("✅ Signature is valid.")
            print(f"📄 Payload:\n{msg.payload.decode('utf-8', errors='replace')}")
        else:
            print("❌ Signature verification failed.")
    except Exception as e:
        print(f"❌ Verification error: {e}")

if __name__ == "__main__":
    main()
