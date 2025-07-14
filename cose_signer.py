import sys
from pycose.messages import Sign1Message
from pycose.keys.ec2 import EC2Key
from pycose.algorithms import Es256
from pycose.headers import KID

from cryptography.hazmat.primitives import serialization

def load_private_key(pkcs8_path):
    with open(pkcs8_path, "rb") as f:
        return serialization.load_der_private_key(f.read(), password=None)

def main():
    if len(sys.argv) != 4:
        print("Usage: python cose_signer.py <input_file> <output_file> <private_key.pk8>")
        sys.exit(1)

    input_file, output_file, private_key_file = sys.argv[1:4]

    with open(input_file, "rb") as f:
        payload = f.read()

    private_key = load_private_key(private_key_file)

    # Create COSE EC2 key from cryptography private key
    cose_key = EC2Key._from_cryptography_key(private_key, optional_params={KID: b"01"})

    msg = Sign1Message(phdr={KID: b"01"}, payload=payload, alg=Es256)
    msg.key = cose_key

    encoded = msg.encode()

    with open(output_file, "wb") as f:
        f.write(encoded)

    print(f"✅ Signed {input_file} → {output_file}")

if __name__ == "__main__":
    main()
