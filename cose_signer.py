import sys
from pycose.messages import Sign1Message
from pycose.keys.ec2 import EC2Key
from pycose.algorithms import Es256
from pycose.headers import KID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_private_key(pkcs8_path):
    with open(pkcs8_path, "rb") as f:
        return serialization.load_der_private_key(f.read(), password=None, backend=default_backend())

def main():
    if len(sys.argv) != 4:
        print("Usage: python cose_signer.py <input_file> <output_file> <private_key.pk8>")
        sys.exit(1)

    input_file, output_file, private_key_file = sys.argv[1:4]

    with open(input_file, "rb") as f:
        payload = f.read()

    private_key = load_private_key(private_key_file)

    # Use from_cryptography_key from the latest pycose master branch
    cose_key = EC2Key.from_cryptography_key(private_key, optional_params={KID: b"01"})

    msg = Sign1Message(phdr={KID: b"01"}, payload=payload, alg=Es256)
    msg.key = cose_key

    with open(output_file, "wb") as f:
        f.write(msg.encode())

    print(f"✅ Signed {input_file} → {output_file}")

if __name__ == "__main__":
    main()
