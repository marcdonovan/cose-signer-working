import sys
from pycose.messages.sign1message import Sign1Message
from pycose.keys.ec2 import EC2Key
from pycose.algorithms import Es256
from pycose.headers import KID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_private_key(pkcs8_path):
    with open(pkcs8_path, "rb") as f:
        return serialization.load_der_private_key(f.read(), password=None, backend=default_backend())

def main():
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key_file = sys.argv[3]

    with open(input_file, "rb") as f:
        payload = f.read()

    private_key = load_private_key(key_file)

    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers
    x = public_numbers.x.to_bytes(32, "big")
    y = public_numbers.y.to_bytes(32, "big")
    d = numbers.private_value.to_bytes(32, "big")

    cose_key = EC2Key(crv="P_256", x=x, y=y, d=d)

    msg = Sign1Message(phdr={KID: b"01"}, payload=payload)
    msg.key = cose_key
    msg.alg = Es256()

    # ✅ DIAGNOSTIC
    print("key:", type(msg.key))
    print("alg:", msg.alg)
    print("ready to encode...")

    encoded = msg.encode()
    with open(output_file, "wb") as f:
        f.write(encoded)

    print(f"✅ Signed {input_file} → {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python cose_signer_debug.py <input_file> <output_file> <key_file>")
        sys.exit(1)
    main()
