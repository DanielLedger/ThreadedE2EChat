from cryptography.hazmat.primitives import hashes, hmac

import base64

from hashlib import sha256

def sign(data, key):
    if len(key) < 16:
        raise ValueError("Key must be at least 128 bits!")
    signer = hmac.HMAC(key, hashes.SHA256())
    signer.update(data)
    return signer.finalize()

while True:
    packet = input("Enter packet data to sign> ").encode("ASCII")
    packetNum = int(input("Enter the packet number.> "))
    key = input("Enter the signing key (base64 encoded)> ")
    key = base64.b64decode(key)
    packetSig = sha256(packet).digest()
    toSign = int.to_bytes(packetNum, 4, "big")
    signature = sign(toSign, key)
    print("Packet signature: " + str(base64.b64encode(signature)))