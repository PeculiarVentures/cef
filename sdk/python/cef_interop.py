#!/usr/bin/env python3
"""CEF interop helper — used by test/interop.mjs"""

import json
import sys
import base64

sys.path.insert(0, ".")
from cef import encrypt, decrypt, FileInput, Sender, Recipient
from cef.pq import mlkem_keygen, mldsa_keygen


def keygen():
    kem = mlkem_keygen()
    dsa = mldsa_keygen()
    print(kem.public_key.hex())
    print(kem.secret_key.hex())
    print(dsa.public_key.hex())
    print(dsa.secret_key.hex())


def do_encrypt(args):
    sender_sk = bytes.fromhex(args[0])
    sender_kid = args[1]
    recip_pk = bytes.fromhex(args[2])
    recip_kid = args[3]

    files_json = json.loads(sys.stdin.read())
    files = [
        FileInput(name=f["name"], data=base64.b64decode(f["data"]))
        for f in files_json
    ]

    result = encrypt(
        files=files,
        sender=Sender(signing_key=sender_sk, kid=sender_kid),
        recipients=[Recipient(kid=recip_kid, encryption_key=recip_pk)],
    )
    sys.stdout.buffer.write(result.container)


def do_decrypt(args):
    recip_sk = bytes.fromhex(args[0])
    recip_kid = args[1]
    sender_pk = bytes.fromhex(args[2])

    container = sys.stdin.buffer.read()
    result = decrypt(
        container, recip_kid, recip_sk,
        verify_key=sender_pk,
    )

    files = [
        {"name": f.original_name, "data": base64.b64encode(f.data).decode()}
        for f in result.files
    ]
    print(json.dumps(files))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "keygen":
        keygen()
    elif cmd == "encrypt":
        do_encrypt(sys.argv[2:])
    elif cmd == "decrypt":
        do_decrypt(sys.argv[2:])
    else:
        print(f"Unknown: {cmd}", file=sys.stderr)
        sys.exit(1)
