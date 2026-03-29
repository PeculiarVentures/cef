"""CEF Python SDK test suite."""

import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cef import (
    encrypt, decrypt, verify,
    FileInput, Sender, Recipient, DecryptResult,
)
from cef.container import (
    SenderClaims, Manifest, SenderInfo, RecipientRef, FileMetadata,
    Container, marshal_manifest, unmarshal_manifest, write_container,
    read_container, random_file_name, sanitize_filename,
    FORMAT_VERSION, HASH_ALG_SHA256,
)
from cef import cose, crypto, pq


# ── Crypto layer ──────────────────────────────────────────────────

class TestCrypto(unittest.TestCase):
    def test_aes_gcm_round_trip(self):
        key, iv = os.urandom(32), os.urandom(12)
        ct = crypto.aes_gcm_encrypt(key, iv, b"hello", b"aad")
        pt = crypto.aes_gcm_decrypt(key, iv, ct, b"aad")
        self.assertEqual(pt, b"hello")

    def test_aes_gcm_wrong_key(self):
        key, iv = os.urandom(32), os.urandom(12)
        ct = crypto.aes_gcm_encrypt(key, iv, b"x", b"")
        with self.assertRaises(Exception):
            crypto.aes_gcm_decrypt(os.urandom(32), iv, ct, b"")

    def test_aes_kw_round_trip(self):
        kek, pt = os.urandom(32), os.urandom(32)
        wrapped = crypto.aes_kw_wrap(kek, pt)
        self.assertEqual(crypto.aes_kw_unwrap(kek, wrapped), pt)

    def test_hkdf_rfc5869_tc1(self):
        ikm = bytes([0x0b] * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        okm = crypto.hkdf_sha256(ikm, salt, info, 42)
        self.assertEqual(
            okm.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

    def test_hkdf_cef_domain_vector(self):
        ss = bytes(range(32))
        kek = crypto.hkdf_sha256(ss, b"", b"CEF-ML-KEM-768-A256KW", 32)
        self.assertEqual(
            kek.hex(),
            "d838a93b048320e5974e7bc3ff9c0c4f9979f0897ffdc88ac749d6010ce488a5",
        )

    def test_constant_time_compare(self):
        self.assertTrue(crypto.constant_time_compare(b"abc", b"abc"))
        self.assertFalse(crypto.constant_time_compare(b"abc", b"xyz"))


# ── PQ layer ──────────────────────────────────────────────────────

class TestPQ(unittest.TestCase):
    def test_mlkem_round_trip(self):
        kp = pq.mlkem_keygen()
        cek = os.urandom(32)
        wrapped = pq.mlkem_wrap(kp.public_key, cek)
        self.assertEqual(pq.mlkem_unwrap(kp.secret_key, wrapped), cek)

    def test_mlkem_wrong_key(self):
        k1, k2 = pq.mlkem_keygen(), pq.mlkem_keygen()
        cek = os.urandom(32)
        wrapped = pq.mlkem_wrap(k1.public_key, cek)
        with self.assertRaises(Exception):
            pq.mlkem_unwrap(k2.secret_key, wrapped)

    def test_mldsa_sign_verify(self):
        kp = pq.mldsa_keygen()
        sig = pq.mldsa_sign(kp.secret_key, b"test")
        pq.mldsa_verify(kp.public_key, b"test", sig)

    def test_mldsa_wrong_key(self):
        k1, k2 = pq.mldsa_keygen(), pq.mldsa_keygen()
        sig = pq.mldsa_sign(k1.secret_key, b"x")
        with self.assertRaises(Exception):
            pq.mldsa_verify(k2.public_key, b"x", sig)

    def test_key_sizes(self):
        kem = pq.mlkem_keygen()
        dsa = pq.mldsa_keygen()
        self.assertEqual(len(kem.public_key), 1184)
        self.assertEqual(len(kem.secret_key), 2400)
        self.assertEqual(len(dsa.public_key), 1952)
        self.assertEqual(len(dsa.secret_key), 4032)


# ── COSE layer ────────────────────────────────────────────────────

class TestCOSE(unittest.TestCase):
    def _passthrough_wrap(self, cek, _ri):
        return cek

    def _passthrough_unwrap(self, wrapped, _r):
        return wrapped

    def test_encrypt_decrypt_round_trip(self):
        ri = cose.RecipientInfo(key_id="test", algorithm=-1)
        msg = cose.encrypt(b"hello", [ri], self._passthrough_wrap)
        pt = cose.decrypt(msg, 0, self._passthrough_unwrap)
        self.assertEqual(pt, b"hello")

    def test_marshal_unmarshal(self):
        ri = cose.RecipientInfo(key_id="kid1", algorithm=-1, recipient_type="key")
        msg = cose.encrypt(b"data", [ri], self._passthrough_wrap)
        data = cose.marshal_encrypt(msg)
        msg2 = cose.unmarshal_encrypt(data)
        self.assertEqual(msg.ciphertext, msg2.ciphertext)
        self.assertEqual(len(msg.recipients), len(msg2.recipients))

    def test_find_recipient_index(self):
        ris = [cose.RecipientInfo(key_id="a", algorithm=-1),
               cose.RecipientInfo(key_id="b", algorithm=-1)]
        msg = cose.encrypt(b"x", ris, self._passthrough_wrap)
        self.assertEqual(cose.find_recipient_index(msg, "a"), 0)
        self.assertEqual(cose.find_recipient_index(msg, "b"), 1)
        with self.assertRaises(ValueError):
            cose.find_recipient_index(msg, "eve")

    def test_no_recipients(self):
        with self.assertRaises(ValueError):
            cose.encrypt(b"x", [], self._passthrough_wrap)

    def test_wrong_tag_rejected(self):
        import cbor2
        data = cbor2.dumps(cbor2.CBORTag(99, [b"", {}, b"", []]))
        with self.assertRaises(ValueError):
            cose.unmarshal_encrypt(data)

    def test_sign1_round_trip(self):
        sign_fn = lambda d: d[:32]
        verify_fn = lambda d, s: None if d[:32] == s else (_ for _ in ()).throw(ValueError("bad"))
        msg = cose.sign1(-49, "sender", b"payload", False, sign_fn)
        cose.verify1(msg, None, verify_fn)

    def test_sign1_detached(self):
        sign_fn = lambda d: d[:32]
        verify_fn = lambda d, s: None if d[:32] == s else (_ for _ in ()).throw(ValueError("bad"))
        msg = cose.sign1(-49, "sender", b"detached", True, sign_fn)
        self.assertIsNone(msg.payload)
        cose.verify1(msg, b"detached", verify_fn)

    def test_sign1_marshal_unmarshal(self):
        sign_fn = lambda _: b"\x01\x02\x03"
        msg = cose.sign1(-49, "kid", b"payload", False, sign_fn)
        data = cose.marshal_sign1(msg)
        msg2 = cose.unmarshal_sign1(data)
        self.assertEqual(msg.signature, msg2.signature)

    def test_empty_payload(self):
        ri = cose.RecipientInfo(key_id="t", algorithm=-1)
        msg = cose.encrypt(b"", [ri], self._passthrough_wrap)
        pt = cose.decrypt(msg, 0, self._passthrough_unwrap)
        self.assertEqual(pt, b"")

    def test_recipient_type_preserved(self):
        ri = cose.RecipientInfo(key_id="t", algorithm=-1, recipient_type="email")
        msg = cose.encrypt(b"x", [ri], self._passthrough_wrap)
        data = cose.marshal_encrypt(msg)
        msg2 = cose.unmarshal_encrypt(data)
        self.assertEqual(msg2.recipients[0].unprotected[cose.HEADER_CEF_RECIPIENT_TYPE], "email")


# ── Container layer ───────────────────────────────────────────────

class TestContainer(unittest.TestCase):
    def test_manifest_cbor_round_trip(self):
        m = Manifest(
            version=FORMAT_VERSION,
            sender=SenderInfo(kid="alice", claims=SenderClaims(
                email="alice@example.com", classification="SECRET"
            )),
            recipients=[RecipientRef(kid="bob", recipient_type="key")],
            files={"x.cose": FileMetadata(
                original_name="test.pdf", hash=b"\x01\x02\x03",
                hash_algorithm=HASH_ALG_SHA256, size=1024,
            )},
        )
        data = marshal_manifest(m)
        m2 = unmarshal_manifest(data)
        self.assertEqual(m2.version, "0")
        self.assertEqual(m2.sender.kid, "alice")
        self.assertEqual(m2.sender.claims.classification, "SECRET")
        self.assertEqual(m2.recipients[0].kid, "bob")

    def test_manifest_rejects_wrong_version(self):
        m = Manifest(version="99", sender=SenderInfo(kid="a"),
                     recipients=[], files={})
        data = marshal_manifest(m)
        with self.assertRaises(ValueError):
            unmarshal_manifest(data)

    def test_zip_round_trip(self):
        c = Container(encrypted_manifest=b"manifest", manifest_signature=b"sig",
                       encrypted_files={"f1.cose": b"enc1", "f2.cose": b"enc2"})
        data = write_container(c)
        c2 = read_container(data)
        self.assertEqual(c2.encrypted_manifest, b"manifest")
        self.assertEqual(c2.manifest_signature, b"sig")
        self.assertEqual(len(c2.encrypted_files), 2)

    def test_random_file_name_unique(self):
        a, b = random_file_name(), random_file_name()
        self.assertNotEqual(a, b)
        self.assertTrue(a.endswith(".cose"))

    def test_handling_marks_round_trip(self):
        m = Manifest(
            version=FORMAT_VERSION,
            sender=SenderInfo(kid="a", claims=SenderClaims(
                classification="TOP SECRET", releasability="REL TO USA, FVEY"
            )),
            recipients=[], files={"x.cose": FileMetadata(
                original_name="d.txt", hash=b"", hash_algorithm=HASH_ALG_SHA256, size=0
            )},
        )
        data = marshal_manifest(m)
        m2 = unmarshal_manifest(data)
        self.assertEqual(m2.sender.claims.classification, "TOP SECRET")
        self.assertEqual(m2.sender.claims.releasability, "REL TO USA, FVEY")

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("../../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\windows\\system32"), "system32")
        self.assertEqual(sanitize_filename("normal.txt"), "normal.txt")
        self.assertEqual(sanitize_filename(".."), "unnamed")
        self.assertEqual(sanitize_filename(""), "unnamed")


# ── Workflow layer ────────────────────────────────────────────────

class TestWorkflow(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("hello.txt", b"hello world")],
            sender=Sender(signing_key=sender.secret_key, kid="alice"),
            recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
        )
        self.assertTrue(result.signed)
        dec = decrypt(result.container, "bob", recip.secret_key,
                      verify_key=sender.public_key)
        self.assertEqual(dec.files[0].original_name, "hello.txt")
        self.assertEqual(dec.files[0].data, b"hello world")
        self.assertTrue(dec.signature_valid)

    def test_multiple_files(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("a.txt", b"aaa"), FileInput("b.txt", b"bbb")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "b", recip.secret_key,
                      verify_key=sender.public_key)
        names = {f.original_name for f in dec.files}
        self.assertEqual(names, {"a.txt", "b.txt"})

    def test_multiple_recipients(self):
        sender = pq.mldsa_keygen()
        bob, carol = pq.mlkem_keygen(), pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"multi")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[
                Recipient(kid="bob", encryption_key=bob.public_key),
                Recipient(kid="carol", encryption_key=carol.public_key),
            ],
        )
        d1 = decrypt(result.container, "bob", bob.secret_key, verify_key=sender.public_key)
        d2 = decrypt(result.container, "carol", carol.secret_key, verify_key=sender.public_key)
        self.assertEqual(d1.files[0].data, b"multi")
        self.assertEqual(d2.files[0].data, b"multi")

    def test_sender_claims(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(
                signing_key=sender.secret_key, kid="alice",
                claims=SenderClaims(email="a@b.com", name="Alice", classification="SECRET"),
            ),
            recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "bob", recip.secret_key, verify_key=sender.public_key)
        self.assertEqual(dec.sender_claims.email, "a@b.com")
        self.assertEqual(dec.sender_claims.classification, "SECRET")
        self.assertIsNotNone(dec.created_at)

    def test_skip_signature_verification(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"data")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "b", recip.secret_key,
                      skip_signature_verification=True)
        self.assertEqual(dec.files[0].data, b"data")
        self.assertIsNone(dec.signature_valid)

    def test_decrypt_requires_verify_key_when_signed(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        with self.assertRaises(ValueError) as ctx:
            decrypt(result.container, "b", recip.secret_key)
        self.assertIn("verification key required", str(ctx.exception))

    def test_decrypt_wrong_key(self):
        sender = pq.mldsa_keygen()
        bob, eve = pq.mlkem_keygen(), pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"secret")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="bob", encryption_key=bob.public_key)],
        )
        with self.assertRaises(Exception):
            decrypt(result.container, "bob", eve.secret_key,
                    verify_key=sender.public_key, skip_signature_verification=True)

    def test_decrypt_wrong_kid(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="bob", encryption_key=recip.public_key)],
        )
        with self.assertRaises(ValueError) as ctx:
            decrypt(result.container, "eve", recip.secret_key,
                    skip_signature_verification=True)
        self.assertIn("not found", str(ctx.exception))

    def test_verify_signature(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="alice"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        vr = verify(result.container, sender.public_key)
        self.assertTrue(vr.signature_valid)
        self.assertEqual(vr.sender_kid, "alice")

    def test_verify_wrong_key(self):
        sender = pq.mldsa_keygen()
        wrong = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        vr = verify(result.container, wrong.public_key)
        self.assertFalse(vr.signature_valid)

    def test_rejects_empty_recipients(self):
        sender = pq.mldsa_keygen()
        with self.assertRaises(ValueError):
            encrypt(files=[FileInput("t.txt", b"x")],
                    sender=Sender(signing_key=sender.secret_key, kid="a"),
                    recipients=[])

    def test_rejects_empty_files(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        with self.assertRaises(ValueError):
            encrypt(files=[],
                    sender=Sender(signing_key=sender.secret_key, kid="a"),
                    recipients=[Recipient(kid="b", encryption_key=recip.public_key)])

    def test_empty_payload(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("empty.bin", b"")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "b", recip.secret_key, verify_key=sender.public_key)
        self.assertEqual(dec.files[0].data, b"")

    def test_large_payload(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        large = bytes([0xAB] * 1_000_000)
        result = encrypt(
            files=[FileInput("big.bin", large)],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "b", recip.secret_key, verify_key=sender.public_key)
        self.assertEqual(len(dec.files[0].data), 1_000_000)

    def test_path_traversal(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("../../../etc/passwd", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        dec = decrypt(result.container, "b", recip.secret_key, verify_key=sender.public_key)
        self.assertNotIn("..", dec.files[0].original_name)
        self.assertNotIn("/", dec.files[0].original_name)

    def test_corrupted_container(self):
        sender = pq.mldsa_keygen()
        recip = pq.mlkem_keygen()
        result = encrypt(
            files=[FileInput("t.txt", b"x")],
            sender=Sender(signing_key=sender.secret_key, kid="a"),
            recipients=[Recipient(kid="b", encryption_key=recip.public_key)],
        )
        corrupted = bytearray(result.container)
        if len(corrupted) > 100:
            corrupted[50] ^= 0xFF
            corrupted[100] ^= 0xFF
        with self.assertRaises(Exception):
            decrypt(bytes(corrupted), "b", recip.secret_key,
                    skip_signature_verification=True)


if __name__ == "__main__":
    unittest.main()
