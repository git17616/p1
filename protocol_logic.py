# protocol_logic.py
# Medical Emergency Access Protocol - Modular Benchmarking Logic
# Participants: Patient, Proxy, TT (Trusted Third Party), Doctor

from charm.toolbox.pairinggroup import PairingGroup, G1, GT, ZR, pair
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from hashlib import sha256
import hashlib
import time


class MedicalProtocol:
    def __init__(self):
        self.group = PairingGroup('SS512')

        # Fixed system parameters (deterministic across all runs)
        self.g = self.group.hash("fixed generator", G1)
        self.alpha = self.group.hash(
            "fixed-alpha value is storedfixe-alpha value is stored", ZR
        )
        self.g_alpha = self.g ** self.alpha
        self.hthumb = self.group.hash("hthumb-constant", ZR)

    # ------------------------------------------------------------------
    # Identity / Key helpers
    # ------------------------------------------------------------------

    def derive_identity_keys(self, identity: str):
        """Return (pk_id, sk_id) for a given identity string."""
        pk_id = self.group.hash(identity, G1)
        sk_id = pk_id ** self.alpha
        return pk_id, sk_id

    def derive_patient_y(self, id_p: str) -> object:
        """Derive the patient's private scalar y from identity."""
        combined = sha256(
            self.group.serialize(self.hthumb) + id_p.encode()
        ).digest()
        alpha_bytes = self.group.serialize(self.alpha)
        return self.group.hash(alpha_bytes + combined, ZR)

    # ------------------------------------------------------------------
    # Phase R1 – Patient → Proxy  (medical ciphertext package)
    # Returns: (package_dict, timing_ms)
    # ------------------------------------------------------------------

    def generate_patient_cipher(
        self,
        id_p: str,
        id_pr: str,
        medical_data: bytes,
        aes_key: bytes,
        aes_nonce: bytes,
        aes_ciphertext: bytes,
    ):
        t0 = time.perf_counter()

        pk_idp, sk_idp = self.derive_identity_keys(id_p)
        pk_idpr, _ = self.derive_identity_keys(id_pr)
        y = self.derive_patient_y(id_p)

        lamda = self.group.random(GT)
        lambda_bytes = self.group.serialize(lamda)
        v1 = self.group.hash(medical_data + lambda_bytes, ZR)

        C1 = self.g ** y
        C2 = self.g ** v1
        C3 = lamda * pair(
            self.g ** self.alpha,
            (pk_idp ** y) * (pk_idpr ** (v1 * self.hthumb)),
        )

        h = sha256(lambda_bytes).digest()
        h_full = (h * (len(aes_ciphertext) // len(h) + 1))[: len(aes_ciphertext)]
        C4 = bytes(a ^ b for a, b in zip(aes_ciphertext, h_full))

        C5 = self.group.init(ZR, 0)

        data = (
            id_pr.encode()
            + self.group.serialize(C1)
            + self.group.serialize(C2)
            + self.group.serialize(C3)
            + C4
            + self.group.serialize(C5)
        )
        H = self.group.hash(data, G1)
        S1 = H ** v1

        elapsed_ms = (time.perf_counter() - t0) * 1000

        package = {
            "C1": C1, "C2": C2, "C3": C3, "C4": C4, "C5": C5, "S1": S1,
            # carry-along for downstream phases
            "lamda": lamda, "v1": v1, "y": y,
            "aes_nonce": aes_nonce,
        }
        return package, elapsed_ms

    # ------------------------------------------------------------------
    # Phase R2 – Patient → TT  (AES key package)
    # Returns: (package_dict, timing_ms)
    # ------------------------------------------------------------------

    def generate_tt_cipher(
        self,
        id_p: str,
        id_TT: str,
        aes_key: bytes,
        y,          # reuse same y from R1 for consistency
    ):
        t0 = time.perf_counter()

        pk_idp, _ = self.derive_identity_keys(id_p)
        pk_idTT, _ = self.derive_identity_keys(id_TT)

        row = self.group.random(GT)
        row_bytes = self.group.serialize(row)
        r1 = self.group.hash(aes_key + row_bytes, ZR)

        C1kp = self.g ** y
        C2kp = self.g ** r1
        C3kp = row * pair(
            self.g ** self.alpha,
            (pk_idp ** y) * (pk_idTT ** (r1 * self.hthumb)),
        )

        hashrow = sha256(row_bytes).digest()
        hrow_full = (hashrow * (len(aes_key) // len(hashrow) + 1))[: len(aes_key)]
        C4kp = bytes(a ^ b for a, b in zip(aes_key, hrow_full))

        C5kp = self.group.init(ZR, 1)

        data = (
            id_TT.encode()
            + self.group.serialize(C1kp)
            + self.group.serialize(C2kp)
            + self.group.serialize(C3kp)
            + C4kp
            + self.group.serialize(C5kp)
        )
        H2 = self.group.hash(data, G1)
        S2 = H2 ** r1

        elapsed_ms = (time.perf_counter() - t0) * 1000

        package = {
            "C1kp": C1kp, "C2kp": C2kp, "C3kp": C3kp,
            "C4kp": C4kp, "C5kp": C5kp, "S2": S2,
            "row": row, "r1": r1,
        }
        return package, elapsed_ms

    # ------------------------------------------------------------------
    # Phase Proxy Re-Encryption – TT→Proxy→Doctor  (cipher transform)
    # Returns: (package_dict, timing_ms)
    # ------------------------------------------------------------------

    def proxy_reencrypt_for_doctor(
        self,
        id_p: str,
        id_pr: str,
        id_D: str,
        r1_pkg,     # R1 package from generate_patient_cipher
        y,          # patient scalar y
        yD,         # doctor ephemeral scalar (generated by TT)
        r,          # TT ephemeral scalar
        A,          # TT random GT element
    ):
        t0 = time.perf_counter()

        pk_idp, sk_idp = self.derive_identity_keys(id_p)
        _, sk_idpr = self.derive_identity_keys(id_pr)
        pk_idD, _ = self.derive_identity_keys(id_D)

        C1 = r1_pkg["C1"]
        C2 = r1_pkg["C2"]
        C3 = r1_pkg["C3"]
        C4 = r1_pkg["C4"]
        C5 = r1_pkg["C5"]

        # TT message to Proxy
        HashA = self.group.hash(A, G1)
        R1 = C1
        R2 = self.g ** r
        R3 = pair(self.g ** (self.alpha * yD), pk_idD ** r) * A
        R4 = pair(self.g ** y, sk_idp * HashA)
        R5 = self.group.init(ZR, 1)

        data1 = (
            id_D.encode()
            + self.group.serialize(R1)
            + self.group.serialize(R2)
            + self.group.serialize(R3)
            + self.group.serialize(R4)
            + self.group.serialize(R5)
        )
        H1 = self.group.hash(data1, G1)
        SR1 = H1 ** (r * self.hthumb)

        # Proxy verifies TT message
        SR1p = H1 ** self.hthumb
        assert pair(self.g, SR1) == pair(R2, SR1p), "Proxy: TT message verification failed"

        # Proxy re-encrypts
        N = self.group.random(GT)
        k_full = hashlib.shake_256(self.group.serialize(N)).digest(len(C4))
        C4new = bytes(a ^ b for a, b in zip(C4, k_full))

        C3new = C3 / (R4 * pair(C2, sk_idpr ** self.hthumb))

        N_bytes = self.group.serialize(N)
        digest = sha256(N_bytes).digest()
        N_zr = self.group.hash(digest, ZR)

        data11 = (
            id_D.encode()
            + self.group.serialize(C1)
            + self.group.serialize(C2)
            + self.group.serialize(C3new)
            + C4new
            + self.group.serialize(C5)
            + self.group.serialize(R2)
            + self.group.serialize(R3)
        )
        H11 = self.group.hash(data11, G1)
        S1new = H11 ** N_zr

        elapsed_ms = (time.perf_counter() - t0) * 1000

        package = {
            "C1": C1, "C2": C2, "C3new": C3new, "C4new": C4new,
            "C5": C5, "S1new": S1new, "R2": R2, "R3": R3,
            "N": N, "N_zr": N_zr,
        }
        return package, elapsed_ms

    # ------------------------------------------------------------------
    # Phase TT Re-Encryption – TT→Doctor  (key transform)
    # Returns: (package_dict, timing_ms)
    # ------------------------------------------------------------------

    def tt_reencrypt_key_for_doctor(
        self,
        id_p: str,
        id_TT: str,
        id_D: str,
        r2_pkg,     # R2 package from generate_tt_cipher
        y,          # patient scalar y
        yD,         # doctor ephemeral scalar
    ):
        t0 = time.perf_counter()

        pk_idp, sk_idp = self.derive_identity_keys(id_p)
        _, sk_idTT = self.derive_identity_keys(id_TT)
        pk_idD, _ = self.derive_identity_keys(id_D)

        C1kp = r2_pkg["C1kp"]
        C2kp = r2_pkg["C2kp"]
        C3kp = r2_pkg["C3kp"]
        C4kp = r2_pkg["C4kp"]
        C5kp = r2_pkg["C5kp"]

        rdash = self.group.random(ZR)
        B = self.group.random(GT)
        HashB = self.group.hash(B, G1)
        R2dash = self.g ** rdash
        R3dash = pair(self.g ** (self.alpha * yD), pk_idD ** rdash) * B
        R4dash = pair(self.g ** y, sk_idp * HashB)

        C3kpnew = C3kp / (R4dash * pair(C2kp, sk_idTT ** self.hthumb))

        datap33 = (
            id_D.encode()
            + self.group.serialize(C1kp)
            + self.group.serialize(C2kp)
            + self.group.serialize(C3kpnew)
            + C4kp
            + self.group.serialize(C5kp)
            + self.group.serialize(R2dash)
            + self.group.serialize(R3dash)
        )
        Hp33 = self.group.hash(datap33, G1)
        S2new = Hp33 ** self.hthumb

        elapsed_ms = (time.perf_counter() - t0) * 1000

        package = {
            "C1kp": C1kp, "C2kp": C2kp, "C3kpnew": C3kpnew,
            "C4kp": C4kp, "C5kp": C5kp, "S2new": S2new,
            "R2dash": R2dash, "R3dash": R3dash, "B": B,
        }
        return package, elapsed_ms

    # ------------------------------------------------------------------
    # Doctor: recover re-encrypted cipher (verify + recover lambda)
    # Returns: (result_dict, timing_ms)  – partial, feeds doctor_decrypt
    # ------------------------------------------------------------------

    def doctor_recover_cipher(
        self,
        id_D: str,
        proxy_pkg,  # from proxy_reencrypt_for_doctor
        yD,
    ):
        t0 = time.perf_counter()

        _, sk_idD = self.derive_identity_keys(id_D)

        C1 = proxy_pkg["C1"]
        C2 = proxy_pkg["C2"]
        C3new = proxy_pkg["C3new"]
        C4new = proxy_pkg["C4new"]
        C5 = proxy_pkg["C5"]
        S1new = proxy_pkg["S1new"]
        R2 = proxy_pkg["R2"]
        R3 = proxy_pkg["R3"]
        N = proxy_pkg["N"]
        N_zr = proxy_pkg["N_zr"]

        # Verify S1new
        datap1 = (
            id_D.encode()
            + self.group.serialize(C1)
            + self.group.serialize(C2)
            + self.group.serialize(C3new)
            + C4new
            + self.group.serialize(C5)
            + self.group.serialize(R2)
            + self.group.serialize(R3)
        )
        Hp1 = self.group.hash(datap1, G1)
        S1newp = Hp1 ** N_zr
        assert S1newp == S1new, "Doctor: S1new verification failed"

        # Recover lambda
        Anew = R3 / pair(R2 ** yD, sk_idD)
        HashAnew = self.group.hash(Anew, G1)
        lamdanew = C3new * pair(C1, HashAnew)

        # Recover AES ciphertext
        k_full1 = hashlib.shake_256(self.group.serialize(N)).digest(len(C4new))
        resultci = bytes(a ^ b for a, b in zip(C4new, k_full1))

        lambdanew_bytes = self.group.serialize(lamdanew)
        h1 = sha256(lambdanew_bytes).digest()
        h_full22 = (h1 * (len(resultci) // len(h1) + 1))[: len(resultci)]
        recovered_ciphertext = bytes(a ^ b for a, b in zip(resultci, h_full22))

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return {
            "lamdanew": lamdanew,
            "recovered_ciphertext": recovered_ciphertext,
        }, elapsed_ms

    # ------------------------------------------------------------------
    # Doctor: recover AES key from TT re-encrypted key package
    # Returns: (result_dict, timing_ms)
    # ------------------------------------------------------------------

    def doctor_recover_key(
        self,
        id_D: str,
        tt_pkg,     # from tt_reencrypt_key_for_doctor
        yD,
    ):
        t0 = time.perf_counter()

        _, sk_idD = self.derive_identity_keys(id_D)

        C1kp = tt_pkg["C1kp"]
        C2kp = tt_pkg["C2kp"]
        C3kpnew = tt_pkg["C3kpnew"]
        C4kp = tt_pkg["C4kp"]
        C5kp = tt_pkg["C5kp"]
        S2new = tt_pkg["S2new"]
        R2dash = tt_pkg["R2dash"]
        R3dash = tt_pkg["R3dash"]

        # Verify S2new
        datap34 = (
            id_D.encode()
            + self.group.serialize(C1kp)
            + self.group.serialize(C2kp)
            + self.group.serialize(C3kpnew)
            + C4kp
            + self.group.serialize(C5kp)
            + self.group.serialize(R2dash)
            + self.group.serialize(R3dash)
        )
        Hp34 = self.group.hash(datap34, G1)
        S2new34 = Hp34 ** self.hthumb
        assert S2new34 == S2new, "Doctor: S2new verification failed"

        # Recover row
        Bnew = R3dash / pair(R2dash ** yD, sk_idD)
        HashBnew = self.group.hash(Bnew, G1)
        rownew = C3kpnew * pair(C1kp, HashBnew)

        # Recover AES key
        rownew_bytes = self.group.serialize(rownew)
        hashrow = sha256(rownew_bytes).digest()
        hrow_full = (hashrow * (len(C4kp) // len(hashrow) + 1))[: len(C4kp)]
        recovered_key = bytes(a ^ b for a, b in zip(C4kp, hrow_full))

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return {"recovered_key": recovered_key}, elapsed_ms

    # ------------------------------------------------------------------
    # Doctor: final AES decryption of medical data
    # Returns: (plaintext_bytes, timing_ms)
    # ------------------------------------------------------------------

    def doctor_decrypt_medical_data(
        self,
        recovered_key: bytes,
        recovered_ciphertext: bytes,
        aes_nonce: bytes,
    ):
        t0 = time.perf_counter()
        cipher_dec = AES.new(recovered_key, AES.MODE_EAX, nonce=aes_nonce)
        plaintext = cipher_dec.decrypt(recovered_ciphertext)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return plaintext, elapsed_ms

    # ------------------------------------------------------------------
    # Convenience: run the full protocol end-to-end and return all timings
    # ------------------------------------------------------------------

    def run_full_protocol(
        self,
        id_p: str = "patient@example.com",
        id_pr: str = "proxy@example.com",
        id_TT: str = "TT@example.com",
        id_D: str = "Doctor@example.com",
        medical_data: bytes = b"aes medical data This is my medical data1",
    ):
        # AES encrypt medical data
        aes_key = get_random_bytes(32)
        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        aes_ciphertext, _ = aes_cipher.encrypt_and_digest(medical_data)
        aes_nonce = aes_cipher.nonce

        # Derive patient y once (shared across R1 and R2)
        y = self.derive_patient_y(id_p)

        # TT ephemeral values (generated once per emergency session)
        yD = self.group.random(ZR)
        r = self.group.random(ZR)
        A = self.group.random(GT)

        # Phase R1
        r1_pkg, t_r1 = self.generate_patient_cipher(
            id_p, id_pr, medical_data, aes_key, aes_nonce, aes_ciphertext
        )

        # Phase R2
        r2_pkg, t_r2 = self.generate_tt_cipher(id_p, id_TT, aes_key, y)

        # Phase Proxy Re-Encryption
        proxy_pkg, t_proxy = self.proxy_reencrypt_for_doctor(
            id_p, id_pr, id_D, r1_pkg, y, yD, r, A
        )

        # Phase TT Re-Encryption
        tt_pkg, t_tt = self.tt_reencrypt_key_for_doctor(
            id_p, id_TT, id_D, r2_pkg, y, yD
        )

        # Doctor Recovery (cipher + key + decrypt)
        t_doc_start = time.perf_counter()
        cipher_result, _ = self.doctor_recover_cipher(id_D, proxy_pkg, yD)
        key_result, _ = self.doctor_recover_key(id_D, tt_pkg, yD)
        plaintext, _ = self.doctor_decrypt_medical_data(
            key_result["recovered_key"],
            cipher_result["recovered_ciphertext"],
            r1_pkg["aes_nonce"],
        )
        t_doctor = (time.perf_counter() - t_doc_start) * 1000

        assert plaintext == medical_data, "Protocol FAILED: recovered data does not match original"

        return {
            "r1_ms": t_r1,
            "r2_ms": t_r2,
            "proxy_ms": t_proxy,
            "tt_ms": t_tt,
            "doctor_ms": t_doctor,
            "success": True,
        }
