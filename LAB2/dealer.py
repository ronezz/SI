import sys, hashlib, secrets, ckzg

SHARES_FILE = "shares.txt"
DEFAULT_SETUP_PATH = "trusted_setup.txt"
FR_MOD = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
BYTES_PER_FE = 32
FIELD_ELEMENTS_PER_BLOB = 4096
PRIMITIVE_ROOT_OF_UNITY = 7

# Finite field
def fr(x): return x % FR_MOD
def int_to_fe_bytes(x): return fr(x).to_bytes(BYTES_PER_FE, "big")

# Polynomial operations 
def random_poly_with_secret(s, t):
    return [fr(s)] + [secrets.randbelow(FR_MOD) for _ in range(t)]

def poly_eval(coeffs, x):
    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % FR_MOD
    return y

# Domain evaluation → blob for KZG
def _compute_roots_of_unity(n):
    assert (FR_MOD - 1) % n == 0
    w = pow(PRIMITIVE_ROOT_OF_UNITY, (FR_MOD - 1) // n, FR_MOD)
    roots = [1]
    for _ in range(1, n):
        roots.append((roots[-1] * w) % FR_MOD)
    return roots

def _bit_reverse(seq):
    n, w = len(seq), (len(seq) - 1).bit_length()
    def rb(k): return int(f"{k:0{w}b}"[::-1], 2)
    return [seq[rb(i)] for i in range(n)]

def coeffs_to_blob(coeffs):
    domain = _compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
    evals = [poly_eval(coeffs, x) for x in domain]
    evals = _bit_reverse(evals)
    return b"".join(int_to_fe_bytes(e) for e in evals)

# Secret from input string
def secret_from_string(text):
    return int.from_bytes(hashlib.sha256(text.encode()).digest(), "big") % FR_MOD

# Write shares to file
def save_shares_txt(commitment_hex, t, rows):
    with open(SHARES_FILE, "w") as f:
        f.write(f"commitment={commitment_hex}\n")
        f.write(f"threshold={t}\n")
        for i, y, proof in rows:
            f.write(f"i={i} y=0x{y.hex()} proof=0x{proof.hex()}\n")

# Sharing...
def main():
    print("[Dealer] Sharing secret...")
    if len(sys.argv) != 4:
        print("Usage: python dealer.py N T SECRET")
        sys.exit(1)

    n = int(sys.argv[1]); t = int(sys.argv[2]); secret_text = sys.argv[3]
    assert n > t >= 0
    s = secret_from_string(secret_text)
    coeffs = random_poly_with_secret(s, t)
    setup = ckzg.load_trusted_setup(DEFAULT_SETUP_PATH, 0)
    blob = coeffs_to_blob(coeffs)

    # Commit(PK, φ(x))
    commitment = ckzg.blob_to_kzg_commitment(blob, setup)
    commitment_hex = "0x" + commitment.hex()

    rows = []
    for i in range(1, n + 1):
        z = int_to_fe_bytes(i)

        # CreateWitness(PK, φ(x), i)
        proof, y = ckzg.compute_kzg_proof(blob, z, setup)

        # VerifyEval(PK, C, i, φ(i), wi)
        if not ckzg.verify_kzg_proof(commitment, z, y, proof, setup):
            raise RuntimeError(f"Invalid proof at share {i}")

        rows.append((i, y, proof))

    save_shares_txt(commitment_hex, t, rows)
    print(f"[Dealer] {n} shares saved to {SHARES_FILE}")
    print(f"[Dealer] threshold t={t}")
    print(f"[Dealer] shared secret hash={s}")

if __name__ == "__main__":
    main()
