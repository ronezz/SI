import sys, ckzg

# Config
SHARES_FILE = "shares.txt"
DEFAULT_SETUP_PATH = "trusted_setup.txt"
FR_MOD = int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
BYTES_PER_FE = 32

# Field conversion helpers
def fr(x): return x % FR_MOD
def int_to_fe_bytes(x): return fr(x).to_bytes(BYTES_PER_FE, "big")
def fe_bytes_to_int(b): return int.from_bytes(b, "big") % FR_MOD

# Lagrange interpolation φ(0)
def lagrange_at_zero(points):
    s = 0
    for i, (x_i, y_i) in enumerate(points):
        num, den = 1, 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-x_j % FR_MOD)) % FR_MOD
            den = (den * ((x_i - x_j) % FR_MOD)) % FR_MOD
        li0 = num * pow(den, FR_MOD - 2, FR_MOD) % FR_MOD
        s = (s + y_i * li0) % FR_MOD
    return s

# Load shares
def load_shares_txt():
    with open(SHARES_FILE) as f:
        lines = [l.strip() for l in f if l.strip()]
    commitment_hex = lines[0].split("=")[1]
    t = int(lines[1].split("=")[1])
    shares = []
    for line in lines[2:]:
        parts = dict(x.split("=") for x in line.split())
        shares.append((
            int(parts["i"]),
            bytes.fromhex(parts["y"][2:]),
            bytes.fromhex(parts["proof"][2:])
        ))
    return commitment_hex, t, shares

# Reconstruction
def main():
    if len(sys.argv) != 1:
        print("Usage: python client.py")
        sys.exit(1)

    
    commitment_hex, t, shares = load_shares_txt()
    print(f"[Client] Reconstructing the secret with {t} shares...")
    setup = ckzg.load_trusted_setup(DEFAULT_SETUP_PATH, 0)
    commitment = bytes.fromhex(commitment_hex[2:])

    good = []
    for i, y, proof in shares:
        z = int_to_fe_bytes(i)

        # VerifyEval(PK, C, i, φ(i), wi)
        if ckzg.verify_kzg_proof(commitment, z, y, proof, setup):
            good.append((i, fe_bytes_to_int(y)))

    if len(good) < t + 1:
        raise RuntimeError(f"Not enough valid shares: {len(good)} < {t+1}")

    good.sort()
    used = good[:t + 1]

    # Interpolation φ(0)
    secret = lagrange_at_zero(used)

    print(f"[Client] reconstructed secret = {secret}")
    print(f"[Client] t={t} shares_usadas={len(used)} idx={[i for i,_ in used]}")
if __name__ == "__main__":
    main()
