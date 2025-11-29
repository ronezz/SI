import os
import sys
from math import log2, ceil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

def encrypt(key, plaintext):
    iv = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    return iv, encryptor.update(plaintext) + encryptor.finalize()

def decrypt(key, iv, ciphertext):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def pad(pt):
    p = padding.PKCS7(128).padder()
    return p.update(pt) + p.finalize()

def unpad(pt):
    u = padding.PKCS7(128).unpadder()
    return u.update(pt) + u.finalize()

def parent(j):
    return j // 2

def sibling(j):
    return j + 1 if j % 2 == 0 else j - 1

def path(j):
    r = []
    while j >= 1:
        r.append(j)
        j = parent(j)
    return r

def is_ancestor(a, leaf):
    while leaf >= 1:
        if leaf == a:
            return True
        leaf //= 2
    return False


# Encrypt
def encrypt_mode(infile, outfile, n, revoked):
    with open(infile, "rb") as f:
        m = f.read()

    m = pad(m)

    # build tree
    t = ceil(log2(max(1, n)))
    leaves = 2**t
    total = 2*leaves - 1
    keys = {i: os.urandom(16) for i in range(1, total+1)}

    # initial cover
    cover = set()
    rset = set(revoked)
    for r in rset:
        leaf = leaves + (r-1)
        for node in path(leaf):
            s = sibling(node)
            if s in keys:
                cover.add(s)

    cover = sorted(cover)

    # remove dangerous nodes (revoked ancestors)
    bad = set()
    rev_leaves = [leaves + (r-1) for r in rset]
    for c in cover:
        for rl in rev_leaves:
            if is_ancestor(c, rl):
                bad.add(c)
                break

    cover = [c for c in cover if c not in bad]

    k = os.urandom(16)

    headers = []
    for c in cover:
        iv, ct = encrypt(keys[c], k)
        headers.append((c, iv, ct))

    civ, cct = encrypt(k, m)

    with open(outfile + ".aacs", "wb") as f:
        f.write(total.to_bytes(4, "big"))
        f.write(t.to_bytes(4, "big"))
        f.write(leaves.to_bytes(4, "big"))
        f.write(len(headers).to_bytes(4, "big"))
        for c, iv, ct in headers:
            f.write(c.to_bytes(4, "big"))
            f.write(iv)
            f.write(len(ct).to_bytes(4, "big"))
            f.write(ct)
        f.write(civ)
        f.write(len(cct).to_bytes(4, "big"))
        f.write(cct)

    with open(outfile + ".keys", "wb") as f:
        for dev in range(1, n+1):
            leaf = leaves + (dev-1)
            nodes = path(leaf)
            f.write(dev.to_bytes(4,"big"))
            f.write(len(nodes).to_bytes(4,"big"))
            for nd in nodes:
                f.write(nd.to_bytes(4,"big"))
                f.write(keys[nd])

    print(f"[+] Encrypted to {outfile}.aacs")
    print(f"    Revoked: {revoked}")
    print(f"    Cover: {cover}")


# Read Files/Keys

def read_aacs(path):
    with open(path,"rb") as f:
        b = f.read()

    pos = 0
    def take(n):
        nonlocal pos
        r=b[pos:pos+n]; pos+=n; return r

    total = int.from_bytes(take(4),"big")
    t_lv = int.from_bytes(take(4),"big")
    leaves = int.from_bytes(take(4),"big")
    hcount = int.from_bytes(take(4),"big")

    headers=[]
    for _ in range(hcount):
        node = int.from_bytes(take(4),"big")
        iv = take(16)
        l = int.from_bytes(take(4),"big")
        ct = take(l)
        headers.append((node,iv,ct))

    civ = take(16)
    l = int.from_bytes(take(4),"big")
    cct = take(l)

    return t_lv, leaves, headers, civ, cct

def load_keys(keyfile, dev):
    with open(keyfile,"rb") as f:
        b=f.read()

    pos=0
    def take(n):
        nonlocal pos
        r=b[pos:pos+n]; pos+=n; return r

    while pos < len(b):
        d = int.from_bytes(take(4),"big")
        cnt = int.from_bytes(take(4),"big")
        if d == dev:
            res={}
            for _ in range(cnt):
                nd = int.from_bytes(take(4),"big")
                k = take(16)
                res[nd] = k
            return res
        else:
            for _ in range(cnt):
                take(4+16)
    return None


# Decrypt 

def decrypt_mode(enc, keyfile, dev):
    t_lv, leaves, headers, civ, cct = read_aacs(enc)
    dkeys = load_keys(keyfile, dev)

    if dkeys is None:
        print("[!] Device not found.")
        return

    k = None
    for node, iv, ct in headers:
        if node in dkeys:
            try:
                k_try = decrypt(dkeys[node], iv, ct)
                k = k_try
                break
            except:
                pass

    if k is None:
        print(f"[!] Device {dev}: revoked")
        return

    try:
        pt_padded = decrypt(k, civ, cct)
        pt = unpad(pt_padded)
        out = f"device_{dev}_output.bin"
        with open(out,"wb") as f:
            f.write(pt)
        print(f"[+] Device {dev}: content decrypted -> {out}")
    except:
        print(f"[!] Device {dev}: key ok but content failed.")


# Main
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("encrypt <in> <out> <n> <revoked>")
        print("decrypt <aacs> <keys> <device>")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "encrypt":
        infile = sys.argv[2]
        out = sys.argv[3]
        n = int(sys.argv[4])
        revoked=[]
        if len(sys.argv) > 5 and sys.argv[5]:
            revoked = [int(x) for x in sys.argv[5].split(",")]
        encrypt_mode(infile, out, n, revoked)

    elif cmd == "decrypt":
        enc = sys.argv[2]
        keyfile = sys.argv[3]
        dev = int(sys.argv[4])
        decrypt_mode(enc, keyfile, dev)
