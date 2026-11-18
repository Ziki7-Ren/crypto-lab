# -*- coding: utf-8 -*-
"""
aes_core.py — AES-128 从零实现（Day 3 完整版）
Day 1: S 盒 + 状态转换 + 四个轮函数
Day 2: 密钥扩展 + 加密主循环 + 官方向量对拍
Day 3: 三个逆变换 + 解密主循环 + 三组官方向量加解密对拍
依据：FIPS 197-upd1（2023），算法与 2001 版一致
"""

# ===== 1. S 盒（FIPS-197 Table 4，256 项，已核对）=====
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# RCON：密钥扩展每一轮要异或的常数（FIPS-197 里叫 Rcon[i]）
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# 逆 S 盒（Day 3 新增）：S 盒是双射，可由它反推。SBOX[i] 的值是 j，则 INV_SBOX[j] = i
INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i


# ===== 2. 状态转换（Day 1）=====
def bytes_to_state(data):
    """16 bytes -> 4x4 state，列优先填充"""
    assert len(data) == 16
    state = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(data[r + c * 4])
        state.append(row)
    return state


def state_to_bytes(state):
    """4x4 state -> 16 bytes，列优先读出"""
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return out


# ===== 3. 四个轮函数（Day 1）=====
def sub_bytes(state):
    """每个字节查 S 盒替换"""
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(SBOX[state[r][c]])
        out.append(row)
    return out


def shift_rows(state):
    """第 r 行循环左移 r 个字节"""
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(state[r][(c + r) % 4])
        out.append(row)
    return out


def xtime(a):
    """GF(2^8) 里乘 0x02"""
    a = a << 1
    if a & 0x100:
        a = a ^ 0x1b
    return a & 0xff


def gmul(a, b):
    """GF(2^8) 通用乘法"""
    p = 0
    for i in range(8):
        if b & 1:
            p = p ^ a
        a = xtime(a)
        b = b >> 1
    return p & 0xff


def mix_columns(state):
    """每列乘固定矩阵 [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]"""
    out = []
    for r in range(4):
        out.append([0, 0, 0, 0])
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]
        out[0][c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        out[1][c] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        out[2][c] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        out[3][c] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return out


def add_round_key(state, round_key):
    """状态与 16 字节轮密钥逐字节异或"""
    rk = bytes_to_state(round_key)
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(state[r][c] ^ rk[r][c])
        out.append(row)
    return out


# ===== 4. 逆变换（Day 3 新增）=====
def inv_sub_bytes(state):
    """每个字节查逆 S 盒替换"""
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(INV_SBOX[state[r][c]])
        out.append(row)
    return out


def inv_shift_rows(state):
    """第 r 行循环右移 r 个字节（正好是 shift_rows 的逆操作）"""
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            row.append(state[r][(c - r) % 4])
        out.append(row)
    return out


def inv_mix_columns(state):
    """每列乘逆矩阵 [14 11 13 9; 9 14 11 13; 13 9 14 11; 11 13 9 14]"""
    out = []
    for r in range(4):
        out.append([0, 0, 0, 0])
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]
        out[0][c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        out[1][c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        out[2][c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        out[3][c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
    return out

# ===== 5. 密钥扩展（Day 2 新增）=====
def rot_word(w):
    """把一个 4 字节 word 循环左移 1 字节：[a,b,c,d] -> [b,c,d,a]"""
    return [w[1], w[2], w[3], w[0]]


def sub_word(w):
    """把一个 4 字节 word 的每个字节都查 S 盒"""
    out = []
    for i in range(4):
        out.append(SBOX[w[i]])
    return out


def key_expansion(key):
    """16 字节初始密钥 -> 11 个 16 字节轮密钥"""
    assert len(key) == 16
    # w 是 44 个 word，每个 word 4 字节；前 4 个 word 就是初始密钥
    w = []
    for i in range(4):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(4, 44):
        temp = w[i - 1][:]  # 复制上一个 word（[:] 是浅拷贝，避免改到原值）
        if i % 4 == 0:      # 每 4 个 word 做一次复杂变换
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] = temp[0] ^ RCON[i // 4 - 1]
        new_word = []
        for j in range(4):
            new_word.append(w[i - 4][j] ^ temp[j])
        w.append(new_word)

    # 把 44 个 word 打包成 11 个轮密钥（每个 4 个 word = 16 字节）
    round_keys = []
    for r in range(11):
        rk = []
        for k in range(4):
            word = w[4 * r + k]
            for b in word:
                rk.append(b)
        round_keys.append(bytes(rk))
    return round_keys


# ===== 6. 加密主循环（Day 2 新增）=====
def aes_encrypt(pt, key):
    """16 字节明文 + 16 字节密钥 -> (16 字节密文, 11 个轮密钥)"""
    round_keys = key_expansion(key)
    state = bytes_to_state(pt)

    # 初始轮：只做一次 AddRoundKey
    state = add_round_key(state, round_keys[0])

    # 第 1~9 轮：四步全做
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

    # 第 10 轮（最终轮）：不做 MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return bytes(state_to_bytes(state))


# ===== 7. 解密主循环（Day 3 新增）=====
def aes_decrypt(ct, key):
    """16 字节密文 + 16 字节密钥 -> 16 字节明文"""
    round_keys = key_expansion(key)
    state = bytes_to_state(ct)

    # 初始轮：只做一次 AddRoundKey，用最后一把轮密钥
    state = add_round_key(state, round_keys[10])

    # 第 9~1 轮：逆行移位 → 逆字节替换 → AddRoundKey → 逆列混合
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

    # 最终轮：不做逆列混合（对应加密第 10 轮不做 MixColumns）
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return bytes(state_to_bytes(state))

# ===== 8. 自测：三组官方向量对拍（Day 3）=====

if __name__ == "__main__":
    assert xtime(0x57) == 0xae, "xtime error"
    assert gmul(0x57, 0x83) == 0xc1, "gmul error"
    print("[OK] xtime / gmul")

    # 三组公开测试向量：(名字, 密钥, 明文, 标准密文)
    vectors = [
        ("FIPS-197 App.B",
         "2b7e151628aed2a6abf7158809cf4f3c",
         "3243f6a8885a308d313198a2e0370734",
         "3925841d02dc09fbdc118597196a0b32"),
        ("FIPS-197 App.C.1",
         "000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff",
         "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("All-zero KAT",
         "00000000000000000000000000000000",
         "00000000000000000000000000000000",
         "66e94bd4ef8a2c3b884cfa59ca342b2e"),
    ]

    for name, key_hex, pt_hex, ct_hex in vectors:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct = aes_encrypt(pt, key)
        dec = aes_decrypt(ct, key)
        assert ct.hex() == ct_hex, name + " ciphertext error"
        assert dec == pt, name + " decrypt error"
        print("[OK]", name, "ct:", ct.hex(), "-> pt:", dec.hex())

    print("[OK] AES-128 加解密三组官方向量全部通过！")
