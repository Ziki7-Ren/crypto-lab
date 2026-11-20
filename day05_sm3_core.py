# -*- coding: utf-8 -*-
"""
sm3_core.py — SM3 国密密码杂凑算法从零实现（Day 5）
依据：GB/T 32905-2016《信息安全技术 SM3 密码杂凑算法》
输出 256 位摘要（32 字节 / 8 个字），分组 512 位（64 字节 / 16 字），64 轮迭代。
结构：Merkle-Damgård；填充 → 消息扩展 → 压缩函数 → 摘要拼接。

与 SM4 的区别：SM4 是对称加密（可逆、有密钥），SM3 是哈希（不可逆、无密钥）。
所有常量（IV、轮常数 T、P0/P1 移位数）均按国标写死，不手抄摘要，
用国标附录 A 两组向量对拍验证：
    "abc"        -> 66c7f0f4...8f4ba8e0
    "abcd" * 16  -> debe9ff9...9c0c5732
"""

# 1. 常量：32 位掩码 + 初始变量 IV
MASK = 0xFFFFFFFF  # 32 位"天花板"，加法后 & 一下，保证结果还是 32 位

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]  # 国标写死的 8 个起始常数 = 8 个状态字的"出厂设置"


# 2. 六个小工具函数
def rotl(x, n):
    """循环左移：把 32 位的 x 往左挪 n 位，挪出去的从右边绕回来。"""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & MASK


def T(j):
    """轮常数：前 16 轮一个值，后 48 轮另一个值。"""
    if j < 16:
        return 0x79CC4519
    return 0x7A879D8A


def FF(j, x, y, z):
    """布尔函数 FF：前 16 轮三路异或，后 48 轮改成与或。"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def GG(j, x, y, z):
    """布尔函数 GG：前 16 轮三路异或，后 48 轮改成与/取反/与。"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & MASK) & z)


def P0(x):
    """置换函数 P0：x 和自己左移 9 位、17 位异或。"""
    return x ^ rotl(x, 9) ^ rotl(x, 17)


def P1(x):
    """置换函数 P1：x 和自己左移 15 位、23 位异或。"""
    return x ^ rotl(x, 15) ^ rotl(x, 23)


# 3. 消息填充：把任意长度消息补成 64 字节整块
def pad(msg):
    bit_len = len(msg) * 8          # 原始消息的位长度
    data = bytearray(msg)
    data.append(0x80)              # 补一个结束标记 1000 0000
    while len(data) % 64 != 56:    # 补 0 到 56 字节
        data.append(0x00)
    data += bit_len.to_bytes(8, "big")  # 末尾 8 字节写原长，凑满 64
    return data


# 4. 消息扩展：16 个字抻成 68 个 W，再造 64 个 W1
def expand(block):
    W = []
    for i in range(16):
        W.append(int.from_bytes(block[i * 4:(i + 1) * 4], "big"))
    for i in range(16, 68):
        w = P1(W[i - 16] ^ W[i - 9] ^ rotl(W[i - 3], 15)) ^ rotl(W[i - 13], 7) ^ W[i - 6]
        W.append(w)
    W1 = []
    for j in range(64):
        W1.append(W[j] ^ W[j + 4])
    return W, W1


# 5. 压缩函数：8 个状态字滚 64 轮
def compress(V, block):
    W, W1 = expand(block)
    A, B, C, D, E, F, G, H = V
    for j in range(64):
        SS1 = rotl((rotl(A, 12) + E + rotl(T(j), j)) & MASK, 7)
        SS2 = SS1 ^ rotl(A, 12)
        TT1 = (FF(j, A, B, C) + D + SS2 + W1[j]) & MASK
        TT2 = (GG(j, E, F, G) + H + SS1 + W[j]) & MASK
        D = C
        C = rotl(B, 9)
        B = A
        A = TT1
        H = G
        G = rotl(F, 19)
        F = E
        E = P0(TT2)
    nxt = [A, B, C, D, E, F, G, H]
    return [V[k] ^ nxt[k] for k in range(8)]  # 与旧状态异或 = 反馈


# 6. 主函数：填充 → 逐块压缩 → 拼接摘要
def sm3(msg):
    data = pad(msg)
    V = IV[:]
    for offset in range(0, len(data), 64):
        V = compress(V, data[offset:offset + 64])
    return "".join("%08x" % x for x in V)


# 7. 自测：两组国标向量对拍
if __name__ == "__main__":
    vec1_msg = b"abc"
    vec1_exp = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    vec2_msg = b"abcd" * 16
    vec2_exp = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"

    r1 = sm3(vec1_msg)
    r2 = sm3(vec2_msg)
    print("向量1  abc        :", r1)
    print("  国标期望         :", vec1_exp, " 对拍:", r1 == vec1_exp)
    print("向量2  abcd*16     :", r2)
    print("  国标期望         :", vec2_exp, " 对拍:", r2 == vec2_exp)
    print("两组全部通过:", r1 == vec1_exp and r2 == vec2_exp)
