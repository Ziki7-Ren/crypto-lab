# -*- coding: utf-8 -*-
"""
sm4_core.py — SM4 国密分组密码从零实现（Day 4）
依据：GB/T 32907-2016《信息安全技术 SM4 分组密码算法》
分组长度 128 位，密钥 128 位，32 轮非线性迭代。
结构：非平衡 Feistel；解密 = 加密结构相同、轮密钥逆序。

S 盒不手抄 256 项，而是用国标的数学定义现场生成：
    S[x] = Affine( GF_inv( Affine(x) ) )
其中 Affine 是 GF(2) 上的 8x8 矩阵变换异或常数 0xD3，
GF_inv 是有限域 GF(2^8)（模多项式 x^8+x^7+x^6+x^5+x^4+x^2+1）上的乘法逆元。
这样既避免抄错，又能对着国标表验证。
"""


#1.常量＋造S盒
POLY = 0x1F5  # x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1  # 有限域的"模数" 为了让字节相乘的结果，永远还是个字节。

# 仿射矩阵=配方表：8 行，每行写着"这个输出位，要把哪几个输入位异或起来"。
AFFINE_ROWS = [
    (0, 1, 3, 6, 7),
    (0, 1, 2, 4, 7),
    (0, 1, 2, 3, 5),
    (1, 2, 3, 4, 6),
    (2, 3, 4, 5, 7),
    (0, 3, 4, 5, 6),
    (1, 4, 5, 6, 7),
    (0, 2, 5, 6, 7),
]
#常数 0xD3 = 每行的额外作料：不管配方算出啥，最后再异或一个固定的 bit
AFFINE_C = 0xD3

#有限域乘法函数
def gf_mul(a, b):
    """GF(2^8) 上的乘法。"""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        b = b >> 1
        a = a << 1
        if a & 0x100:
            a = a ^ POLY  # 超界就 a ^= 0x1F5 折回来结果永远在 0–255
    return result & 0xFF

#求倒数函数
def gf_inv(a):
    """GF(2^8) 上的乘法逆元；0 的逆元定义为 0。"""
    if a == 0:
        return 0
    for x in range(1, 256):
        if gf_mul(a, x) == 1:
            return x
    return 0


#仿射函数--把 1 个字节拆成 8 个 bit，按一张"配方表"重新算 8 遍，每遍吐出 1 个新 bit，再拼回 1 个字节。
def affine(x):
    """国标仿射变换：8x8 矩阵乘 x 再异或常数 0xD3。"""
    bits = []
    for i in range(8):
        bits.append((x >> (7 - i)) & 1) #把 x 这个字节拆成 8 个 bit，存进 bits
    c_bits = []
    for i in range(8):
        c_bits.append((AFFINE_C >> (7 - i)) & 1)
    out = 0  #按 AFFINE_ROWS 这张"配方表"，把特定的几个 bit 异或起来，再加上常数的对应位，最后拼回一个字节。
    for i in range(8):
        bit = c_bits[i]
        for j in AFFINE_ROWS[i]:
            bit = bit ^ bits[j]
        out = (out << 1) | bit
    return out

#建S盒子---先仿射，再求逆，再仿射
def build_sbox():
    """用数学定义生成 256 项 S 盒。"""
    box = []
    for x in range(256):
        box.append(affine(gf_inv(affine(x))))
    return box

SBOX = build_sbox()


#2.参数+三个变换

# 系统参数 FK 是 4 个固定常数写死的列表（国标给定）
FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
# 造 32 个固定常数 CK，是按国标公式算出来的
CK = []
for i in range(32):
    ck = 0
    for j in range(4):
        ck = (ck << 8) | ((4 * i + j) * 7 % 256)
    CK.append(ck)

#循环左移：普通左移会把顶出去的位丢掉；循环左移是把它接回最低位
def rotl(x, n):
    """32 位循环左移。"""
    x = x & 0xFFFFFFFF #是掩码：0xFFFFFFFF 是 32 个 1，& 它等于"只保留低 32 位，超出的扔掉"。
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
#x << n 是左移 n 位；x >> (32-n) 是把即将被挤走的高 n 位挪到最低位；| 把两半拼起来


#四字节查表--混淆
def tau(a):
    """非线性变换：32 位字拆 4 字节，分别过 S 盒。"""
    b0 = SBOX[(a >> 24) & 0xFF] #把最高 8 位挪到最低位置，& 0xFF 只留这 8 位 —— 这两步合起来就是"​取出第 1 个字节
    b1 = SBOX[(a >> 16) & 0xFF]
    b2 = SBOX[(a >> 8) & 0xFF]
    b3 = SBOX[a & 0xFF]
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

#T和T'---扩散
def T(a):
    """合成置换 T = L(tau)，用于轮函数。"""
    b = tau(a)
    return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)


def T_prime(a):
    """密钥扩展用的 T'，把 L 换成 L'。"""
    b = tau(a)
    return b ^ rotl(b, 13) ^ rotl(b, 23)

#3.密钥扩展：128 位初始密钥 → 32 把 32 位轮密钥，供 32 轮加密每轮用一把。
def key_expansion(key_hex):
    """128 位密钥（32 个 hex 字符）扩展出 32 个 32 位轮密钥。"""
    mk = []
    for i in range(4):
        mk.append(int(key_hex[i * 8:(i + 1) * 8], 16)) #切四块
    k = []
    for i in range(4):
        k.append(mk[i] ^ FK[i]) #这一步叫"白化"，把初始密钥先搅一下再进主循环。
    rk = []
    for i in range(32): #循环 32 轮，吐出 32 把轮密钥
        nxt = k[i] ^ T_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])
        k.append(nxt)
        rk.append(nxt)
    return rk
#新算出的 nxt 追加到 k 列表尾部，列表越来越长。下一轮 i=1 时，k[i+1..i+3] 就自动变成了往后挪一格的新三个数——这就是滑动窗口

#4.切块+加解密主循环
def bytes_to_words(block):
    """16 字节 -> 4 个 32 位字（大端）。"""
    words = []
    for i in range(4):
        words.append(int.from_bytes(block[i * 4:(i + 1) * 4], "big")) #"big" 叫大端——高位字节放前面（就像写数字 1234，千位在左）。
    return words


def words_to_bytes(words):
    """4 个 32 位字 -> 16 字节。"""
    out = b"" #造一个空字节串
    for w in words:
        out = out + w.to_bytes(4, "big") #反操作：把整数拆回 4 字节
    return out


def sm4_crypt(block, rk):
    """SM4 加/解密核心：结构相同，只是轮密钥顺序不同。"""
    X = bytes_to_words(block)
    for i in range(32):
        nxt = X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ rk[i])
        X = [X[1], X[2], X[3], nxt]
    # 反序变换 R
    return words_to_bytes([X[3], X[2], X[1], X[0]])


def sm4_encrypt(plaintext, key_hex):
    """加密：返回 16 字节密文。"""
    rk = key_expansion(key_hex)
    return sm4_crypt(plaintext, rk)


def sm4_decrypt(ciphertext, key_hex):
    """解密：轮密钥逆序。"""
    rk = key_expansion(key_hex)
    rk_rev = []
    for i in range(len(rk) - 1, -1, -1):
        rk_rev.append(rk[i])
    return sm4_crypt(ciphertext, rk_rev)


if __name__ == "__main__":
    print("SM4 国密算法从零实现（GB/T 32907-2016）")
    print("=" * 50)

    # S 盒自检：对照国标表 1 的三个点
    print("S 盒自检:")
    print("  S[00]=%02X (应 D6)" % SBOX[0x00])
    print("  S[01]=%02X (应 90)" % SBOX[0x01])
    print("  S[EF]=%02X (应 84)" % SBOX[0xEF])
    print("  S[FF]=%02X (应 48)" % SBOX[0xFF])

    # 国标附录 A 示例 1
    key = "0123456789abcdeffedcba9876543210"
    pt = bytes.fromhex(key)
    rk = key_expansion(key)
    print("\n轮密钥（共 %d 把，国标附录 A）:" % len(rk))
    print("  rk[0] = %08X" % rk[0])
    print("  rk[1] = %08X" % rk[1])
    print("  rk[31]= %08X" % rk[31])

    print("\n国标附录 A 示例 1:")
    ct = sm4_encrypt(pt, key)
    print("  明文 =", pt.hex().upper())
    print("  密文 =", ct.hex().upper())
    print("  期望 = 681EDF34D206965E86B3E94F536E4246")
    print("  对拍 =", "OK" if ct.hex().upper() == "681EDF34D206965E86B3E94F536E4246" else "FAIL")
    dec = sm4_decrypt(ct, key)
    print("  解密还原 =", "OK" if dec == pt else "FAIL")

    # 示例 2 要跑 100 万次，纯 Python 较慢（约 20 秒），加 --full 参数才跑
    import sys
    if "--full" in sys.argv:
        print("\n国标附录 A 示例 2（100 万次加密，约 20 秒）:")
        blk = pt
        for i in range(1000000):
            blk = sm4_encrypt(blk, key)
        print("  密文 =", blk.hex().upper())
        print("  期望 = 595298C7C6FD271F0402F804C33D3F66")
        print("  对拍 =", "OK" if blk.hex().upper() == "595298C7C6FD271F0402F804C33D3F66" else "FAIL")
    else:
        print("\n（示例 2 需 100 万次加密，跑 `python day04_sm4_core.py --full` 验证）")
