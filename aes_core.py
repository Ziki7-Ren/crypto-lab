# -*- coding: utf-8 -*-
"""
Created on Mon Nov 16 17:31:58 2026

@author: seven
"""

# aes_core.py
# AES-128 round functions, from scratch, following FIPS-197

#1.导入S盒

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
#2.状态转换：16字节——>4×4矩阵
#(1).把16字节摆成矩阵
def bytes_to_state(data):
    """
        16 bytes -> 4×4 state，colume-major(FIPS-197 Sec 3.4)    
    """
    assert len(data)==16
    state=[]
    for r in range(4):
        row=[]
        for c in range(4):
            row.append(data[r+c*4])
        state.append(row)
    return state
#（2）把矩阵摆回16字节
def state_to_bytes(state):
    """4x4 state -> 16 bytes, column-major"""
    out=[]
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return out
# #(3)验证
# d = list(range(16))
# s = bytes_to_state(d)
# print(s)
# print(state_to_bytes(s))

#3.subbytes
def sub_bytes(state):
    """Replace every byte with S-box value"""
    out = []
    for r in range(4):
        row = []
        for c in range(4):
            v = state[r][c]
            row.append(SBOX[v])
        out.append(row)
    return out
#4.shiftrows
def shift_rows(state):
    """
    row r is cyclically shifted left by r bytes.
    """
    out=[]
    for r in range(4):
        row=[]
        for c in range(4):
            row.append(state[r][(c+r)%4])
        out.append(row)
    return out
#4.GF(2⁸) 乘法 ＋ MixColumns
#(1)乘0x02的快捷函数
def xtime(a):
    """
    Multiply a byte by 0x02 in GF(2^8).
    """
    a=a<<1
    if a & 0x100:
        a=a^0x1b
    return a&0xff
#（2）通用乘法
def gmul(a,b):
    """
    Multiply two bytes in GF(2^8)
    """
    p=0
    for i in range(8):
        if b&1:
            p=p^a
        a=xtime(a)      # 这两行要和 if 对齐，属于 for 循环，不属于 if
        b=b>>1
    return p&0xff
# (3)MixColumns
def mix_columns(state):
    out=[]
    for r in range(4):
        out.append([0,0,0,0])
    for c in range(4):
        a0=state[0][c]
        a1=state[1][c]
        a2=state[2][c]
        a3=state[3][c]
        out[0][c]=gmul(a0,2)^gmul(a1,3)^a2^a3
        out[1][c]=a0^gmul(a1,2)^gmul(a2,3)^a3
        out[2][c]=a0^a1^gmul(a2,2)^gmul(a3,3)
        out[3][c]=gmul(a0,3)^a1^a2^gmul(a3,2)
    return out
#5.ADDROUNDKEY()
def add_round_key(state,round_key):
    """
    XOR state with 16-byte round key
    """
    rk=bytes_to_state(round_key)
    out=[]
    for r in range(4):
        row=[]
        for c in range(4):
            row.append(state[r][c]^rk[r][c])
        out.append(row)
    return out

#6.自测
if __name__ == "__main__":
    # --- 基本自检 ---
    assert xtime(0x57) == 0xae, "xtime error"
    assert gmul(0x57, 0x83) == 0xc1, "gmul error"
    print("[OK] xtime / gmul")

    # --- FIPS 197-upd1 Appendix B (Cipher Example) 官方向量 ---
    pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")  # 明文
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")  # 初始密钥
    state = bytes_to_state(pt)

    # 注意：AES 第一步是初始 AddRoundKey，必须先做，否则后面全对不上官方值
    state = add_round_key(state, key)
    print("round 1 start (should be 19 3d e3 be / a0 f4 e2 2b / 9a c6 8d 2a / e9 f8 48 08):")
    for row in state:
        line = []
        for x in row:
            line.append(hex(x))
        print("  ", line)

    # --- 四个函数各跑一遍，打印结果 ---
    s1 = sub_bytes(state)
    print("after SubBytes (should be d4 e0 b8 1e / 27 bf b4 41 / 11 98 5d 52 / ae f1 e5 30):")
    for row in s1:
        line = []
        for x in row:
            line.append(hex(x))
        print("  ", line)

    s2 = shift_rows(s1)
    print("after ShiftRows:")
    for row in s2:
        line = []
        for x in row:
            line.append(hex(x))
        print("  ", line)

    s3 = mix_columns(s2)
    print("after MixColumns:")
    for row in s3:
        line = []
        for x in row:
            line.append(hex(x))
        print("  ", line)

    s4 = add_round_key(s3, bytes(16))   # 今天先用全 0 轮密钥占位
    print("after AddRoundKey (zero key):")
    for row in s4:
        line = []
        for x in row:
            line.append(hex(x))
        print("  ", line)
        
    
    
    
        
            