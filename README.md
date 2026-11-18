# crypto-lab

手写对称密码 / 哈希分析工具，从零实现，逐日存档。

## 当前进度
AES-128 加解密完整实现，通过 3 组 NIST 官方向量对拍（2026-11-18）。
下一步：SM4 / 差分分析入门。

## 已实现
- GF(2^8) 运算：xtime / gmul（对拍 0x57×0x83=0xc1）
- AES-128 加密：SubBytes / ShiftRows / MixColumns / AddRoundKey + 密钥扩展 + 10 轮
- AES-128 解密：三个逆变换 + 解密主循环
- 标准向量对拍：FIPS-197 App.B / App.C.1 / 全零 KAT，加解密均通过

## 怎么跑
环境：Python 3（无第三方依赖，只用标准库）
    python code_by_day/day03_aes_core.py
看到 "[OK] AES-128 加解密三组官方向量全部通过！" 即成功。

## 代码结构（按天存档）
- code_by_day/day01_aes_core.py — 四个轮函数 + 状态转换
- code_by_day/day02_aes_core.py — 密钥扩展 + 加密主循环
- code_by_day/day03_aes_core.py — 逆变换 + 解密主循环 + 三组对拍
- 复盘记录.md — 每日复盘笔记

## 踩过的坑
- 状态是列优先 data[r+4*c]，行优先会全错
- 循环体缩进必须同层（gmul 曾因缩进错算成 0xf9）
- append() 用圆括号，SBOX[v] 用方括号
