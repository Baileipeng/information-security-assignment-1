#ifndef SDES_H
#define SDES_H

#include <cstdint>
#include <string>
#include <vector>

namespace sdes {

// ---------------------------------------------------------------------------
// S-DES (Simplified DES) 核心算法实现
//
// 参数设定（依据作业文档 2.x 节）:
//   分组长度   : 8 bit
//   密钥长度   : 10 bit
//   加密流程   : C = IP^-1( fk2( SW( fk1( IP(P) ) ) ) )
//   解密流程   : P = IP^-1( fk2( SW( fk1( IP(C) ) ) ) )
//   密钥扩展   : k1 = P8( Shift1( P10(K) ) ),  k2 = P8( Shift2( P10(K) ) )
//
// 所有置换表均按作业文档给定的数值硬编码，与 PPT 版本可能不同之处
// （SBox2 为作业文档修改版）以作业文档为准，保证交叉测试一致性。
// ---------------------------------------------------------------------------

// 置换表定义（元素含义：输出第 i 位取自输入的第 table[i]-1 位，编号从 1 开始）
extern const int P10[10];   // 密钥扩展置换 P10  = {3,5,2,7,4,10,1,9,8,6}
extern const int P8[8];     // 密钥扩展置换 P8   = {6,3,7,4,8,5,10,9}
extern const int IP[8];     // 初始置换 IP       = {2,6,3,1,4,8,5,7}
extern const int IP_INV[8]; // 最终置换 IP^-1    = {4,1,3,5,7,2,8,6}
extern const int EP[8];     // 扩展置换 EPBox    = {4,1,2,3,2,3,4,1}
extern const int SP[4];     // 缩减置换 SPBox    = {2,4,3,1}

// S-Box（作业文档指定版本，注意 SBox2 与经典 S-DES 不同）
// SBox1[i][j] : 行 i = b0 b3, 列 j = b1 b2（二进制）
extern const int SBOX1[4][4];
extern const int SBOX2[4][4];

// 通用置换函数：对 value 的前 n 位（高位在前，MSB first）按 table 执行置换，
// 返回结果与 table 元素个数等宽。例如 n=10 时 value 有效位为 10 bit。
uint8_t permute(uint16_t value, const int* table, int tableLen, int inputBits);

// 左移函数：对 5 bit 的 value 循环左移 shift 位
uint8_t leftShift5(uint8_t value, int shift);

// 密钥扩展：由 10 bit 主密钥生成两个 8 bit 子密钥 k1、k2
void generateSubKeys(uint16_t key10, uint8_t& k1, uint8_t& k2);

// 轮函数 fk(L,R,sk)：对 8 bit 输入的左 4 位与 F(R,sk) 异或
uint8_t fk(uint8_t block, uint8_t subKey);

// 交换函数 SW：交换 8 bit 数据的高 4 位与低 4 位
uint8_t sw(uint8_t block);

// 轮函数 F：对 4 bit 右半部分做 EP 扩展 -> 与子密钥异或 -> SBox 压缩 -> SPBox 置换
uint8_t fFunc(uint8_t r4, uint8_t subKey);

// S-Box 查表：输入 4 bit（b0b1b2b3），行 = b0b3，列 = b1b2，输出 2 bit
uint8_t sboxLookup(uint8_t value4, const int sbox[4][4]);

// 加密：8 bit 明文 + 10 bit 密钥 -> 8 bit 密文
uint8_t encrypt(uint8_t plaintext, uint16_t key10);

// 解密：8 bit 密文 + 10 bit 密钥 -> 8 bit 明文
uint8_t decrypt(uint8_t ciphertext, uint16_t key10);

// ---------------------------- 工具函数 -------------------------------------

// 将字节转为长度为 bits 的二进制字符串（MSB 在前），如 0x2A,8 -> "00101010"
std::string toBinaryString(uint8_t value, int bits);

// 将 16 bit 值转为二进制字符串（用于 10 bit 密钥显示）
std::string toBinaryString(uint16_t value, int bits);

// 解析二进制字符串为数值，忽略空白字符；合法字符仅 '0'/'1'。
// 成功返回 true 并写入 out；失败返回 false。
bool parseBinaryString(const std::string& text, int bits, uint16_t& out);

// 暴力破解：给定若干明文/密文对，遍历全部 1024 个候选密钥，
// 返回所有同时满足全部密文对约束的 10 bit 密钥列表。
std::vector<uint16_t> bruteForce(const std::vector<std::pair<uint8_t, uint8_t>>& pairs);

// 封闭测试分析：对给定明文 P，统计 1024 个密钥中每个密文值对应的密钥个数，
// 返回 collisionCount（同一明文存在两个不同密钥加密到相同密文的明文总数）
// 以及映射表 plaintext -> (ciphertext -> key 列表)，用于第 5 关分析展示。
// 这里仅提供逐明文的密钥-密文统计接口，GUI/控制台层负责汇总展示。
struct ClosureResult {
    uint8_t plaintext;                       // 分析的明文
    std::vector<uint16_t> keys;              // 所有能把该明文加密为 ciphertext 的密钥
    uint8_t ciphertext;                      // 目标密文
};

// 对指定明文/密文对，找出全部匹配密钥（含多重密钥情况）
std::vector<uint16_t> findAllKeys(uint8_t plaintext, uint8_t ciphertext);

} // namespace sdes

#endif // SDES_H
