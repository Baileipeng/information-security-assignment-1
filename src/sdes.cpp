#include "sdes.h"

#include <map>

namespace sdes {

// ------------------------- 置换表与 S-Box 定义 ------------------------------

const int P10[10]   = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
const int P8[8]     = {6, 3, 7, 4, 8, 5, 10, 9};
const int IP[8]     = {2, 6, 3, 1, 4, 8, 5, 7};
const int IP_INV[8] = {4, 1, 3, 5, 7, 2, 8, 6};
const int EP[8]     = {4, 1, 2, 3, 2, 3, 4, 1};
const int SP[4]     = {2, 4, 3, 1};

// SBox1 与经典 S-DES 一致；SBox2 为作业文档指定的修改版本
const int SBOX1[4][4] = {
    {1, 0, 3, 2},
    {3, 2, 1, 0},
    {0, 2, 1, 3},
    {3, 1, 0, 2},
};

const int SBOX2[4][4] = {
    {0, 1, 2, 3},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {2, 1, 0, 3},
};

// --------------------------- 基础位运算 -------------------------------------

uint8_t permute(uint16_t value, const int* table, int tableLen, int inputBits) {
    uint16_t result = 0;
    // table[i] 为 1 起始的输入位编号，取该位放到输出的第 i 位
    for (int i = 0; i < tableLen; ++i) {
        int bitPos = inputBits - table[i]; // 转换为 0 起始的右移位数
        uint16_t bit = (value >> bitPos) & 0x1;
        result |= bit << (tableLen - 1 - i);
    }
    return static_cast<uint8_t>(result);
}

uint8_t leftShift5(uint8_t value, int shift) {
    value &= 0x1F; // 仅保留低 5 位
    shift %= 5;
    return static_cast<uint8_t>(((value << shift) | (value >> (5 - shift))) & 0x1F);
}

// --------------------------- 密钥扩展 ---------------------------------------

void generateSubKeys(uint16_t key10, uint8_t& k1, uint8_t& k2) {
    // 1) P10 置换得到 10 bit 中间结果
    uint8_t p10 = permute(key10, P10, 10, 10);

    // 2) 拆分为高低各 5 bit
    uint8_t high5 = (p10 >> 5) & 0x1F;
    uint8_t low5  = p10 & 0x1F;

    // 3) 循环左移 1 位后合并，经 P8 得到子密钥 k1
    uint8_t sh1 = (leftShift5(high5, 1) << 5) | leftShift5(low5, 1);
    k1 = permute(sh1, P8, 8, 10);

    // 4) 在左移 1 位的基础上再左移 2 位（累计左移 3 位），经 P8 得到 k2
    uint8_t sh2 = (leftShift5(high5, 3) << 5) | leftShift5(low5, 3);
    k2 = permute(sh2, P8, 8, 10);
}

// --------------------------- 轮函数与 S-Box ----------------------------------

uint8_t sboxLookup(uint8_t value4, const int sbox[4][4]) {
    int b0 = (value4 >> 3) & 0x1;
    int b1 = (value4 >> 2) & 0x1;
    int b2 = (value4 >> 1) & 0x1;
    int b3 = value4 & 0x1;
    int row = b0 * 2 + b3; // 行由第 1、4 位构成
    int col = b1 * 2 + b2; // 列由第 2、3 位构成
    return static_cast<uint8_t>(sbox[row][col] & 0x3);
}

uint8_t fFunc(uint8_t r4, uint8_t subKey) {
    // 1) EPBox：4 bit 扩展为 8 bit
    uint8_t expanded = permute(r4, EP, 8, 4);

    // 2) 与子密钥按位异或
    uint8_t mixed = expanded ^ subKey;

    // 3) 拆分为高低 4 bit，分别通过 SBox1 / SBox2 压缩为 2 bit
    uint8_t s1 = sboxLookup((mixed >> 4) & 0x0F, SBOX1);
    uint8_t s2 = sboxLookup(mixed & 0x0F, SBOX2);

    // 4) 合并为 4 bit 后经 SPBox 置换输出
    uint8_t combined = static_cast<uint8_t>((s1 << 2) | s2);
    return permute(combined, SP, 4, 4);
}

uint8_t fk(uint8_t block, uint8_t subKey) {
    uint8_t left  = (block >> 4) & 0x0F; // 高 4 位
    uint8_t right = block & 0x0F;        // 低 4 位
    uint8_t newLeft = left ^ fFunc(right, subKey);
    return static_cast<uint8_t>((newLeft << 4) | right);
}

uint8_t sw(uint8_t block) {
    return static_cast<uint8_t>(((block & 0x0F) << 4) | ((block >> 4) & 0x0F));
}

// --------------------------- 加解密主流程 ------------------------------------

uint8_t encrypt(uint8_t plaintext, uint16_t key10) {
    uint8_t k1, k2;
    generateSubKeys(key10, k1, k2);

    uint8_t step1 = permute(plaintext, IP, 8, 8); // 初始置换 IP
    uint8_t step2 = fk(step1, k1);                // 第一轮 fk1
    uint8_t step3 = sw(step2);                    // 交换 SW
    uint8_t step4 = fk(step3, k2);                // 第二轮 fk2
    return permute(step4, IP_INV, 8, 8);          // 最终置换 IP^-1
}

uint8_t decrypt(uint8_t ciphertext, uint16_t key10) {
    // 解密与加密结构相同，仅子密钥使用顺序相反：先 k2 后 k1
    uint8_t k1, k2;
    generateSubKeys(key10, k1, k2);

    uint8_t step1 = permute(ciphertext, IP, 8, 8);
    uint8_t step2 = fk(step1, k2);
    uint8_t step3 = sw(step2);
    uint8_t step4 = fk(step3, k1);
    return permute(step4, IP_INV, 8, 8);
}

// ---------------------------- 工具函数 --------------------------------------

std::string toBinaryString(uint8_t value, int bits) {
    std::string out;
    out.reserve(bits);
    for (int i = bits - 1; i >= 0; --i) {
        out.push_back(((value >> i) & 0x1) ? '1' : '0');
    }
    return out;
}

std::string toBinaryString(uint16_t value, int bits) {
    std::string out;
    out.reserve(bits);
    for (int i = bits - 1; i >= 0; --i) {
        out.push_back(((value >> i) & 0x1) ? '1' : '0');
    }
    return out;
}

bool parseBinaryString(const std::string& text, int bits, uint16_t& out) {
    std::string clean;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c != '0' && c != '1') return false; // 出现非法字符直接失败
        clean.push_back(c);
    }
    if (static_cast<int>(clean.size()) != bits) return false; // 长度必须精确匹配

    uint16_t value = 0;
    for (char c : clean) {
        value = static_cast<uint16_t>((value << 1) | (c - '0'));
    }
    out = value;
    return true;
}

std::vector<uint16_t> bruteForce(
        const std::vector<std::pair<uint8_t, uint8_t>>& pairs) {
    std::vector<uint16_t> matched;
    if (pairs.empty()) return matched;

    // 密钥空间只有 2^10 = 1024，直接全量遍历
    for (uint16_t key = 0; key < 1024; ++key) {
        bool ok = true;
        for (const auto& pc : pairs) {
            if (encrypt(pc.first, key) != pc.second) {
                ok = false;
                break;
            }
        }
        if (ok) matched.push_back(key);
    }
    return matched;
}

std::vector<uint16_t> findAllKeys(uint8_t plaintext, uint8_t ciphertext) {
    std::vector<std::pair<uint8_t, uint8_t>> pairs{{plaintext, ciphertext}};
    return bruteForce(pairs);
}

} // namespace sdes
