// ===========================================================================
// 关卡 1：基本测试 —— S-DES 8 bit 明文 / 10 bit 密钥加解密
// ===========================================================================
//
// 【关卡要求】
//   实现 S-DES 算法，输入 8 bit 明文与 10 bit 密钥，输出 8 bit 密文；
//   解密时输入密文与同一密钥，应能还原出原明文。
//
// 【本程序演示内容】
//   1. 密钥扩展 Keygen(K)：P10 -> 左右 5 bit 循环左移 -> P8，输出 k1、k2；
//   2. 加密全过程：IP -> fk1 -> SW -> fk2 -> IP^-1，逐级打印中间结果；
//   3. 轮函数 F 展开：EP 扩展 -> 与子密钥异或 -> SBox1/SBox2 -> SPBox 置换；
//   4. 解密全过程：结构与加密相同，子密钥逆序使用（先 k2 后 k1）；
//   5. 往返校验：解密结果必须等于原明文，并给出 PASS/FAIL。
//
// 【编译】见仓库根 CMakeLists.txt，或直接用 g++ 编译：
//   g++ -std=c++17 -O2 -I../src ../src/sdes.cpp main.cpp -o level1_basic_test
//
// 【运行】
//   level1_basic_test                      默认 K=1010000010, P=00101000
//   level1_basic_test <key10> <plain8>     指定 10 bit 密钥与 8 bit 明文
//   参数同时支持二进制串 / 0x 十六进制 / 十进制写法
//
// 【实测结果（默认参数）】
//   K = 1010000010, P = 00101000  ->  C = 11110100，解密还原 P 成功
// ===========================================================================

#include <iostream>
#include <string>

#include "console_utils.h"
#include "sdes.h"

using namespace sdes;

namespace {

const uint16_t kDefaultKey   = 0b1010000010u;  // 作业示例密钥
const uint8_t  kDefaultPlain = 0b00101000u;    // 作业示例明文

// ---------------------------------------------------------------------------
// 1. 密钥扩展过程（含手工复现，用于验证 generateSubKeys 的正确性）
// ---------------------------------------------------------------------------
void printKeySchedule(uint16_t key) {
    uint8_t k1 = 0, k2 = 0;
    generateSubKeys(key, k1, k2);

    // 手工按定义重新算一遍，和上面的结果对照
    const uint16_t p10 = permute(key, P10, 10, 10);
    const uint8_t  l0  = static_cast<uint8_t>((p10 >> 5) & 0x1F);
    const uint8_t  r0  = static_cast<uint8_t>(p10 & 0x1F);
    const uint8_t  l1  = leftShift5(l0, 1), r1 = leftShift5(r0, 1);  // 左移 1 位
    const uint8_t  l3  = leftShift5(l0, 3), r3 = leftShift5(r0, 3);  // 累计左移 3 位
    const uint8_t  chk1 = permute(static_cast<uint16_t>((l1 << 5) | r1), P8, 8, 10);
    const uint8_t  chk2 = permute(static_cast<uint16_t>((l3 << 5) | r3), P8, 8, 10);

    std::cout << "---- 1. 密钥扩展 Keygen(K) ----" << std::endl;
    std::cout << "  K    (10bit)      : " << toBinaryString(key, 10) << std::endl;
    std::cout << "  P10(K)            : " << toBinaryString(p10, 10) << std::endl;
    std::cout << "  L0 | R0           : " << toBinaryString(l0, 5)
              << " | " << toBinaryString(r0, 5) << std::endl;
    std::cout << "  LS1: L | R        : " << toBinaryString(l1, 5)
              << " | " << toBinaryString(r1, 5) << std::endl;
    std::cout << "  LS3: L | R        : " << toBinaryString(l3, 5)
              << " | " << toBinaryString(r3, 5) << std::endl;
    std::cout << "  k1 = P8(LS1)      : " << toBinaryString(k1, 8)
              << "   " << (k1 == chk1 ? "[手工复现一致]" : "[手工复现不一致]") << std::endl;
    std::cout << "  k2 = P8(LS3)      : " << toBinaryString(k2, 8)
              << "   " << (k2 == chk2 ? "[手工复现一致]" : "[手工复现不一致]") << std::endl;
}

// ---------------------------------------------------------------------------
// 2. 轮函数 F(R, sk) 的分步展开
// ---------------------------------------------------------------------------
void printRoundFunction(uint8_t r4, uint8_t subKey, const char* title) {
    const uint8_t ep  = permute(r4, EP, 8, 4);                       // EP 扩展 4 -> 8
    const uint8_t mix = static_cast<uint8_t>(ep ^ subKey);           // 与子密钥异或
    const uint8_t s1  = sboxLookup(static_cast<uint8_t>((mix >> 4) & 0x0F), SBOX1);
    const uint8_t s2  = sboxLookup(static_cast<uint8_t>(mix & 0x0F), SBOX2);
    const uint8_t sp  = permute(static_cast<uint8_t>((s1 << 2) | s2), SP, 4, 4);
    const uint8_t chk = fFunc(r4, subKey);

    std::cout << "    " << title << std::endl;
    std::cout << "      R (4bit)          = " << toBinaryString(r4, 4) << std::endl;
    std::cout << "      EP(R)             = " << toBinaryString(ep, 8) << std::endl;
    std::cout << "      子密钥 sk         = " << toBinaryString(subKey, 8) << std::endl;
    std::cout << "      EP(R) XOR sk      = " << toBinaryString(mix, 8) << std::endl;
    std::cout << "      SBox1(sk1) / SBox2 = " << toBinaryString(s1, 2)
              << " / " << toBinaryString(s2, 2) << std::endl;
    std::cout << "      F = SPBox(...)    = " << toBinaryString(sp, 4)
              << "   " << (sp == chk ? "[与 fFunc() 一致]" : "[与 fFunc() 不一致]") << std::endl;
}

// ---------------------------------------------------------------------------
// 3. 加密 / 解密全过程
// ---------------------------------------------------------------------------
uint8_t printEncryptTrace(uint8_t plain, uint8_t k1, uint8_t k2) {
    std::cout << std::endl << "---- 2. 加密 E(K, P) ----" << std::endl;
    std::cout << "  P (明文 8bit)     : " << toBinaryString(plain, 8) << std::endl;

    const uint8_t ip = permute(plain, IP, 8, 8);                     // 初始置换
    std::cout << "  IP(P)             : " << toBinaryString(ip, 8)
              << "   (L0=" << toBinaryString(static_cast<uint8_t>((ip >> 4) & 0x0F), 4)
              << " R0=" << toBinaryString(static_cast<uint8_t>(ip & 0x0F), 4) << ")"
              << std::endl;

    std::cout << "    -- 第一轮 (子密钥 k1) --" << std::endl;
    printRoundFunction(static_cast<uint8_t>(ip & 0x0F), k1, "F(R0, k1):");
    const uint8_t t1 = fk(ip, k1);
    std::cout << "  fk1 输出          : " << toBinaryString(t1, 8) << std::endl;

    const uint8_t t2 = sw(t1);                                        // 交换左右 4 bit
    std::cout << "  SW 交换后         : " << toBinaryString(t2, 8)
              << "   (L1=" << toBinaryString(static_cast<uint8_t>((t2 >> 4) & 0x0F), 4)
              << " R1=" << toBinaryString(static_cast<uint8_t>(t2 & 0x0F), 4) << ")"
              << std::endl;

    std::cout << "    -- 第二轮 (子密钥 k2) --" << std::endl;
    printRoundFunction(static_cast<uint8_t>(t2 & 0x0F), k2, "F(R1, k2):");
    const uint8_t t3 = fk(t2, k2);
    std::cout << "  fk2 输出          : " << toBinaryString(t3, 8) << std::endl;

    const uint8_t cipher = permute(t3, IP_INV, 8, 8);                // 最终置换
    std::cout << "  IP^-1 输出        : " << toBinaryString(cipher, 8)
              << "   <== 密文 C" << std::endl;
    return cipher;
}

void printDecryptTrace(uint8_t cipher, uint8_t k1, uint8_t k2, uint8_t expected) {
    std::cout << std::endl << "---- 3. 解密 D(K, C) ----" << std::endl;
    std::cout << "  C (密文 8bit)     : " << toBinaryString(cipher, 8) << std::endl;

    const uint8_t ip = permute(cipher, IP, 8, 8);
    std::cout << "  IP(C)             : " << toBinaryString(ip, 8) << std::endl;

    const uint8_t t1 = fk(ip, k2);          // 注意：解密先用 k2
    std::cout << "  fk(·, k2) 第一轮  : " << toBinaryString(t1, 8) << std::endl;
    const uint8_t t2 = sw(t1);
    std::cout << "  SW 交换后         : " << toBinaryString(t2, 8) << std::endl;
    const uint8_t t3 = fk(t2, k1);          // 再用 k1
    std::cout << "  fk(·, k1) 第二轮  : " << toBinaryString(t3, 8) << std::endl;

    const uint8_t plain = permute(t3, IP_INV, 8, 8);
    std::cout << "  IP^-1 输出        : " << toBinaryString(plain, 8)
              << "   <== 明文 P" << std::endl;
    std::cout << "  往返校验          : "
              << (plain == expected ? "[PASS] 解密结果与原始明文一致"
                                    : "[FAIL] 解密结果与原始明文不一致")
              << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    uint16_t key   = kDefaultKey;
    uint8_t  plain = kDefaultPlain;

    if (argc >= 3) {
        if (!parseKeyArg(argv[1], key) || !parseByteArg(argv[2], plain)) {
            std::cerr << "参数格式错误。用法: level1_basic_test <密钥 10bit> <明文 8bit>\n"
                         "  密钥/明文可写二进制串（如 1010000010）、0x 十六进制或十进制。"
                      << std::endl;
            return 1;
        }
    } else if (argc == 2) {
        std::string a = argv[1];
        if (a == "-h" || a == "--help") {
            std::cout << "用法: level1_basic_test [<密钥 10bit> <明文 8bit>]\n"
                         "  不带参数时使用默认 K=1010000010, P=00101000" << std::endl;
            return 0;
        }
    }

    std::cout << "==========================================================" << std::endl;
    std::cout << " 关卡 1：基本测试 —— S-DES 8 bit 加解密" << std::endl;
    std::cout << "==========================================================" << std::endl;

    uint8_t k1 = 0, k2 = 0;
    generateSubKeys(key, k1, k2);

    printKeySchedule(key);

    const uint8_t cipher = printEncryptTrace(plain, k1, k2);
    printDecryptTrace(cipher, k1, k2, plain);

    // ---- 同时调用库函数复核，防止“手写流程”与“库函数”不一致 ----
    const uint8_t libC = encrypt(plain, key);
    const uint8_t libP = decrypt(libC, key);
    std::cout << std::endl << "---- 4. 结果汇总 ----" << std::endl;
    std::cout << "  密钥 K            : " << toBinaryString(key, 10) << std::endl;
    std::cout << "  子密钥 k1 / k2    : " << toBinaryString(k1, 8)
              << " / " << toBinaryString(k2, 8) << std::endl;
    std::cout << "  明文 P            : " << toBinaryString(plain, 8)
              << "  (" << hexByte(plain) << ")" << std::endl;
    std::cout << "  密文 C            : " << toBinaryString(cipher, 8)
              << "  (" << hexByte(cipher) << ")" << std::endl;
    std::cout << "  解密还原          : " << toBinaryString(libP, 8)
              << "  " << (libP == plain ? "[PASS]" : "[FAIL]") << std::endl;
    std::cout << "  与库函数 encrypt() 一致性: "
              << (libC == cipher ? "[一致]" : "[不一致]") << std::endl;

    const bool ok = (libP == plain) && (libC == cipher);
    std::cout << std::endl << (ok ? "关卡 1 测试通过。" : "关卡 1 测试失败！") << std::endl;
    return ok ? 0 : 2;
}
