// ===========================================================================
// 关卡 3：扩展功能 —— 对 ASCII 字符串做分组加解密
// ===========================================================================
//
// 【关卡要求】
//   S-DES 的分组长度只有 8 bit，把扩展功能做成“对任意 ASCII 字符串加密”：
//   把字符串按字符拆成若干 8 bit 分组，逐组用同一密钥加密 / 解密。
//
// 【实现要点】
//   * 分组模式：ECB（电子密码本）——每个字符独立加密，实现最简单，
//     但相同字符会产生相同密文（本程序会把这一点作为结论打印出来）；
//   * 字符集：取每个字符的低 8 位（ASCII），非 ASCII 宽字符会被截断；
//   * 密文表示：同时给出二进制串与 HEX 串，HEX 串可直接粘回解密框。
//
// 【编译】
//   g++ -std=c++17 -O2 -I../src ../src/sdes.cpp main.cpp -o level3_ascii_text
//
// 【运行】
//   level3_ascii_text                                    默认文本 "This is a test"
//   level3_ascii_text <key10> "文本"                     指定密钥与文本
//   level3_ascii_text <key10> <hex密文> --decrypt        仅解密
//
// 【实测结果】
//   K=1010000010, "This is a test" -> HEX 0b446f8fce6f8fce95cee3d08fe3，
//   解密后完整还原原文。
// ===========================================================================

#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "console_utils.h"
#include "sdes.h"

using namespace sdes;

namespace {

const uint16_t kDefaultKey  = 0b1010000010u;
const std::string kDefaultText = "This is a test";

// 逐字符加密：返回每组的密文，并打印分组明细表
std::vector<uint8_t> encryptText(const std::string& text, uint16_t key) {
    std::vector<uint8_t> out;
    out.reserve(text.size());

    std::cout << "---- 1. 分组加密（ECB，每组 8 bit） ----" << std::endl;
    std::cout << " 序号 | 字符 | ASCII(dec) | 明文字节 | 密文字节 | 密文HEX" << std::endl;
    std::cout << "------+------+------------+----------+----------+--------" << std::endl;

    int idx = 0;
    for (unsigned char ch : text) {
        const uint8_t c = encrypt(ch, key);
        out.push_back(c);
        std::cout << std::setw(5) << ++idx << " |  " << static_cast<char>(ch)
                  << "   |    " << std::setw(3) << static_cast<int>(ch)
                  << "     | " << toBinaryString(ch, 8)
                  << " | " << toBinaryString(c, 8)
                  << " |  " << hexBytePlain(c) << std::endl;
    }
    return out;
}

// 把密文字节拼成二进制串与 HEX 串
void printCipherString(const std::vector<uint8_t>& cipher) {
    std::string bin, hex;
    for (size_t i = 0; i < cipher.size(); ++i) {
        bin += toBinaryString(cipher[i], 8);
        hex += hexBytePlain(cipher[i]);
        if (i + 1 < cipher.size()) bin += ' ';
    }
    std::cout << std::endl << "---- 2. 密文串 ----" << std::endl;
    std::cout << " 长度        : " << cipher.size() << " 字节（每组 8 bit）" << std::endl;
    std::cout << " 二进制密文  : " << bin << std::endl;
    std::cout << " HEX 密文    : " << hex << std::endl;
}

// 解密并由密文还原原文
std::string decryptText(const std::vector<uint8_t>& cipher, uint16_t key,
                        const std::string& original) {
    std::string out;
    out.reserve(cipher.size());
    for (uint8_t c : cipher) out.push_back(static_cast<char>(decrypt(c, key)));

    std::cout << std::endl << "---- 3. 解密与还原 ----" << std::endl;
    std::cout << " 还原文本    : " << out << std::endl;
    std::cout << " 原始文本    : " << original << std::endl;
    std::cout << " 一致性校验  : "
              << (out == original ? "[PASS] 解密结果与原文完全一致"
                                  : "[FAIL] 解密结果与原文不一致")
              << std::endl; 
    return out;
}

// 统计密文中重复出现的字节，说明 ECB 模式的确定性特征
void printEcbNote(const std::vector<uint8_t>& cipher) {
    std::map<uint8_t, int> freq;
    for (uint8_t c : cipher) ++freq[c];
    int repeated = 0;
    for (const auto& kv : freq) if (kv.second > 1) ++repeated;

    std::cout << std::endl << "---- 4. 分组模式说明（ECB） ----" << std::endl;
    std::cout << " 不同密文字节值 : " << freq.size()
              << " / " << cipher.size() << " 个" << std::endl;
    std::cout << " 出现重复的字节值 : " << repeated << " 种" << std::endl;
    std::cout << " 结论：ECB 模式下相同明文分组必然得到相同密文分组（确定性加密），"
              << std::endl;
    std::cout << "       因此密文会泄漏“哪些字符相同”的统计信息；" << std::endl;
    std::cout << "       若要消除该特征，需要在分组前引入随机化（如 CBC / 随机 IV）。"
              << std::endl;
}

} // namespace

int main(int argc, char* argv[]) {
    uint16_t key = kDefaultKey;
    std::string text = kDefaultText;
    bool decryptOnly = false;
    std::string hexInput;

    // 参数解析：先收集标志位，再按位置解析（密钥、文本/HEX 密文）
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--decrypt") { decryptOnly = true; continue; }
        if (a == "-h" || a == "--help") {
            std::cout << "用法:\n"
                         "  level3_ascii_text [<密钥 10bit> [\"文本\"]]\n"
                         "  level3_ascii_text <密钥 10bit> <hex密文> --decrypt\n" << std::endl;
            return 0;
        }
        positional.push_back(a);
    }
    if (!positional.empty() && !parseKeyArg(positional[0], key)) {
        std::cerr << "密钥格式错误（须为 10 bit 二进制 / 0x / 十进制）" << std::endl;
        return 1;
    }
    if (positional.size() >= 2) {
        if (decryptOnly) hexInput = positional[1];
        else             text     = positional[1];
    }

    std::cout << "==========================================================" << std::endl;
    std::cout << " 关卡 3：扩展功能 —— ASCII 字符串分组加解密（ECB）" << std::endl;
    std::cout << "==========================================================" << std::endl;
    std::cout << " 密钥 K : " << toBinaryString(key, 10) << std::endl;

    // 仅解密模式：把 HEX 密文还原成文本
    if (decryptOnly) {
        if (hexInput.empty()) {
            std::cerr << "仅解密模式需要提供 HEX 密文" << std::endl;
            return 1;
        }
        if (hexInput.size() % 2 != 0) {
            std::cerr << "HEX 长度必须为偶数" << std::endl;
            return 1;
        }
        std::vector<uint8_t> cipher;
        for (size_t i = 0; i < hexInput.size(); i += 2) {
            cipher.push_back(static_cast<uint8_t>(
                std::stoul(hexInput.substr(i, 2), nullptr, 16)));
        }
        std::string out;
        for (uint8_t c : cipher) out.push_back(static_cast<char>(decrypt(c, key)));
        std::cout << " HEX 密文    : " << hexInput << std::endl;
        std::cout << " 解密文本    : " << out << std::endl;
        return 0;
    }

    std::cout << " 明文文本: " << text << "（" << text.size() << " 个字符）" << std::endl
              << std::endl;

    std::vector<uint8_t> cipher = encryptText(text, key);
    printCipherString(cipher);
    const std::string restored = decryptText(cipher, key, text);
    printEcbNote(cipher);

    const bool ok = (restored == text);
    std::cout << std::endl << (ok ? "关卡 3 测试通过。" : "关卡 3 测试失败！") << std::endl;
    return ok ? 0 : 2;
}
