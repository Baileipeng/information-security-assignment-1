#ifndef SDES_CONSOLE_UTILS_H
#define SDES_CONSOLE_UTILS_H

#include <cstdint>
#include <iostream>
#include <string>

#include "sdes.h"

// ---------------------------------------------------------------------------
// 控制台程序的公共小工具（纯头文件实现，各关卡程序与 sdes_console 共用）
//
//   - 命令行参数解析：同时支持 二进制串 / 0x 十六进制 / 十进制 三种写法
//   - 位串打印：二进制与十六进制并列输出，便于交叉测试时人工核对
// ---------------------------------------------------------------------------
namespace sdes {

// 解析 8 bit 数值参数：8 位二进制串 / 0x 十六进制 / 十进制
inline bool parseByteArg(const std::string& arg, uint8_t& out) {
    if (arg.size() > 2 &&
        (arg.compare(0, 2, "0x") == 0 || arg.compare(0, 2, "0X") == 0)) {
        try {
            unsigned long v = std::stoul(arg, nullptr, 16);
            if (v > 0xFF) return false;
            out = static_cast<uint8_t>(v);
            return true;
        } catch (...) {
            return false;
        }
    }
    if (arg.size() == 8 && arg.find_first_not_of("01") == std::string::npos) {
        uint16_t v = 0;
        if (!parseBinaryString(arg, 8, v)) return false;
        out = static_cast<uint8_t>(v);
        return true;
    }
    try {
        unsigned long v = std::stoul(arg);
        if (v > 0xFF) return false;
        out = static_cast<uint8_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

// 解析 10 bit 密钥参数：10 位二进制串 / 0x 十六进制 / 十进制
inline bool parseKeyArg(const std::string& arg, uint16_t& out) {
    if (arg.size() == 10 && arg.find_first_not_of("01") == std::string::npos) {
        return parseBinaryString(arg, 10, out);
    }
    try {
        unsigned long v = std::stoul(arg, nullptr, 0);
        if (v > 0x3FF) return false;
        out = static_cast<uint16_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

// 打印 "标签: 二进制串 (0x??)"
inline void printBits(const std::string& label, const std::string& bits) {
    std::cout << label << ": " << bits
              << "  (0x" << std::hex << std::stoul(bits, nullptr, 2) << std::dec << ")"
              << std::endl;
}

// 单字节 -> "0xAB"（两位大写十六进制，带前缀）
inline std::string hexByte(uint8_t v) {
    static const char* kDigits = "0123456789ABCDEF";
    std::string s = "0x";
    s.push_back(kDigits[(v >> 4) & 0x0F]);
    s.push_back(kDigits[v & 0x0F]);
    return s;
}

// 单字节 -> "ab"（两位小写十六进制，无前缀，文本密文串用）
inline std::string hexBytePlain(uint8_t v) {
    static const char* kDigits = "0123456789abcdef";
    std::string s;
    s.push_back(kDigits[(v >> 4) & 0x0F]);
    s.push_back(kDigits[v & 0x0F]);
    return s;
}

// 打印一行二级标题
inline void printSection(const std::string& title) {
    std::cout << std::endl << "---- " << title << " ----" << std::endl;
}

} // namespace sdes

#endif // SDES_CONSOLE_UTILS_H
