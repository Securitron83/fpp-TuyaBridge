#include "TuyaProtocol.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <zlib.h>

namespace Tuya {

static const uint8_t PREFIX[4] = {0x00, 0x00, 0x55, 0xAA};
static const uint8_t SUFFIX[4] = {0x00, 0x00, 0xAA, 0x55};

// v3.3 version header: "3.3" + 9 null bytes = 12 bytes
static const uint8_t VER33[12] = {'3', '.', '3', 0, 0, 0, 0, 0, 0, 0, 0, 0};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static void pushU32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v      ) & 0xFF));
}

static uint32_t readU32BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
            static_cast<uint32_t>(p[3]);
}

// AES-128-ECB encrypt with PKCS7 padding
static std::vector<uint8_t> aesEcbEncrypt(const std::string& key, const std::string& plaintext) {
    size_t padLen = 16 - (plaintext.size() % 16);
    std::string padded = plaintext + std::string(padLen, static_cast<char>(padLen));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
                       reinterpret_cast<const uint8_t*>(key.data()), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<uint8_t> out(padded.size());
    int outLen = 0, finalLen = 0;
    EVP_EncryptUpdate(ctx, out.data(), &outLen,
                      reinterpret_cast<const uint8_t*>(padded.data()), padded.size());
    EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(outLen + finalLen);
    return out;
}

// AES-128-ECB decrypt, removes PKCS7 padding, returns plaintext
static std::string aesEcbDecrypt(const std::string& key, const uint8_t* data, size_t len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
                       reinterpret_cast<const uint8_t*>(key.data()), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<uint8_t> out(len);
    int outLen = 0, finalLen = 0;
    EVP_DecryptUpdate(ctx, out.data(), &outLen, data, len);
    EVP_DecryptFinal_ex(ctx, out.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);

    int total = outLen + finalLen;
    if (total > 0) {
        int pad = out[total - 1];
        if (pad >= 1 && pad <= 16)
            total -= pad;
    }
    return std::string(out.begin(), out.begin() + total);
}

// Standard CRC32 (zlib) over the first len bytes
static uint32_t computeCRC(const uint8_t* data, size_t len) {
    return static_cast<uint32_t>(crc32(0L, data, static_cast<uInt>(len)));
}

// Base64-encode using OpenSSL BIO (no newlines)
static std::string base64Encode(const std::vector<uint8_t>& data) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64, mem);
    BIO_write(mem, data.data(), static_cast<int>(data.size()));
    BIO_flush(mem);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    std::string result(bptr->data, bptr->length);
    BIO_free_all(mem);
    return result;
}

// MD5 hex digest via EVP (avoids OpenSSL 3.x deprecation of raw MD5())
static std::string md5Hex(const std::string& data) {
    unsigned char digest[16];
    unsigned int digestLen = 16;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest, &digestLen);
    EVP_MD_CTX_free(ctx);

    std::ostringstream ss;
    for (int i = 0; i < 16; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    return ss.str();
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<uint8_t> buildPacket33(const std::string& localKey,
                                    const std::string& jsonPayload,
                                    uint32_t sequence,
                                    uint32_t command) {
    auto encrypted = aesEcbEncrypt(localKey, jsonPayload);

    // length field = version_header(12) + encrypted + CRC(4) + suffix(4)
    uint32_t length = 12 + static_cast<uint32_t>(encrypted.size()) + 8;

    std::vector<uint8_t> pkt;
    pkt.reserve(4 + 12 + length);

    pkt.insert(pkt.end(), PREFIX, PREFIX + 4);
    pushU32BE(pkt, sequence);
    pushU32BE(pkt, command);
    pushU32BE(pkt, length);
    pkt.insert(pkt.end(), VER33, VER33 + 12);
    pkt.insert(pkt.end(), encrypted.begin(), encrypted.end());

    uint32_t crc = computeCRC(pkt.data(), pkt.size());
    pushU32BE(pkt, crc);
    pkt.insert(pkt.end(), SUFFIX, SUFFIX + 4);

    return pkt;
}

std::vector<uint8_t> buildPacket31(const std::string& localKey,
                                    const std::string& deviceId,
                                    const std::string& jsonPayload,
                                    uint32_t sequence,
                                    uint32_t command) {
    auto encrypted = aesEcbEncrypt(localKey, jsonPayload);
    std::string b64 = base64Encode(encrypted);

    // MD5("data=" + b64 + "||lpv=3.1||" + localKey), take chars [8,24)
    std::string toHash = "data=" + b64 + "||lpv=3.1||" + localKey;
    std::string digest = md5Hex(toHash).substr(8, 16);

    std::string payload = "data=" + b64 + "||lpv=3.1||" + digest;

    uint32_t length = static_cast<uint32_t>(payload.size()) + 8;

    std::vector<uint8_t> pkt;
    pkt.reserve(16 + payload.size() + 8);

    pkt.insert(pkt.end(), PREFIX, PREFIX + 4);
    pushU32BE(pkt, sequence);
    pushU32BE(pkt, command);
    pushU32BE(pkt, length);
    pkt.insert(pkt.end(), payload.begin(), payload.end());

    uint32_t crc = computeCRC(pkt.data(), pkt.size());
    pushU32BE(pkt, crc);
    pkt.insert(pkt.end(), SUFFIX, SUFFIX + 4);

    return pkt;
}

std::string decodeResponse(const std::vector<uint8_t>& pkt,
                            const std::string& localKey,
                            const std::string& version) {
    // Minimum packet: prefix(4) + seq(4) + cmd(4) + len(4) + crc(4) + suffix(4) = 24
    if (pkt.size() < 24) return "";

    // Verify prefix and suffix
    if (pkt[0] != 0x00 || pkt[1] != 0x00 || pkt[2] != 0x55 || pkt[3] != 0xAA) return "";

    uint32_t length = readU32BE(pkt.data() + 12);
    // length includes the data, CRC, and suffix (8 bytes at end)
    if (pkt.size() < 16 + length) return "";

    size_t dataStart = 16;
    size_t dataLen   = length - 8; // strip CRC + suffix

    if (dataLen == 0) return "";

    if (version == "3.3") {
        // Skip 12-byte version header if present
        if (dataLen >= 12 &&
            pkt[dataStart] == '3' && pkt[dataStart + 1] == '.' && pkt[dataStart + 2] == '3') {
            dataStart += 12;
            dataLen   -= 12;
        }
        if (dataLen == 0) return "";
        return aesEcbDecrypt(localKey, pkt.data() + dataStart, dataLen);
    } else {
        // v3.1 status responses are plain JSON (not encrypted)
        return std::string(pkt.begin() + dataStart, pkt.begin() + dataStart + dataLen);
    }
}

} // namespace Tuya
