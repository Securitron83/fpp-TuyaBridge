#include "TuyaProtocol.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <zlib.h>

namespace Tuya {

static const uint8_t PREFIX[4] = {0x00, 0x00, 0x55, 0xAA};
static const uint8_t SUFFIX[4] = {0x00, 0x00, 0xAA, 0x55};

// v3.3 version header: "3.3" + 12 null bytes = 15 bytes.
// tinytuya, pytuya, and real device firmware all use 15 bytes; using 12 shifts
// the encrypted payload 3 bytes into the header field, causing "parse data error".
static const uint8_t VER33[15] = {'3', '.', '3', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

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
                                    uint32_t command,
                                    bool withVersionHeader) {
    auto encrypted = aesEcbEncrypt(localKey, jsonPayload);
    uint32_t headerLen = withVersionHeader ? 15 : 0;

    // length field = version_header(15, optional) + encrypted + CRC(4) + suffix(4)
    uint32_t length = headerLen + static_cast<uint32_t>(encrypted.size()) + 8;

    std::vector<uint8_t> pkt;
    pkt.reserve(4 + 12 + length);

    pkt.insert(pkt.end(), PREFIX, PREFIX + 4);
    pushU32BE(pkt, sequence);
    pushU32BE(pkt, command);
    pushU32BE(pkt, length);
    if (withVersionHeader)
        pkt.insert(pkt.end(), VER33, VER33 + 15);
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
                            const std::string& version,
                            uint32_t* retcodeOut) {
    // Minimum: PREFIX(4)+SEQ(4)+CMD(4)+LEN(4)+RETCODE(4)+CRC(4)+SUFFIX(4) = 28 bytes
    if (pkt.size() < 28) return "";

    if (pkt[0] != 0x00 || pkt[1] != 0x00 || pkt[2] != 0x55 || pkt[3] != 0xAA) return "";

    uint32_t length = readU32BE(pkt.data() + 12);
    if (pkt.size() < 16 + length) return "";

    // Response packets have a 4-byte return code immediately after the fixed header.
    // (Request/command packets do NOT have this field.)
    // Layout from byte 16 onward: RETCODE(4) + [VER33(12)] + ENCRYPTED(N) + CRC(4) + SUFFIX(4)
    if (length < 12) return "";                // need at least retcode + crc + suffix
    uint32_t retcode = readU32BE(pkt.data() + 16);
    if (retcodeOut) *retcodeOut = retcode;

    size_t dataStart = 20;                     // skip retcode
    size_t dataLen   = length - 4 - 8;         // LEN - retcode(4) - CRC(4) - SUFFIX(4)

    if (dataLen == 0) return "";

    if (version == "3.3") {
        // Some v3.3 responses include the 15-byte version header; skip it if present
        if (dataLen >= 15 &&
            pkt[dataStart] == '3' && pkt[dataStart + 1] == '.' && pkt[dataStart + 2] == '3') {
            dataStart += 15;
            dataLen   -= 15;
        }
        if (dataLen == 0) return "";
        return aesEcbDecrypt(localKey, pkt.data() + dataStart, dataLen);
    } else {
        // v3.1 responses are plain JSON (not encrypted)
        return std::string(pkt.begin() + dataStart, pkt.begin() + dataStart + dataLen);
    }
}

// ---------------------------------------------------------------------------
// v3.4 / v3.5
// ---------------------------------------------------------------------------

static const uint8_t PREFIX35[4] = {0x00, 0x00, 0x66, 0x99};
static const uint8_t SUFFIX35[4] = {0x00, 0x00, 0x99, 0x66};

// AES-128-GCM encrypt; returns ciphertext followed by the 16-byte tag.
static bool aesGcmEncrypt(const std::string& key, const uint8_t* iv,
                          const uint8_t* aad, size_t aadLen,
                          const std::string& plaintext, std::vector<uint8_t>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                 reinterpret_cast<const uint8_t*>(key.data()), iv) == 1;
    if (ok && aadLen > 0)
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aadLen)) == 1;
    out.assign(plaintext.size() + 16, 0);
    int ctLen = 0;
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(ctx, out.data(), &len,
                               reinterpret_cast<const uint8_t*>(plaintext.data()),
                               static_cast<int>(plaintext.size())) == 1;
        ctLen = len;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, out.data() + ctLen, &len) == 1;
        ctLen += len;
    }
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + ctLen) == 1;
    EVP_CIPHER_CTX_free(ctx);
    out.resize(ctLen + 16);
    return ok;
}

// AES-128-GCM decrypt and verify the tag. Returns false on authentication failure.
static bool aesGcmDecrypt(const std::string& key, const uint8_t* iv,
                          const uint8_t* aad, size_t aadLen,
                          const uint8_t* ct, size_t ctLen, const uint8_t* tag,
                          std::string& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    std::vector<uint8_t> pt(ctLen + 16);
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                 reinterpret_cast<const uint8_t*>(key.data()), iv) == 1;
    if (ok && aadLen > 0)
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aadLen)) == 1;
    int ptLen = 0;
    if (ok && ctLen > 0) {
        ok = EVP_DecryptUpdate(ctx, pt.data(), &len, ct, static_cast<int>(ctLen)) == 1;
        ptLen = len;
    }
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) == 1;
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, pt.data() + ptLen, &len) == 1;
        ptLen += len;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (ok)
        out.assign(reinterpret_cast<const char*>(pt.data()), ptLen);
    return ok;
}

std::string versionHeader(const std::string& version) {
    return version.substr(0, 3) + std::string(12, '\0');
}

std::string randomNonce16() {
    uint8_t buf[16];
    RAND_bytes(buf, sizeof(buf));
    return std::string(reinterpret_cast<const char*>(buf), sizeof(buf));
}

std::string hmacSha256(const std::string& key, const std::string& data) {
    uint8_t mac[32];
    unsigned int macLen = sizeof(mac);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const uint8_t*>(data.data()), data.size(), mac, &macLen);
    return std::string(reinterpret_cast<const char*>(mac), macLen);
}

std::string deriveSessionKey(const std::string& version,
                             const std::string& localKey,
                             const std::string& localNonce,
                             const std::string& remoteNonce) {
    std::string mixed(16, '\0');
    for (size_t i = 0; i < 16; ++i)
        mixed[i] = static_cast<char>(localNonce[i] ^ remoteNonce[i]);

    if (version == "3.5") {
        std::vector<uint8_t> ct;
        if (!aesGcmEncrypt(localKey, reinterpret_cast<const uint8_t*>(localNonce.data()),
                           nullptr, 0, mixed, ct))
            return "";
        return std::string(ct.begin(), ct.begin() + 16);  // ciphertext only, tag dropped
    }

    // v3.4: AES-ECB without padding (input is exactly one block)
    auto ct = aesEcbEncrypt(localKey, mixed);
    return std::string(ct.begin(), ct.begin() + 16);
}

std::vector<uint8_t> buildPacket34(const std::string& key,
                                   const std::string& plaintext,
                                   uint32_t           sequence,
                                   uint32_t           command) {
    auto encrypted = aesEcbEncrypt(key, plaintext);

    // length field = encrypted + HMAC(32) + suffix(4)
    std::vector<uint8_t> pkt;
    pkt.insert(pkt.end(), PREFIX, PREFIX + 4);
    pushU32BE(pkt, sequence);
    pushU32BE(pkt, command);
    pushU32BE(pkt, static_cast<uint32_t>(encrypted.size()) + 36);
    pkt.insert(pkt.end(), encrypted.begin(), encrypted.end());

    std::string mac = hmacSha256(key, std::string(pkt.begin(), pkt.end()));
    pkt.insert(pkt.end(), mac.begin(), mac.end());
    pkt.insert(pkt.end(), SUFFIX, SUFFIX + 4);
    return pkt;
}

std::vector<uint8_t> buildPacket35(const std::string& key,
                                   const std::string& plaintext,
                                   uint32_t           sequence,
                                   uint32_t           command) {
    uint8_t iv[12];
    RAND_bytes(iv, sizeof(iv));

    // Header: PREFIX(4) + reserved(2) + SEQ(4) + CMD(4) + LEN(4).
    // LEN = IV(12) + ciphertext + tag(16); the suffix is not counted.
    std::vector<uint8_t> pkt;
    pkt.insert(pkt.end(), PREFIX35, PREFIX35 + 4);
    pkt.push_back(0);
    pkt.push_back(0);
    pushU32BE(pkt, sequence);
    pushU32BE(pkt, command);
    pushU32BE(pkt, static_cast<uint32_t>(12 + plaintext.size() + 16));

    // AAD is the header after the prefix (14 bytes)
    std::vector<uint8_t> ct;
    if (!aesGcmEncrypt(key, iv, pkt.data() + 4, 14, plaintext, ct))
        return {};

    pkt.insert(pkt.end(), iv, iv + 12);
    pkt.insert(pkt.end(), ct.begin(), ct.end());
    pkt.insert(pkt.end(), SUFFIX35, SUFFIX35 + 4);
    return pkt;
}

// Skip to the first occurrence of prefix in buf; returns its offset or -1.
static long findPrefix(const std::vector<uint8_t>& buf, const uint8_t* prefix) {
    for (size_t i = 0; i + 4 <= buf.size(); ++i)
        if (memcmp(buf.data() + i, prefix, 4) == 0)
            return static_cast<long>(i);
    return -1;
}

long decodeFrame33(const std::vector<uint8_t>& buf, const std::string& key, Frame& out) {
    long start = findPrefix(buf, PREFIX);
    if (start < 0) return 0;
    if (buf.size() < static_cast<size_t>(start) + 16) return 0;

    const uint8_t* p = buf.data() + start;
    uint32_t length = readU32BE(p + 12);
    if (length < 8 || length > 0x10000) return -1;
    if (buf.size() < static_cast<size_t>(start) + 16 + length) return 0;

    out = Frame();
    out.sequence = readU32BE(p + 4);
    out.command  = readU32BE(p + 8);

    const uint8_t* body    = p + 16;
    size_t         bodyLen = length - 8;  // minus CRC(4) + suffix(4)
    // Replies to our commands carry a retcode; device-initiated status pushes
    // start directly with the "3.3" version header instead.
    if (bodyLen >= 4 && !(body[0] == '3' && body[1] == '.' && body[2] == '3')) {
        out.hasRetcode = true;
        out.retcode    = readU32BE(body);
        body    += 4;
        bodyLen -= 4;
    }
    if (bodyLen >= 15 && body[0] == '3' && body[1] == '.' && body[2] == '3') {
        body    += 15;
        bodyLen -= 15;
    }
    if (bodyLen > 0 && bodyLen % 16 == 0) {
        std::string pt = aesEcbDecrypt(key, body, bodyLen);
        if (!pt.empty() && pt[0] == '{')
            out.payload = pt;
    }
    return start + static_cast<long>(16 + length);
}

long decodeFrame34(const std::vector<uint8_t>& buf, const std::string& key, Frame& out) {
    long start = findPrefix(buf, PREFIX);
    if (start < 0) return 0;
    if (buf.size() < static_cast<size_t>(start) + 16) return 0;

    const uint8_t* p = buf.data() + start;
    uint32_t length = readU32BE(p + 12);
    if (length < 36 || length > 0x10000) return -1;
    if (buf.size() < static_cast<size_t>(start) + 16 + length) return 0;

    size_t total   = 16 + length;
    size_t bodyLen = length - 36;  // between header and HMAC

    std::string mac = hmacSha256(key, std::string(p, p + 16 + bodyLen));
    if (CRYPTO_memcmp(mac.data(), p + 16 + bodyLen, 32) != 0) return -1;

    out = Frame();
    out.sequence = readU32BE(p + 4);
    out.command  = readU32BE(p + 8);

    const uint8_t* body = p + 16;
    // Encrypted data is a multiple of 16 bytes, so a 4-byte remainder is the retcode.
    if (bodyLen % 16 == 4) {
        out.hasRetcode = true;
        out.retcode    = readU32BE(body);
        body    += 4;
        bodyLen -= 4;
    }
    if (bodyLen > 0)
        out.payload = aesEcbDecrypt(key, body, bodyLen);
    return start + static_cast<long>(total);
}

long decodeFrame35(const std::vector<uint8_t>& buf, const std::string& key, Frame& out) {
    long start = findPrefix(buf, PREFIX35);
    if (start < 0) return 0;
    if (buf.size() < static_cast<size_t>(start) + 18) return 0;

    const uint8_t* p = buf.data() + start;
    uint32_t length = readU32BE(p + 14);
    if (length < 28 || length > 0x10000) return -1;
    if (buf.size() < static_cast<size_t>(start) + 18 + length + 4) return 0;

    const uint8_t* iv  = p + 18;
    const uint8_t* ct  = iv + 12;
    size_t         ctLen = length - 28;
    const uint8_t* tag = ct + ctLen;

    std::string pt;
    if (!aesGcmDecrypt(key, iv, p + 4, 14, ct, ctLen, tag, pt)) return -1;

    out = Frame();
    out.sequence = readU32BE(p + 6);
    out.command  = readU32BE(p + 10);
    // Device replies start with a 4-byte retcode; it is always a small value,
    // whereas JSON, version headers and nonces never start with three zero bytes.
    if (pt.size() >= 4 && pt[0] == 0 && pt[1] == 0 && pt[2] == 0) {
        out.hasRetcode = true;
        out.retcode    = static_cast<uint8_t>(pt[3]);
        pt.erase(0, 4);
    }
    out.payload = pt;
    return start + static_cast<long>(18 + length + 4);
}

} // namespace Tuya
