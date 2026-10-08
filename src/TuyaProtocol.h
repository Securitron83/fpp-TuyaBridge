#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Tuya {

enum Command : uint32_t {
    CMD_SESS_KEY_NEG_START  = 0x03,  // v3.4/3.5 session key negotiation
    CMD_SESS_KEY_NEG_RESP   = 0x04,
    CMD_SESS_KEY_NEG_FINISH = 0x05,
    CMD_SET                 = 0x07,
    CMD_HEARTBEAT           = 0x09,
    CMD_QUERY               = 0x0A,
    CMD_CONTROL_NEW         = 0x0D,  // v3.4/3.5 SET
    CMD_QUERY_NEW           = 0x10,  // v3.4/3.5 QUERY
};

// ---------------------------------------------------------------------------
// v3.4 / v3.5
//
// Both versions negotiate a per-connection session key before any other
// traffic (see TuyaDevice::negotiateSession). Until negotiation finishes, the
// key argument below is the device's local key; afterwards it is the session key.
//
//   v3.4: 0x55AA frames, AES-128-ECB payload, HMAC-SHA256 trailer instead of CRC.
//   v3.5: 0x6699 frames, AES-128-GCM payload (12-byte IV, 16-byte tag).
// ---------------------------------------------------------------------------

// A decoded v3.4/v3.5 frame. payload is the decrypted plaintext with any
// leading return code removed (hasRetcode/retcode report it).
struct Frame {
    uint32_t    sequence   = 0;
    uint32_t    command    = 0;
    bool        hasRetcode = false;
    uint32_t    retcode    = 0;
    std::string payload;
};

// "3.4"/"3.5" + 12 null bytes, prepended to CONTROL_NEW payloads before encryption.
std::string versionHeader(const std::string& version);

std::vector<uint8_t> buildPacket34(const std::string& key,
                                   const std::string& plaintext,
                                   uint32_t           sequence,
                                   uint32_t           command);

std::vector<uint8_t> buildPacket35(const std::string& key,
                                   const std::string& plaintext,
                                   uint32_t           sequence,
                                   uint32_t           command);

// Try to decode one frame from the front of buf. Returns the number of bytes
// consumed (> 0) when a complete frame was found, 0 when more data is needed,
// and -1 when the data is malformed or fails authentication (wrong key).
// Bytes before a frame prefix are skipped and counted as consumed.
// v3.3 counterpart for reading replies and status pushes. CRC is not checked;
// a frame only decodes if its payload decrypts to JSON with the local key.
long decodeFrame33(const std::vector<uint8_t>& buf, const std::string& key, Frame& out);
long decodeFrame34(const std::vector<uint8_t>& buf, const std::string& key, Frame& out);
long decodeFrame35(const std::vector<uint8_t>& buf, const std::string& key, Frame& out);

// Session key negotiation primitives (shared by v3.4 and v3.5).
std::string randomNonce16();
std::string hmacSha256(const std::string& key, const std::string& data);
// v3.4: AES-ECB(localKey, localNonce XOR remoteNonce)
// v3.5: AES-GCM(localKey, iv=localNonce[0..12), localNonce XOR remoteNonce), ciphertext only
std::string deriveSessionKey(const std::string& version,
                             const std::string& localKey,
                             const std::string& localNonce,
                             const std::string& remoteNonce);

// Build a v3.3 command packet (most common on modern Tuya devices).
// localKey must be exactly 16 bytes; jsonPayload is the raw DPS JSON string.
// withVersionHeader must be false for CMD_QUERY (devices reject a header there).
std::vector<uint8_t> buildPacket33(
    const std::string& localKey,
    const std::string& jsonPayload,
    uint32_t           sequence,
    uint32_t           command = CMD_SET,
    bool               withVersionHeader = true
);

// Build a v3.1 command packet (older devices).
std::vector<uint8_t> buildPacket31(
    const std::string& localKey,
    const std::string& deviceId,
    const std::string& jsonPayload,
    uint32_t           sequence,
    uint32_t           command = CMD_SET
);

// Parse a received Tuya response packet and return the plaintext JSON body.
// Response packets have an extra 4-byte return code after the fixed header
// (not present in command/request packets).
// If retcodeOut is non-null, the device's return code is written to it (0 = OK).
// Returns empty string if the packet is malformed or decryption fails.
std::string decodeResponse(
    const std::vector<uint8_t>& packet,
    const std::string&          localKey,
    const std::string&          version,
    uint32_t*                   retcodeOut = nullptr
);

} // namespace Tuya
