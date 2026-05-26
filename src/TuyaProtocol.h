#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Tuya {

enum Command : uint32_t {
    CMD_SET       = 0x07,
    CMD_HEARTBEAT = 0x09,
    CMD_QUERY     = 0x0A,
};

// Build a v3.3 command packet (most common on modern Tuya devices).
// localKey must be exactly 16 bytes; jsonPayload is the raw DPS JSON string.
std::vector<uint8_t> buildPacket33(
    const std::string& localKey,
    const std::string& jsonPayload,
    uint32_t           sequence,
    uint32_t           command = CMD_SET
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
