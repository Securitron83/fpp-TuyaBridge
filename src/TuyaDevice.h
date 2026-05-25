#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#if __has_include(<jsoncpp/json/json.h>)
#include <jsoncpp/json/json.h>
#elif __has_include(<json/json.h>)
#include <json/json.h>
#endif

class TuyaDevice {
public:
    enum class Type {
        SIMPLE_SWITCH,
        SIMPLE_DIMMER,
        RGBTW_LIGHT,
        GENERIC,
    };

    TuyaDevice(const std::string& name,
               const std::string& ip,
               const std::string& deviceId,
               const std::string& localKey,
               const std::string& version,
               Type               type = Type::SIMPLE_SWITCH);
    ~TuyaDevice();

    // Non-copyable
    TuyaDevice(const TuyaDevice&)            = delete;
    TuyaDevice& operator=(const TuyaDevice&) = delete;

    const std::string& getName()    const { return m_name; }
    const std::string& getIp()      const { return m_ip; }
    Type               getType()    const { return m_type; }
    bool               isConnected() const;

    // Attempt TCP connection to the device. Returns false on failure.
    bool connect();
    void disconnect();

    // High-level device control — thread-safe.
    // Returns false if the device is unreachable or the send fails.
    bool setSwitch(bool on);

    // brightness: 0–100 mapped to Tuya 0–1000
    bool setDimmer(int brightness);

    // r, g, b: 0–255; converted to Tuya HSV color string on DPS 5
    bool setColor(uint8_t r, uint8_t g, uint8_t b);

    // Send an arbitrary DPS map — values must be bool, int, or string JSON nodes.
    bool sendRawDps(const Json::Value& dps);

    static Type typeFromString(const std::string& s);
    static std::string typeToString(Type t);

private:
    std::string m_name;
    std::string m_ip;
    std::string m_deviceId;
    std::string m_localKey;
    std::string m_version;
    Type        m_type;

    int      m_sock     = -1;
    uint32_t m_sequence = 0;
    mutable std::mutex m_mutex;

    bool ensureConnected();
    bool sendJson(const Json::Value& payload);
    bool sendPacket(const std::vector<uint8_t>& packet);

    static std::string rgbToTuyaColor(uint8_t r, uint8_t g, uint8_t b);
};
