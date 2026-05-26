#include "TuyaDevice.h"
#include "TuyaLog.h"
#include "TuyaProtocol.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <ctime>
#include <sstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static const int TUYA_PORT         = 6668;
static const int CONNECT_TIMEOUT_S = 3;
static const int GREETING_DRAIN_MS = 300;  // wait for device greeting on new connection
static const int RESPONSE_WAIT_MS  = 1500; // wait for SET response in debug mode

TuyaDevice::TuyaDevice(const std::string& name,
                        const std::string& ip,
                        const std::string& deviceId,
                        const std::string& localKey,
                        const std::string& version,
                        Type               type)
    : m_name(name),
      m_ip(ip),
      m_deviceId(deviceId),
      m_localKey(localKey),
      m_version(version),
      m_type(type) {}

TuyaDevice::~TuyaDevice() {
    disconnect();
}

bool TuyaDevice::isConnected() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_sock >= 0;
}

bool TuyaDevice::connect() {
    // Caller must hold m_mutex
    if (m_sock >= 0) return true;

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        TuyaLog::err("Device '%s': socket() failed: %s", m_name.c_str(), strerror(errno));
        return false;
    }

    // Set send/receive timeouts
    struct timeval tv;
    tv.tv_sec  = CONNECT_TIMEOUT_S;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(TUYA_PORT);
    if (inet_pton(AF_INET, m_ip.c_str(), &addr.sin_addr) <= 0) {
        TuyaLog::err("Device '%s': invalid IP address '%s'", m_name.c_str(), m_ip.c_str());
        ::close(sock);
        return false;
    }

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        TuyaLog::err("Device '%s': TCP connect to %s:%d failed: %s",
                     m_name.c_str(), m_ip.c_str(), TUYA_PORT, strerror(errno));
        ::close(sock);
        return false;
    }

    m_sock = sock;
    TuyaLog::info("Device '%s': connected to %s:%d", m_name.c_str(), m_ip.c_str(), TUYA_PORT);

    // Many Tuya devices send a STATUS (CMD 0x0A) greeting immediately on connection.
    // We must drain it before sending a SET command or the device will ignore us.
    struct pollfd pfd;
    pfd.fd     = m_sock;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, GREETING_DRAIN_MS) > 0 && (pfd.revents & POLLIN)) {
        uint8_t greeting[512];
        ssize_t n = recv(m_sock, greeting, sizeof(greeting), MSG_DONTWAIT);
        TuyaLog::debug("Device '%s': drained %zd-byte greeting on connect", m_name.c_str(), n);
    }

    return true;
}

void TuyaDevice::disconnect() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_sock >= 0) {
        ::close(m_sock);
        m_sock = -1;
    }
}

bool TuyaDevice::ensureConnected() {
    // Caller must hold m_mutex
    return connect();
}

bool TuyaDevice::sendPacket(const std::vector<uint8_t>& packet) {
    // Caller must hold m_mutex
    if (m_sock < 0) return false;

    if (TuyaLog::debugEnabled()) {
        std::string hex;
        hex.reserve(packet.size() * 3 + packet.size() / 4);
        char buf[3];
        for (size_t i = 0; i < packet.size(); i++) {
            snprintf(buf, sizeof(buf), "%02X", packet[i]);
            hex += buf;
            hex += ((i + 1) % 4 == 0) ? ' ' : ':';
        }
        TuyaLog::debug("tuya/%s/packet  %zu bytes: %s", m_name.c_str(), packet.size(), hex.c_str());
    }

    ssize_t sent = ::send(m_sock, packet.data(), packet.size(), MSG_NOSIGNAL);
    if (sent != static_cast<ssize_t>(packet.size())) {
        TuyaLog::err("Device '%s': send failed (sent %zd of %zu bytes): %s",
                     m_name.c_str(), sent, packet.size(), strerror(errno));
        ::close(m_sock);
        m_sock = -1;
        return false;
    }

    return true;
}

bool TuyaDevice::sendJson(const Json::Value& dps) {
    // Caller must hold m_mutex

    // Standard Tuya local protocol SET payload.
    // gwId is required by many devices and must match devId — omitting it causes
    // silent rejection on a large number of Tuya firmware versions.
    Json::Value payload;
    payload["gwId"]  = m_deviceId;
    payload["devId"] = m_deviceId;
    payload["uid"]   = m_deviceId;
    payload["t"]     = static_cast<Json::Int64>(std::time(nullptr));
    payload["dps"]   = dps;

    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    std::string jsonStr = Json::writeString(wb, payload);

    // Debug: log each DPS key in MQTT-topic style so output is directly
    // comparable to the old tuya-mqtt format: tuya/{name}/dps/{key}/command
    if (TuyaLog::debugEnabled()) {
        TuyaLog::debug("--- sending to device '%s'  id=%s  ip=%s  ver=%s ---",
                       m_name.c_str(), m_deviceId.c_str(),
                       m_ip.c_str(), m_version.c_str());
        for (const auto& key : dps.getMemberNames()) {
            const Json::Value& val = dps[key];
            std::string valStr;
            if (val.isBool())        valStr = val.asBool() ? "true" : "false";
            else if (val.isInt())    valStr = std::to_string(val.asInt());
            else                     valStr = val.asString();
            TuyaLog::debug("  tuya/%s/dps/%s/command  %s",
                           m_name.c_str(), key.c_str(), valStr.c_str());
        }
    }

    std::vector<uint8_t> pkt;
    if (m_version == "3.3") {
        pkt = Tuya::buildPacket33(m_localKey, jsonStr, m_sequence++);
    } else {
        pkt = Tuya::buildPacket31(m_localKey, m_deviceId, jsonStr, m_sequence++);
    }

    if (!sendPacket(pkt))
        return false;

    // Read the device's response.
    // In debug mode: wait up to RESPONSE_WAIT_MS for a full reply and decode it.
    // In normal mode: non-blocking drain so the socket stays clean for next call.
    if (TuyaLog::debugEnabled()) {
        struct pollfd pfd;
        pfd.fd     = m_sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, RESPONSE_WAIT_MS) > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[1024];
            ssize_t n = recv(m_sock, buf, sizeof(buf), MSG_DONTWAIT);
            if (n > 0) {
                std::vector<uint8_t> respPkt(buf, buf + n);
                uint32_t retcode = 0xFFFFFFFF;
                std::string json = Tuya::decodeResponse(respPkt, m_localKey, m_version, &retcode);
                TuyaLog::debug("Device '%s' return code: 0x%08X (%s)",
                               m_name.c_str(), retcode,
                               retcode == 0 ? "OK" : "ERROR");
                if (!json.empty())
                    TuyaLog::debug("Device '%s' response JSON: %s", m_name.c_str(), json.c_str());
                else
                    TuyaLog::debug("Device '%s' response: %zd bytes (could not decode — wrong key or v3.4?)", m_name.c_str(), n);
            } else {
                TuyaLog::debug("Device '%s': no response within %dms", m_name.c_str(), RESPONSE_WAIT_MS);
            }
        } else {
            TuyaLog::debug("Device '%s': no response within %dms", m_name.c_str(), RESPONSE_WAIT_MS);
        }
    } else {
        // Non-debug: quick non-blocking drain so stale data doesn't accumulate
        uint8_t buf[256];
        recv(m_sock, buf, sizeof(buf), MSG_DONTWAIT);
    }

    return true;
}

bool TuyaDevice::setSwitch(bool on) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ensureConnected()) return false;

    Json::Value dps;
    dps["1"] = on;
    return sendJson(dps);
}

bool TuyaDevice::setDimmer(int brightness) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ensureConnected()) return false;

    bool on = (brightness > 0);
    int tuyaBrightness = std::min(1000, (brightness * 1000) / 100);

    Json::Value dps;
    dps["1"] = on;
    dps["2"] = tuyaBrightness;
    return sendJson(dps);
}

// Convert RGB (0–255 each) to Tuya's 12-hex-char HSV color string:
// HHHH SSSS VVVV where H=0-360, S=0-1000, V=0-1000
std::string TuyaDevice::rgbToTuyaColor(uint8_t r, uint8_t g, uint8_t b) {
    float rf = r / 255.0f;
    float gf = g / 255.0f;
    float bf = b / 255.0f;

    float maxc  = std::max({rf, gf, bf});
    float minc  = std::min({rf, gf, bf});
    float delta = maxc - minc;

    float hue = 0.0f;
    if (delta > 0.0f) {
        if (maxc == rf)
            hue = 60.0f * std::fmod((gf - bf) / delta, 6.0f);
        else if (maxc == gf)
            hue = 60.0f * ((bf - rf) / delta + 2.0f);
        else
            hue = 60.0f * ((rf - gf) / delta + 4.0f);
    }
    if (hue < 0.0f) hue += 360.0f;

    float sat = (maxc > 0.0f) ? (delta / maxc) : 0.0f;
    float val = maxc;

    int h = static_cast<int>(hue);
    int s = static_cast<int>(sat * 1000.0f);
    int v = static_cast<int>(val * 1000.0f);

    char buf[13];
    snprintf(buf, sizeof(buf), "%04X%04X%04X", h, s, v);
    return std::string(buf);
}

bool TuyaDevice::setColor(uint8_t r, uint8_t g, uint8_t b) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ensureConnected()) return false;

    bool on = (r > 0 || g > 0 || b > 0);
    Json::Value dps;
    dps["1"] = on;
    dps["5"] = rgbToTuyaColor(r, g, b);
    return sendJson(dps);
}

bool TuyaDevice::sendRawDps(const Json::Value& dps) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ensureConnected()) return false;
    return sendJson(dps);
}

TuyaDevice::Type TuyaDevice::typeFromString(const std::string& s) {
    if (s == "dimmer")    return Type::SIMPLE_DIMMER;
    if (s == "rgblight")  return Type::RGBTW_LIGHT;
    if (s == "generic")   return Type::GENERIC;
    return Type::SIMPLE_SWITCH;
}

std::string TuyaDevice::typeToString(Type t) {
    switch (t) {
    case Type::SIMPLE_DIMMER: return "dimmer";
    case Type::RGBTW_LIGHT:   return "rgblight";
    case Type::GENERIC:       return "generic";
    default:                  return "switch";
    }
}
