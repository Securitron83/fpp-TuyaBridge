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

    // v3.4/3.5 devices stay silent until a session key has been negotiated.
    if (usesSession()) {
        if (!negotiateSession()) {
            closeSocket();
            return false;
        }
        return true;
    }

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
    closeSocket();
}

void TuyaDevice::closeSocket() {
    // Caller must hold m_mutex
    if (m_sock >= 0) {
        ::close(m_sock);
        m_sock = -1;
    }
    m_sessionKey.clear();
    m_rxBuf.clear();
}

std::vector<uint8_t> TuyaDevice::buildSessionPacket(const std::string& key,
                                                    const std::string& plaintext,
                                                    uint32_t command) {
    // Caller must hold m_mutex
    if (m_version == "3.5")
        return Tuya::buildPacket35(key, plaintext, m_sequence++, command);
    return Tuya::buildPacket34(key, plaintext, m_sequence++, command);
}

bool TuyaDevice::readFrame(const std::string& key, int timeoutMs, Tuya::Frame& out) {
    // Caller must hold m_mutex
    for (;;) {
        long used = (m_version == "3.5") ? Tuya::decodeFrame35(m_rxBuf, key, out)
                                         : Tuya::decodeFrame34(m_rxBuf, key, out);
        if (used > 0) {
            m_rxBuf.erase(m_rxBuf.begin(), m_rxBuf.begin() + used);
            return true;
        }
        if (used < 0) {
            TuyaLog::debug("Device '%s': could not authenticate frame (wrong key?)", m_name.c_str());
            m_rxBuf.clear();
            return false;
        }

        struct pollfd pfd;
        pfd.fd     = m_sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeoutMs) <= 0 || !(pfd.revents & POLLIN))
            return false;
        uint8_t buf[1024];
        ssize_t n = recv(m_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0)
            return false;
        m_rxBuf.insert(m_rxBuf.end(), buf, buf + n);
    }
}

bool TuyaDevice::negotiateSession() {
    // Caller must hold m_mutex
    // 1. Send our nonce encrypted with the local key.
    // 2. Device replies with its nonce + HMAC(localKey, ourNonce), proving it has the key.
    // 3. We reply HMAC(localKey, deviceNonce); both sides derive the session key.
    m_sessionKey.clear();
    m_rxBuf.clear();
    // v3.5 firmware drops the connection on a frame with sequence number 0.
    if (m_sequence == 0)
        m_sequence = 1;

    std::string localNonce = Tuya::randomNonce16();
    if (!sendPacket(buildSessionPacket(m_localKey, localNonce, Tuya::CMD_SESS_KEY_NEG_START)))
        return false;

    Tuya::Frame resp;
    if (!readFrame(m_localKey, CONNECT_TIMEOUT_S * 1000, resp) ||
        resp.command != Tuya::CMD_SESS_KEY_NEG_RESP) {
        TuyaLog::err("Device '%s': no v%s session key response (wrong key or version?)",
                     m_name.c_str(), m_version.c_str());
        return false;
    }

    std::string body = resp.payload;
    if (body.size() == 52)  // retcode not detected by the frame decoder
        body.erase(0, 4);
    if (body.size() < 48) {
        TuyaLog::err("Device '%s': short session key response (%zu bytes)", m_name.c_str(), body.size());
        return false;
    }
    std::string remoteNonce = body.substr(0, 16);
    if (body.substr(16, 32) != Tuya::hmacSha256(m_localKey, localNonce)) {
        TuyaLog::err("Device '%s': session key response failed verification (wrong key?)", m_name.c_str());
        return false;
    }

    if (!sendPacket(buildSessionPacket(m_localKey, Tuya::hmacSha256(m_localKey, remoteNonce),
                                       Tuya::CMD_SESS_KEY_NEG_FINISH)))
        return false;

    m_sessionKey = Tuya::deriveSessionKey(m_version, m_localKey, localNonce, remoteNonce);
    if (m_sessionKey.size() != 16) {
        TuyaLog::err("Device '%s': session key derivation failed", m_name.c_str());
        return false;
    }
    TuyaLog::info("Device '%s': v%s session established", m_name.c_str(), m_version.c_str());
    return true;
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
        closeSocket();
        return false;
    }

    return true;
}

bool TuyaDevice::sendJson(const Json::Value& dps) {
    // Caller must hold m_mutex

    // Build JSON payload in the exact field order tuyapi uses:
    //   devId, uid, t, dps
    // jsoncpp sorts keys alphabetically (devId, dps, t, uid), putting dps before
    // the auth fields. Some Tuya firmware parsers validate devId/uid/t first and
    // then act on dps — if dps appears earlier the parser returns "parse data error".
    // Building the string manually avoids the sort and matches tuyapi exactly.
    Json::StreamWriterBuilder wb;
    wb["indentation"] = "";
    std::string dpsStr = Json::writeString(wb, dps);

    if (usesSession())
        return sendJsonSession(dpsStr);

    std::string jsonStr =
        "{\"devId\":\"" + m_deviceId +
        "\",\"uid\":\""  + m_deviceId +
        "\",\"t\":\""    + std::to_string(std::time(nullptr)) +
        "\",\"dps\":"    + dpsStr + "}";

    if (TuyaLog::debugEnabled()) {
        TuyaLog::debug("--- sending to device '%s'  id=%s  ip=%s  ver=%s ---",
                       m_name.c_str(), m_deviceId.c_str(),
                       m_ip.c_str(), m_version.c_str());
        TuyaLog::debug("JSON payload: %s", jsonStr.c_str());
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

    // The reply is read (and the change confirmed) by verifyState().
    return sendPacket(pkt);
}

bool TuyaDevice::sendJsonSession(const std::string& dpsStr) {
    // Caller must hold m_mutex
    // v3.4/3.5 CONTROL_NEW payload: {"protocol":5,"t":<int>,"data":{"dps":{...}}},
    // prefixed with the version header and encrypted with the session key.
    std::string jsonStr =
        "{\"protocol\":5,\"t\":" + std::to_string(std::time(nullptr)) +
        ",\"data\":{\"dps\":" + dpsStr + "}}";

    if (TuyaLog::debugEnabled()) {
        TuyaLog::debug("--- sending to device '%s'  id=%s  ip=%s  ver=%s ---",
                       m_name.c_str(), m_deviceId.c_str(),
                       m_ip.c_str(), m_version.c_str());
        TuyaLog::debug("JSON payload: %s", jsonStr.c_str());
    }

    std::vector<uint8_t> pkt = buildSessionPacket(
        m_sessionKey, Tuya::versionHeader(m_version) + jsonStr, Tuya::CMD_CONTROL_NEW);
    // The reply is read (and the change confirmed) by verifyState().
    return !pkt.empty() && sendPacket(pkt);
}

// Does the device-reported value match what we sent? Integers (brightness,
// timers) are not compared because firmware may clamp or scale them.
static bool dpsValueMatches(const Json::Value& sent, const Json::Value& reported) {
    if (sent.isBool())
        return reported.isBool() && reported.asBool() == sent.asBool();
    if (sent.isString() && reported.isString()) {
        std::string a = sent.asString(), b = reported.asString();
        std::transform(a.begin(), a.end(), a.begin(), ::tolower);
        std::transform(b.begin(), b.end(), b.begin(), ::tolower);
        return a == b;
    }
    return true;
}

TuyaDevice::Verify TuyaDevice::verifyState(const Json::Value& dps) {
    // Caller must hold m_mutex and an open connection on which dps was just sent.
    // Ask the device for its state and compare it with what we set. Status pushes
    // the device sends on its own after a change count as evidence too.
    if (m_version != "3.3" && !usesSession())
        return Verify::UNVERIFIABLE;  // v3.1: no query support in this plugin

    std::vector<uint8_t> query;
    if (usesSession()) {
        query = buildSessionPacket(m_sessionKey, "{}", Tuya::CMD_QUERY_NEW);
    } else {
        std::string q = "{\"gwId\":\"" + m_deviceId + "\",\"devId\":\"" + m_deviceId +
                        "\",\"uid\":\"" + m_deviceId + "\",\"t\":\"" +
                        std::to_string(std::time(nullptr)) + "\"}";
        query = Tuya::buildPacket33(m_localKey, q, m_sequence++, Tuya::CMD_QUERY, false);
    }
    if (query.empty() || !sendPacket(query))
        return Verify::UNVERIFIABLE;

    const std::string& key = usesSession() ? m_sessionKey : m_localKey;
    Verify result = Verify::UNVERIFIABLE;
    for (int i = 0; i < 6; ++i) {
        Tuya::Frame f;
        bool got = usesSession() ? readFrame(key, RESPONSE_WAIT_MS, f)
                                 : readFrame33(RESPONSE_WAIT_MS, f);
        if (!got)
            break;

        std::string json = f.payload;
        if (json.size() >= 15 && json.compare(0, 2, "3.") == 0)
            json.erase(0, 15);
        if (json.empty() || json[0] != '{')
            continue;

        Json::Value root;
        Json::CharReaderBuilder rb;
        std::string errs;
        std::istringstream in(json);
        if (!Json::parseFromStream(rb, in, &root, &errs))
            continue;
        const Json::Value& reported = root.isMember("dps") ? root["dps"] : root["data"]["dps"];
        if (!reported.isObject())
            continue;

        TuyaLog::debug("Device '%s' reported: %s", m_name.c_str(), json.c_str());
        bool anyCompared = false, allMatch = true;
        for (const auto& k : dps.getMemberNames()) {
            if (!reported.isMember(k)) continue;
            anyCompared = true;
            if (!dpsValueMatches(dps[k], reported[k])) allMatch = false;
        }
        if (!anyCompared)
            continue;
        if (allMatch)
            return Verify::CONFIRMED;
        // A full status reply that disagrees is a definite miss; keep reading in case
        // a later status push shows the change landing just after the query.
        result = Verify::MISMATCH;
    }
    return result;
}

bool TuyaDevice::readFrame33(int timeoutMs, Tuya::Frame& out) {
    // Caller must hold m_mutex
    for (;;) {
        long used = Tuya::decodeFrame33(m_rxBuf, m_localKey, out);
        if (used > 0) {
            m_rxBuf.erase(m_rxBuf.begin(), m_rxBuf.begin() + used);
            return true;
        }
        if (used < 0) {
            m_rxBuf.clear();
            return false;
        }
        struct pollfd pfd;
        pfd.fd     = m_sock;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, timeoutMs) <= 0 || !(pfd.revents & POLLIN))
            return false;
        uint8_t buf[1024];
        ssize_t n = recv(m_sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0)
            return false;
        m_rxBuf.insert(m_rxBuf.end(), buf, buf + n);
    }
}

bool TuyaDevice::execute(const Json::Value& dps, const char* what) {
    // Caller must hold m_mutex
    // Tuya devices drop idle connections without always telling us, and a
    // command written into such a connection is silently lost. So every command
    // gets a fresh connection, is read back to confirm it took, and is retried once.
    static const int MAX_ATTEMPTS = 2;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        closeSocket();
        if (!connect()) {
            TuyaLog::warn("Device '%s': %s attempt %d/%d — could not connect",
                          m_name.c_str(), what, attempt, MAX_ATTEMPTS);
            continue;
        }
        if (!sendJson(dps)) {
            TuyaLog::warn("Device '%s': %s attempt %d/%d — send failed",
                          m_name.c_str(), what, attempt, MAX_ATTEMPTS);
            closeSocket();
            continue;
        }
        Verify v = verifyState(dps);
        closeSocket();

        if (v == Verify::CONFIRMED) {
            if (attempt > 1)
                TuyaLog::info("Device '%s': %s confirmed on attempt %d", m_name.c_str(), what, attempt);
            else
                TuyaLog::debug("Device '%s': %s confirmed", m_name.c_str(), what);
            return true;
        }
        if (v == Verify::UNVERIFIABLE) {
            TuyaLog::warn("Device '%s': %s sent, but the device did not report its state to confirm it",
                          m_name.c_str(), what);
            return true;
        }
        TuyaLog::warn("Device '%s': %s attempt %d/%d — device state did not change",
                      m_name.c_str(), what, attempt, MAX_ATTEMPTS);
    }
    TuyaLog::err("Device '%s': %s failed after %d attempts", m_name.c_str(), what, MAX_ATTEMPTS);
    return false;
}

bool TuyaDevice::setSwitch(bool on) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Json::Value dps;
    dps["1"] = on;
    return execute(dps, on ? "switch on" : "switch off");
}

bool TuyaDevice::setDimmer(int brightness) {
    std::lock_guard<std::mutex> lock(m_mutex);
    bool on = (brightness > 0);
    int tuyaBrightness = std::min(1000, (brightness * 1000) / 100);

    Json::Value dps;
    dps["1"] = on;
    dps["2"] = tuyaBrightness;
    return execute(dps, "set dimmer");
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
    bool on = (r > 0 || g > 0 || b > 0);
    Json::Value dps;
    dps["1"] = on;
    dps["5"] = rgbToTuyaColor(r, g, b);
    return execute(dps, "set color");
}

bool TuyaDevice::sendRawDps(const Json::Value& dps) {
    std::lock_guard<std::mutex> lock(m_mutex);
    return execute(dps, "send DPS");
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
