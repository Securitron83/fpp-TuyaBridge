/*
 * fpp-TuyaBridge — C++ FPP plugin for controlling Tuya smart devices
 * over the local network without cloud or MQTT dependency.
 *
 * Registers FPP commands usable from sequences, scripts, and playlist entries:
 *   Tuya Bridge - Set Switch  (device, on|off|toggle)
 *   Tuya Bridge - Set Dimmer  (device, 0-100)
 *   Tuya Bridge - Set Color   (device, R, G, B)
 *   Tuya Bridge - Send DPS    (device, dps_key, value)
 *
 * Devices are configured via:
 *   /home/fpp/media/plugins/fpp-TuyaBridge/devices.conf (JSON array)
 */

// Include jsoncpp before any FPP headers (Plugin.h expects it already present)
#if __has_include(<jsoncpp/json/json.h>)
#include <jsoncpp/json/json.h>
#elif __has_include(<json/json.h>)
#include <json/json.h>
#endif

// FPP plugin API
#include <Plugin.h>
#include <commands/Commands.h>
#include <log.h>

// Standard library
#include <algorithm>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "TuyaDevice.h"

// ---------------------------------------------------------------------------
// Plugin class
// ---------------------------------------------------------------------------

class TuyaBridgePlugin : public FPPPlugin {
public:
    TuyaBridgePlugin();
    virtual ~TuyaBridgePlugin() override;

    // Find a device by name; returns nullptr if not found.
    TuyaDevice* findDevice(const std::string& name) const;

    // Toggle the tracked on/off state for a switch device and send the command.
    // Returns false if the device is not found or the send fails.
    bool toggleSwitch(const std::string& deviceName);

    // Accessible by command objects for toggle state tracking
    mutable std::mutex           m_stateMutex;
    std::map<std::string, bool>  m_switchStates;

private:
    std::vector<std::unique_ptr<TuyaDevice>> m_devices;
    std::vector<std::string>                 m_commandsRegistered;

    void loadDevices(const std::string& confPath);
    void registerCommands();
    void unregisterCommands();
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

class TuyaSwitchCommand : public Command {
public:
    explicit TuyaSwitchCommand(TuyaBridgePlugin* plugin)
        : Command("Tuya Bridge - Set Switch",
                  "Turn a Tuya switch/plug on, off, or toggle its current state"),
          m_plugin(plugin) {
        args.emplace_back("Device", "string", "Device name from devices.conf");
        args.emplace_back("State", "string", "on / off / toggle")
            .setContentList({"on", "off", "toggle"});
    }

    std::unique_ptr<Result> run(const std::vector<std::string>& a) override {
        if (a.size() < 2)
            return std::make_unique<ErrorResult>("Usage: device state");

        TuyaDevice* dev = m_plugin->findDevice(a[0]);
        if (!dev)
            return std::make_unique<ErrorResult>("Device not found: " + a[0]);

        if (a[1] == "toggle") {
            return m_plugin->toggleSwitch(a[0])
                ? std::make_unique<Result>("OK")
                : std::make_unique<ErrorResult>("Send failed for device: " + a[0]);
        }

        bool on = (a[1] == "on" || a[1] == "1" || a[1] == "true");

        // Update tracked state then send
        {
            std::lock_guard<std::mutex> lk(m_plugin->m_stateMutex);
            m_plugin->m_switchStates[a[0]] = on;
        }
        return dev->setSwitch(on)
            ? std::make_unique<Result>("OK")
            : std::make_unique<ErrorResult>("Send failed for device: " + a[0]);
    }

private:
    TuyaBridgePlugin* m_plugin;
};

class TuyaDimmerCommand : public Command {
public:
    explicit TuyaDimmerCommand(TuyaBridgePlugin* plugin)
        : Command("Tuya Bridge - Set Dimmer",
                  "Set brightness of a Tuya dimmer (0 = off, 100 = full)"),
          m_plugin(plugin) {
        args.emplace_back("Device", "string", "Device name from devices.conf");
        args.emplace_back("Brightness", "int", "0–100 percent")
            .setRange(0, 100);
    }

    std::unique_ptr<Result> run(const std::vector<std::string>& a) override {
        if (a.size() < 2)
            return std::make_unique<ErrorResult>("Usage: device brightness");

        TuyaDevice* dev = m_plugin->findDevice(a[0]);
        if (!dev)
            return std::make_unique<ErrorResult>("Device not found: " + a[0]);

        int brightness = std::clamp(std::stoi(a[1]), 0, 100);

        return dev->setDimmer(brightness)
            ? std::make_unique<Result>("OK")
            : std::make_unique<ErrorResult>("Send failed for device: " + a[0]);
    }

private:
    TuyaBridgePlugin* m_plugin;
};

class TuyaColorCommand : public Command {
public:
    explicit TuyaColorCommand(TuyaBridgePlugin* plugin)
        : Command("Tuya Bridge - Set Color",
                  "Set RGB color on a Tuya RGB light"),
          m_plugin(plugin) {
        args.emplace_back("Device", "string", "Device name from devices.conf");
        args.emplace_back("Red",   "int", "0–255").setRange(0, 255);
        args.emplace_back("Green", "int", "0–255").setRange(0, 255);
        args.emplace_back("Blue",  "int", "0–255").setRange(0, 255);
    }

    std::unique_ptr<Result> run(const std::vector<std::string>& a) override {
        if (a.size() < 4)
            return std::make_unique<ErrorResult>("Usage: device R G B");

        TuyaDevice* dev = m_plugin->findDevice(a[0]);
        if (!dev)
            return std::make_unique<ErrorResult>("Device not found: " + a[0]);

        auto clamp255 = [](int v) { return static_cast<uint8_t>(std::clamp(v, 0, 255)); };
        uint8_t r = clamp255(std::stoi(a[1]));
        uint8_t g = clamp255(std::stoi(a[2]));
        uint8_t b = clamp255(std::stoi(a[3]));

        return dev->setColor(r, g, b)
            ? std::make_unique<Result>("OK")
            : std::make_unique<ErrorResult>("Send failed for device: " + a[0]);
    }

private:
    TuyaBridgePlugin* m_plugin;
};

// Generic DPS command for advanced users or device types not covered above.
// Value is parsed as JSON so booleans (true/false), integers, and strings all work.
class TuyaDpsCommand : public Command {
public:
    explicit TuyaDpsCommand(TuyaBridgePlugin* plugin)
        : Command("Tuya Bridge - Send DPS",
                  "Send a raw DPS key/value pair to any Tuya device"),
          m_plugin(plugin) {
        args.emplace_back("Device",  "string", "Device name from devices.conf");
        args.emplace_back("DPS Key", "string", "Datapoint key, e.g. 1, 20, 24");
        args.emplace_back("Value",   "string", "Value: true, false, 0-1000, or a string");
    }

    std::unique_ptr<Result> run(const std::vector<std::string>& a) override {
        if (a.size() < 3)
            return std::make_unique<ErrorResult>("Usage: device dps_key value");

        TuyaDevice* dev = m_plugin->findDevice(a[0]);
        if (!dev)
            return std::make_unique<ErrorResult>("Device not found: " + a[0]);

        const std::string& valStr = a[2];
        Json::Value dps;

        // Parse value: true/false → bool, integer string → int, else string
        if (valStr == "true" || valStr == "on")       dps[a[1]] = true;
        else if (valStr == "false" || valStr == "off") dps[a[1]] = false;
        else {
            try {
                size_t pos = 0;
                int iv = std::stoi(valStr, &pos);
                if (pos == valStr.size())
                    dps[a[1]] = iv;
                else
                    dps[a[1]] = valStr;
            } catch (...) {
                dps[a[1]] = valStr;
            }
        }

        return dev->sendRawDps(dps)
            ? std::make_unique<Result>("OK")
            : std::make_unique<ErrorResult>("Send failed for device: " + a[0]);
    }

private:
    TuyaBridgePlugin* m_plugin;
};

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

static std::string getDevicesConfPath() {
    // FPP media dir is /home/fpp/media on Pi; respect the env var if set.
    const char* mediaDir = getenv("FPPDIR_MEDIA");
    std::string base = mediaDir ? mediaDir : "/home/fpp/media";
    return base + "/plugins/fpp-TuyaBridge/devices.conf";
}

TuyaBridgePlugin::TuyaBridgePlugin()
    : FPPPlugin("TuyaBridge") {
    LogInfo(VB_PLUGIN, "TuyaBridge: initialising\n");
    loadDevices(getDevicesConfPath());
    registerCommands();
}

TuyaBridgePlugin::~TuyaBridgePlugin() {
    unregisterCommands();
    LogInfo(VB_PLUGIN, "TuyaBridge: shutdown\n");
}

void TuyaBridgePlugin::loadDevices(const std::string& confPath) {
    m_devices.clear();

    std::ifstream f(confPath);
    if (!f.is_open()) {
        LogWarn(VB_PLUGIN, "TuyaBridge: devices.conf not found at %s\n", confPath.c_str());
        return;
    }

    Json::Value root;
    Json::CharReaderBuilder rb;
    std::string errs;
    if (!Json::parseFromStream(rb, f, &root, &errs) || !root.isArray()) {
        LogErr(VB_PLUGIN, "TuyaBridge: failed to parse devices.conf: %s\n", errs.c_str());
        return;
    }

    for (const auto& entry : root) {
        std::string name    = entry.get("name",    "").asString();
        std::string ip      = entry.get("ip",      "").asString();
        std::string id      = entry.get("id",      "").asString();
        std::string key     = entry.get("key",     "").asString();
        std::string version = entry.get("version", "3.3").asString();
        std::string type    = entry.get("type",    "switch").asString();

        if (name.empty() || ip.empty() || id.empty() || key.empty()) {
            LogWarn(VB_PLUGIN, "TuyaBridge: skipping incomplete device entry\n");
            continue;
        }
        if (key.size() != 16) {
            LogWarn(VB_PLUGIN, "TuyaBridge: key for '%s' is not 16 bytes — skipping\n", name.c_str());
            continue;
        }

        m_devices.push_back(std::make_unique<TuyaDevice>(
            name, ip, id, key, version, TuyaDevice::typeFromString(type)));

        LogInfo(VB_PLUGIN, "TuyaBridge: loaded device '%s' (%s) v%s\n",
                name.c_str(), ip.c_str(), version.c_str());
    }
}

void TuyaBridgePlugin::registerCommands() {
    // Build device name list for UI dropdowns
    std::vector<std::string> names;
    for (const auto& d : m_devices)
        names.push_back(d->getName());

    auto* sw  = new TuyaSwitchCommand(this);
    auto* dim = new TuyaDimmerCommand(this);
    auto* col = new TuyaColorCommand(this);
    auto* dps = new TuyaDpsCommand(this);

    // Populate the device dropdown in each command
    if (!names.empty()) {
        sw->args.front().setContentList(names);
        dim->args.front().setContentList(names);
        col->args.front().setContentList(names);
        dps->args.front().setContentList(names);
    }

    CommandManager::INSTANCE.addCommand(sw);
    CommandManager::INSTANCE.addCommand(dim);
    CommandManager::INSTANCE.addCommand(col);
    CommandManager::INSTANCE.addCommand(dps);

    m_commandsRegistered = {sw->name, dim->name, col->name, dps->name};
    LogInfo(VB_PLUGIN, "TuyaBridge: registered %zu commands\n", m_commandsRegistered.size());
}

void TuyaBridgePlugin::unregisterCommands() {
    for (const auto& n : m_commandsRegistered)
        CommandManager::INSTANCE.removeCommand(n);
    m_commandsRegistered.clear();
}

TuyaDevice* TuyaBridgePlugin::findDevice(const std::string& name) const {
    for (const auto& d : m_devices)
        if (d->getName() == name)
            return d.get();
    return nullptr;
}

bool TuyaBridgePlugin::toggleSwitch(const std::string& deviceName) {
    TuyaDevice* dev = findDevice(deviceName);
    if (!dev) return false;

    bool newState = false;
    {
        std::lock_guard<std::mutex> lk(m_stateMutex);
        auto it = m_switchStates.find(deviceName);
        newState = (it == m_switchStates.end()) ? true : !it->second;
        m_switchStates[deviceName] = newState;
    }
    return dev->setSwitch(newState);
}

// ---------------------------------------------------------------------------
// FPP plugin entry points
// ---------------------------------------------------------------------------

extern "C" {

FPPPlugins::Plugin* createPlugin() {
    return new TuyaBridgePlugin();
}

} // extern "C"
