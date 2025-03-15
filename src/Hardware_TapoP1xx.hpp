
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

// #define DEBUG_TAPO
#include "tapo_device_plug.hpp"
#include "tapo_device_test.hpp"
#include "tapo_discover.hpp"

#include <memory>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <WiFi.h>
#include <WiFiClient.h>

class Hardware_TapoP1xx {
public:
    static inline constexpr interval_t DEFAULT_INTERVAL_RESCAN = 5 * 60 * 1000;

    struct ConfigDevice {
        String identifier, username, password;
    };
    struct Config {
        String publicKey;
        std::vector<ConfigDevice> devices;
        interval_t intervalRescan = DEFAULT_INTERVAL_RESCAN;
    };

private:
    const Config &config;
    enum class State {
        Initial,
        Discover,
        Discovered,
        Failed
    } state = State::Initial;
    std::unique_ptr<tapo::DiscoverUDP> discover;
    using Device = std::pair<std::shared_ptr<tapo::P11x>, tapo::DeviceInfo>;
    std::vector<Device> devices;
    Intervalable intervalRescan;
    WiFiClient network;

    bool deviceExists (const IPAddress &address) const {
        return std::find_if (devices.begin (), devices.end (), [&] (const auto &device) { return device.first->address () == address; }) != devices.end ();
    }
    void deviceInsert (const IPAddress &address, const ConfigDevice &deviceConfig) {
        Serial.printf ("Hardware_P1xx:: device discovered, identifier=%s, address=%s\n", deviceConfig.identifier.c_str (), address.toString ().c_str ());
        const auto device = std::make_shared<tapo::P11x> (tapo::DeviceConfig { .address = address, .username = deviceConfig.username, .password = deviceConfig.password }, network);
        const auto [connect_success, connect_error] = device->connect ();
        if (! connect_success) {
            Serial.printf ("Hardware_P1xx:: device connect failed: %s\n", connect_error.c_str ());
            return;
        }
        const auto [devinfo_success, devinfo_details] = device->get_device_info ();
        if (! devinfo_success) {
            Serial.printf ("Hardware_P1xx:: device info-request failed\n");
            return;
        }
        Serial.printf ("Hardware_P1xx:: device info == %s\n", devinfo_details.toString ().c_str ());
        devices.emplace_back (Device (device, devinfo_details));
    }
    void deviceIdentify (const tapo::DiscoverUDP::Devices &devices) {
        for (const auto &[address, details] : devices) {
            bool identified = false;
            const String deviceId = details.deviceId ();
            for (const auto &deviceConfig : config.devices)
                if (deviceConfig.identifier == deviceId) {
                    if (! deviceExists (address))
                        deviceInsert (address, deviceConfig);
                    identified = true;
                }
            if (! identified)
                Serial.printf ("Hardware_P1xx:: device unrecognized, identifier=%s, address=%s, model=%s\n", deviceId.c_str (), address.toString ().c_str (), details.deviceModel ().c_str ());
        }
    }

public:
    explicit Hardware_TapoP1xx (const Config &cfg) :
        config (cfg),
        intervalRescan (config.intervalRescan) { }

    void state_discoverBegin () {
        discover = std::make_unique<tapo::DiscoverUDP> (config.publicKey, tapo::TAPO_DISCOVERY_DEFAULT_PORT);
        if (! discover || ! discover->begin ()) {
            Serial.printf ("Hardware_P1xx:: discover begin failed\n");
            state = State::Failed;
            return;
        }
        state = State::Discover;
    }
    void state_discoverProcess () {
        if (! discover->process ()) {
            discover->end ();
            deviceIdentify (discover->devices ());
            discover.reset ();
            state = State::Discovered;
            Serial.printf ("Hardware_P1xx:: devices (%d): ", devices.size ());
            for (int index = 0; index < devices.size (); index++)
                Serial.printf ("%s[%d]: '%s' (%s)", (index > 0 ? ", " : ""), index, devices [index].second.nickname.c_str (), devices [index].second.model.c_str ());
            Serial.printf ("\n");
        }
    }

    //

    void begin () {
        state_discoverBegin ();
        intervalRescan.reset ();
    }
    void end () {
        state = State::Initial;
        devices.clear ();
    }
    void process () {
        if (state == State::Discover)
            state_discoverProcess ();
        else if (state != State::Initial && intervalRescan)
            state_discoverBegin ();
    }

    //

    size_t deviceCount () const {
        return devices.size ();
    }
    String deviceName (int index) const {
        if (index >= 0 && index < devices.size ())
            return devices [index].second.nickname;
        return String ();
    }
    void powerEnable (const bool state, int index = -1) {
        if (index >= 0 && index < devices.size ())
            devices [index].first->set_power (state);
        else
            for (auto &device : devices)
                device.first->set_power (state);
    }
    double powerCurrent (int index = -1) const {
        if (index >= 0 && index < devices.size ()) {
            const auto response = devices [index].first->get_current_power ();
            return response.first ? response.second.current_power : 0;
        } else {
            double power = 0;
            for (auto &device : devices) {
                const auto response = device.first->get_current_power ();
                if (response.first)
                    power += response.second.current_power;
            }
            return power;
        }
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
