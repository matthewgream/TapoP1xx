
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

// #define DEBUG_TAPO
#include "tapo_device_plug.hpp"
#include "tapo_device_test.hpp"
#include "tapo_discover.hpp"

#include <memory>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <nvs_flash.h>

class PersistentData {

public:
    static inline constexpr const char *DEFAULT_PERSISTENT_PARTITION = "nvs";
    static inline constexpr int SPACE_SIZE_MAXIMUM = 15, NAME_SIZE_MAXIMUM = 15, VALUE_STRING_SIZE_MAXIMUM = 4000 - 1;

private:
    static bool __initialise () {
        static bool initialised = false;
        if (! initialised) {
            initialised = true;
            esp_err_t err = nvs_flash_init_partition (DEFAULT_PERSISTENT_PARTITION);
            if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
                if (nvs_flash_erase_partition (DEFAULT_PERSISTENT_PARTITION) != ESP_OK || nvs_flash_init_partition (DEFAULT_PERSISTENT_PARTITION) != ESP_OK)
                    return false;
        }
        return initialised;
    }

private:
    nvs_handle_t _handle;
    const bool _okay = false;

public:
    explicit PersistentData (const char *space) :
        _okay (__initialise () && nvs_open_from_partition (DEFAULT_PERSISTENT_PARTITION, space, NVS_READWRITE, &_handle) == ESP_OK) {
        assert (strlen (space) <= SPACE_SIZE_MAXIMUM && "PersistentData namespace length > SPACE_SIZE_MAXIMUM");
    }
    ~PersistentData () {
        if (_okay)
            nvs_close (_handle);
    }

    bool get (const char *name, uint32_t *value) const {
        return (_okay && nvs_get_u32 (_handle, name, value) == ESP_OK);
    }
    bool set (const char *name, const uint32_t value) {
        return (_okay && nvs_set_u32 (_handle, name, value) == ESP_OK);
    }
    bool get (const char *name, int32_t *value) const {
        return (_okay && nvs_get_i32 (_handle, name, value) == ESP_OK);
    }
    bool set (const char *name, const int32_t value) {
        return (_okay && nvs_set_i32 (_handle, name, value) == ESP_OK);
    }
    // float, double
    bool get (const char *name, String *value) const {
        size_t size;
        bool result = false;
        if (_okay && nvs_get_str (_handle, name, NULL, &size) == ESP_OK) {
            char *buffer = new char [size];
            if (buffer) {
                if (nvs_get_str (_handle, name, buffer, &size) == ESP_OK)
                    (*value) = buffer, result = true;
                delete [] buffer;
            }
        }
        return result;
    }
    bool set (const char *name, const String &value) {
        assert (value.length () <= VALUE_STRING_SIZE_MAXIMUM && "PersistentData String length > VALUE_STRING_SIZE_MAXIMUM");
        return (_okay && nvs_set_str (_handle, name, value.c_str ()) == ESP_OK);
    }
};

template <typename T>
class PersistentValue {

    PersistentData &_data;
    const String _name;
    const T _value_default;

public:
    explicit PersistentValue (PersistentData &data, const char *name, const T &value_default = T ()) :
        _data (data),
        _name (name),
        _value_default (value_default) {
        assert (_name.length () <= PersistentData::NAME_SIZE_MAXIMUM && "PersistentValue name length > NAME_SIZE_MAXIMUM");
    }

    operator T () const {
        T value;
        return _data.get (_name.c_str (), &value) ? value : _value_default;
    }
    bool operator= (const T value) {
        return _data.set (_name.c_str (), value);
    }
    bool operator+= (const T value2) {
        T value = _value_default;
        _data.get (_name.c_str (), &value);
        value += value2;
        return _data.set (_name.c_str (), value);
    }
    bool operator>= (const T value2) const {
        T value = _value_default;
        _data.get (_name.c_str (), &value);
        return value >= value2;
    }
    bool operator> (const T value2) const {
        T value = _value_default;
        _data.get (_name.c_str (), &value);
        return value > value2;
    }
};

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

    PersistentData persistentData;
    PersistentValue<String> persistentValuePublicKey;

    String publicKey () {    // this is not efficient
        String key = persistentValuePublicKey;
        if (key.isEmpty ()) {
            Serial.printf ("Hardware_P1xx:: publicKey not found in PersistentStore: generating and storing\n");
            key = persistentValuePublicKey = tapo::generatePublicKey ();
        } else
            Serial.printf ("Hardware_P1xx:: publicKey retrieved from PersistentStore\n");
        return key;
    }

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

    void discoverBegin () {
        discover = std::make_unique<tapo::DiscoverUDP> (publicKey (), tapo::TAPO_DISCOVERY_DEFAULT_PORT);
        if (! discover || ! discover->begin ()) {
            Serial.printf ("Hardware_P1xx:: discover begin failed\n");
            state = State::Failed;
            return;
        }
        state = State::Discover;
    }
    void discoverProcess () {
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

public:
    explicit Hardware_TapoP1xx (const Config &cfg) :
        config (cfg),
        intervalRescan (config.intervalRescan),
        persistentData ("tapo"),
        persistentValuePublicKey (persistentData, "publicKey") { }

    //

    void begin () {
        discoverBegin ();
        intervalRescan.reset ();
    }
    void end () {
        state = State::Initial;
        devices.clear ();
    }
    void process () {
        if (state == State::Discover)
            discoverProcess ();
        else if ((state == State::Failed || state == State::Discovered) && intervalRescan)
            discoverBegin ();
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
            for (auto &[device, _] : devices)
                device->set_power (state);
    }
    double powerCurrent (int index = -1) const {
        double power = 0;
        if (index >= 0 && index < devices.size ()) {
            const auto [result, value] = devices [index].first->get_current_power ();
            if (result)
                power = value.current_power;
        } else
            for (auto &[device, _] : devices) {
                const auto [result, value] = device->get_current_power ();
                if (result)
                    power += value.current_power;
            }
        return power;
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
