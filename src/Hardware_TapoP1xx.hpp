
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

// #define DEBUG_TAPO
#include "tapo_device_plug.hpp"
#include "tapo_device_test.hpp"

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <WiFi.h>

class Hardware_TapoP1xx {
public:
    typedef struct {
        tapo::DeviceConfig device;
    } Config;

private:
    const Config &config;
    tapo::P11x device;

public:
    explicit Hardware_TapoP1xx (const Config &cfg) :
        config (cfg),
        device (config.device) { }

    void begin () {
        auto [connect_success, connect_error] = device.connect ();
        if (! connect_success)
            Serial.printf ("Hardware_P1xx: failed to connect: %s\n", connect_error.c_str ());
        // collect those we need to operate
        auto [device_info_success, device_info_details] = device.get_device_info ();
        if (device_info_success)
            Serial.printf ("Hardware_P1xx: device-info == %s\n", device_info_details.toString ().c_str ());
    }
    void process () {
    }
    //
    void powerEnable (const bool state) {
        device.set_power (state);
    }
    double powerCurrent () const {
        const auto response = device.get_current_power   ();
        return response.first ? response.second.current_power : 0;
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
