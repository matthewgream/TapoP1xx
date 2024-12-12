
#ifdef TAPO_STANDALONE

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <Arduino.h>

typedef unsigned long interval_t;
typedef unsigned long counter_t;

class Intervalable {
    interval_t _interval, _previous;
    counter_t _exceeded = 0;

public:
    explicit Intervalable (const interval_t interval = 0, const interval_t previous = 0) :
        _interval (interval),
        _previous (previous) { }
    operator bool () {
        const interval_t current = millis ();
        if (current - _previous > _interval) {
            _previous = current;
            return true;
        }
        return false;
    }
    bool passed (interval_t *interval = nullptr, const bool atstart = false) {
        const interval_t current = millis ();
        if ((atstart && _previous == 0) || current - _previous > _interval) {
            if (interval != nullptr)
                (*interval) = current - _previous;
            _previous = current;
            return true;
        }
        return false;
    }
    void reset (const interval_t interval = std::numeric_limits<interval_t>::max ()) {
        if (interval != std::numeric_limits<interval_t>::max ())
            _interval = interval;
        _previous = millis ();
    }
    void setat (const interval_t place) {
        _previous = millis () - ((_interval - place) % _interval);
    }
    void wait () {
        const interval_t current = millis ();
        if (current - _previous < _interval)
            delay (_interval - (current - _previous));
        else if (_previous > 0)
            _exceeded++;
        _previous = millis ();
    }
    counter_t exceeded () const {
        return _exceeded;
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <WiFi.h>
#include "Secrets.hpp"

void inline startWiFi () {
    Serial.printf ("Wifi [%s / %s]...\n", WIFI_SSID, WIFI_PASS);    // Secrets.hpp
    WiFi.setHostname ("test_TapoP1xx");
    WiFi.setAutoReconnect (true);
    WiFi.mode (WIFI_MODE_STA);
    WiFi.begin (WIFI_SSID, WIFI_PASS);    // Secrets.hpp
    WiFi.setTxPower (WIFI_POWER_8_5dBm);
    while (WiFi.status () != WL_CONNECTED)
        delay (500);
    Serial.printf ("Wifi Connected: %d dbm\n", WiFi.RSSI ());
    while (WiFi.localIP () == IPAddress (0, 0, 0, 0))
        delay (500);
    Serial.printf ("Wifi Allocated: %s\n", WiFi.localIP ().toString ().c_str ());
}
void inline startTime () {
    Serial.println ("Time ...");
    configTime (0, 0, "0.uk.pool.ntp.org", "1.uk.pool.ntp.org", "2.uk.pool.ntp.org");
    while (time (nullptr) < 3600 * 2)
        delay (500);
    Serial.println ("Time OK");
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include "Hardware_TapoP1xx.hpp"

Hardware_TapoP1xx *p1xx_device;
const Hardware_TapoP1xx::Config p1xx_config {
    .device = { .address = TAPO_ADDRESS, .username = TAPO_USERNAME, .password = TAPO_PASSWORD }  // Secrets.hpp
};

void setup () {
    Serial.begin (115200);
    delay (5 * 1000);
    Serial.println ("UP");
    startWiFi ();
    startTime ();

    test_P11x (p1xx_config.device);

    // p1xx_device = new Hardware_TapoP1xx (p1xx_config);
    // p1xx_device->begin ();
}

// -----------------------------------------------------------------------------------------------

Intervalable second (15 * 1000);

void loop () {
    second.wait ();
    Serial.println ("***");
    // p1xx_device->process ();
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#endif
