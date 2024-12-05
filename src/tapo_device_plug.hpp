
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#pragma once

#include "tapo_protocol.hpp"
#include <utility>
#include <numeric>

#include <mbedtls/base64.h>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

String decodeBase64 (const String &input) {
    size_t decoded_len;
    mbedtls_base64_decode (nullptr, 0, &decoded_len, reinterpret_cast<const unsigned char *> (input.c_str ()), input.length ());
    std::vector<unsigned char> decoded (decoded_len + 1);
    mbedtls_base64_decode (decoded.data (), decoded.size (), &decoded_len, reinterpret_cast<const unsigned char *> (input.c_str ()), input.length ());
    return String (reinterpret_cast<char *> (decoded.data ()), decoded_len);
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

namespace tapo {

struct DeviceConfig {
    String address;
    String username;
    String password;
    int retry_count = 3;
};

template <typename... Features>
class Device : protected Features... {
public:
    using StringResult = std::pair<bool, String>;
    using Config = DeviceConfig;

protected:
    TapoProtocol protocol_;
    Config config_;

public:
    explicit Device (const Config &config) :
        config_ (config) { }
    StringResult connect () {
        return protocol_.login (config_.address, config_.username, config_.password);
    }
};

}    // namespace tapo

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#include <ArduinoJson.h>

/*

note there are a plethora of commands

https://github.com/python-kasa/python-kasa/tree/master/tests/fixtures/smart

component_nego
qs_component_nego
discovery_result
get_device_info
get_device_time
get_device_usage
get_antitheft_rules
get_auto_off_config
get_auto_update_info
get_connect_cloud_state
get_countdown_rules
get_electricity_price_config
get_emeter_data
get_emeter_vgain_igain
get_energy_usage
get_fw_download_state
get_latest_fw
get_led_info
get_matter_setup_info
get_max_power
get_next_event
get_protection_power
get_schedule_rules
get_wireless_scan_info

*/
namespace tapo {

// data=<<<{"result":{"device_id":"802255FBB9203A462760F916F226A40222EEA3B2","fw_ver":"1.2.3 Build 240617 Rel.153525","hw_ver":"1.0","type":"SMART.TAPOPLUG","model":"P110M","mac":"A8-6E-84-E6-86-D6","hw_id":"E2B8338B0C506D476C4483D3377F1D54","fw_id":"00000000000000000000000000000000","oem_id":"BFB971D4927F4FCF9B6383B8C7AE390D","ip":"192.168.0.151","time_diff":0,"ssid":"R1JFQU1IT01F","rssi":-67,"signal_level":2,"auto_off_status":"on","auto_off_remain_time":79900,"longitude":-3081,"latitude":515007,"lang":"en_US","avatar":"mosquito_repellent","region":"Europe/London","specs":"","nickname":"Q2hhcmdlciBIb2xsYW5kUGFyaw==","has_set_location_info":true,"device_on":true,"on_time":6440,"default_states":{"type":"last_states","state":{}},"overheat_status":"normal","power_protection_status":"normal","overcurrent_status":"normal","charging_status":"normal"},"error_code":0}>>>
// data=<<<{"result":{"device_id":"8022E766E837138275B8CB9C2390BAFD22EE6167","fw_ver":"1.3.1 Build 240621 Rel.162048","hw_ver":"1.0","type":"SMART.TAPOPLUG","model":"P110","mac":"A8-6E-84-D3-56-E5","hw_id":"56DD079101D61D400A11C4A3D41C51DA","fw_id":"00000000000000000000000000000000","oem_id":"AE7B616A7168B34151ABBCF86C88DF34","ip":"192.168.0.142","time_diff":0,"ssid":"R1JFQU1IT01F","rssi":-62,"signal_level":2,"auto_off_status":"on","auto_off_remain_time":70251,"longitude":-1165,"latitude":514835,"lang":"en_US","avatar":"mosquito_repellent","region":"Europe/London","specs":"","nickname":"Q2hhcmdlciBLZW5uaW5ndG9u","has_set_location_info":true,"device_on":true,"on_time":16089,"default_states":{"type":"last_states","state":{}},"overheat_status":"normal","power_protection_status":"normal","overcurrent_status":"normal","charging_status":"normal"},"error_code":0}>>>
// data=<<<{"error_code":0,"result":{"device_id":"8022EFB357AE311E55C23C2CC2D7BDBA1E49B941","fw_ver":"1.5.5 Build 20230927 Rel. 40646","hw_ver":"1.20.0","type":"SMART.TAPOPLUG","model":"P100","mac":"00-5F-67-FD-44-4A","hw_id":"9994A0A7D5B29645B8150C392284029D","fw_id":"1D18AD293A25ABDE41405B20C6F98816","oem_id":"D43E293FEA5A174CC7534285828B0D15","specs":"UK","device_on":false,"on_time":0,"overheated":false,"nickname":"SGVhdGVy","location":"","avatar":"fan","longitude":-2030,"latitude":515020,"has_set_location_info":true,"ip":"192.168.0.100","ssid":"R1JFQU1IT01F","signal_level":3,"rssi":-40,"region":"Europe/London","time_diff":0,"lang":"en_US","default_states":{"type":"last_states","state":{}},"auto_off_status":"off","auto_off_remain_time":0}}>>>
struct DeviceInfo {
    int error_code;
    String nickname, model, type;
    String fw_ver, hw_ver, fw_id, hw_id, device_id;
    // String oem_id;
    String specs;
    int time_diff;
    // bool has_set_location_info;
    double latitude, longitude;
    String region;
    // String location;
    String mac, ip, ssid;
    int rssi, signal_level;
    bool device_on;
    int on_time;
    String auto_off_status;
    int auto_off_remain_time;
    // bool overheated;
    String overheat_status, power_protection_status, overcurrent_status, charging_status;

    static DeviceInfo fromJson (JsonDocument &doc) {
        DeviceInfo r;
        r.error_code = doc ["error_code"].as<int> ();
        const JsonObject &result = doc ["result"];

        r.nickname = decodeBase64 (result ["nickname"].as<String> ());
        r.model = result ["model"].as<String> ();
        r.type = result ["type"].as<String> ();

        r.fw_ver = result ["fw_ver"].as<String> ();
        r.hw_ver = result ["hw_ver"].as<String> ();
        r.hw_id = result ["hw_id"].as<String> ();
        r.fw_id = result ["fw_id"].as<String> ();
        r.device_id = result ["device_id"].as<String> ();
        // r.oem_id = result ["oem_id"].as<String> ();

        r.specs = result ["specs"].as<String> ();

        r.time_diff = result ["time_diff"].as<int> ();
        // r.has_set_location_info = result ["has_set_location_info"].as<bool> ();
        r.latitude = result ["latitude"].as<double> () / 10000;
        r.longitude = result ["longitude"].as<double> () / 10000;
        r.region = result ["region"].as<String> ();
        // r.location = result ["location"].as<String> ();    // P100

        r.mac = result ["mac"].as<String> ();
        r.ip = result ["ip"].as<String> ();
        r.ssid = decodeBase64 (result ["ssid"].as<String> ());
        r.rssi = result ["rssi"].as<int> ();
        r.signal_level = result ["signal_level"].as<int> ();

        r.device_on = result ["device_on"].as<bool> ();
        r.on_time = result ["on_time"].as<int> ();
        r.auto_off_status = result ["auto_off_status"].as<String> ();
        r.auto_off_remain_time = result ["auto_off_remain_time"].as<int> ();
        // r.overheated = result ["overheated"].as<bool> ();    // P100

        r.overheat_status = result ["overheat_status"].as<String> ();
        r.power_protection_status = result ["power_protection_status"].as<String> ();
        r.overcurrent_status = result ["overcurrent_status"].as<String> ();
        r.charging_status = result ["charging_status"].as<String> ();

        return r;
    }
    String toString () const {
        char buffer [512];
        snprintf (buffer, sizeof (buffer), "device=%s (%s)" ", fw=[%s]/hw=[%s]" ", ip=%s/ssid=%s/rssi=%ddB(%d)" ", location=%.4f/%.4f/region=[%s]" ", status=%s/time=%.2fmin" ", auto-off=%s/time=%.2fmin" ", protection:overheat=%s/power=%s/current=%s/charging=%s", nickname.c_str (), model.c_str (), fw_ver.c_str (), hw_ver.c_str (), ip.c_str (), ssid.c_str (), rssi, signal_level, latitude, longitude, region.c_str (), device_on ? "on" : "off", static_cast<double> (on_time) / 60, auto_off_status.c_str (), static_cast<double> (auto_off_remain_time) / 60, overheat_status.c_str (), power_protection_status.c_str (), overcurrent_status.c_str (), charging_status.c_str ());
        return String (buffer);
    }
};

// -----------------------------------------------------------------------------------------------

// data=<<<{"error_code":-1008}>>>
struct PowerResponse {
    int error_code;

    static PowerResponse fromJson (JsonDocument &doc) {
        return PowerResponse {
            .error_code = doc ["error_code"].as<int> ()
        };
    }
    String toString () const {
        return "error_code=" + String (error_code);
    }
};

// -----------------------------------------------------------------------------------------------

// data=<<<{"result":{"current_power":16},"error_code":0}>>>
struct PowerInfo {
    int error_code;
    double current_power;

    static PowerInfo fromJson (JsonDocument &doc) {
        return PowerInfo {
            .error_code = doc ["error_code"].as<int> (),
            .current_power = doc ["result"] ["current_power"].as<double> ()
        };
    }
    String toString () const {
        return "error_code=" + String (error_code) +
               ", current_power=" + String (current_power) + "W";
    }
};

// -----------------------------------------------------------------------------------------------

struct Usage {
    double today, past7, past30;

    static Usage fromJson (const JsonObject &obj, const double divisor = 1) {
        return Usage {
            .today = obj ["today"].as<double> () / divisor,
            .past7 = obj ["past7"].as<double> () / divisor,
            .past30 = obj ["past30"].as<double> () / divisor
        };
    }
    String toString () const {
        return "today=" + String (today) +
               "/past7=" + String (past7) +
               "/past30=" + String (past30);
    }
};

// data=<<<{"error_code":0,"result":{"time_usage":{"today":4,"past7":414,"past30":1387}}}>>>
struct DeviceUsage {
    int error_code;
    Usage time_usage;

    static DeviceUsage fromJson (JsonDocument &doc) {
        return DeviceUsage {
            .error_code = doc ["error_code"].as<int> (),
            .time_usage = Usage::fromJson (doc ["result"]["time_usage"], 60)
        };
    }
    String toString () const {
        return "error_code=" + String (error_code) +
               ", time_usage=" + time_usage.toString ();
    }
};

// data=<<<{"result":{"time_usage":{"today":1,"past7":666,"past30":734},"power_usage":{"today":0,"past7":2684,"past30":2688},"saved_power":{"today":1,"past7":0,"past30":0}},"error_code":0}>>>
struct DeviceUsageEnergyMonitoring {
    int error_code;
    Usage time_usage, power_usage, saved_power;

    static DeviceUsageEnergyMonitoring fromJson (JsonDocument &doc) {
        return DeviceUsageEnergyMonitoring {
            .error_code = doc ["error_code"].as<int> (),
            .time_usage = Usage::fromJson (doc ["result"]["time_usage"], 60),
            .power_usage = Usage::fromJson (doc ["result"]["power_usage"], 1000),
            .saved_power = Usage::fromJson (doc ["result"]["saved_power"], 1000)
        };
    }
    String toString () const {
        return "error_code=" + String (error_code) +
               ", time_usage=" + time_usage.toString () +
               ", power_usage=" + power_usage.toString () +
               ", saved_power=" + saved_power.toString ();
    }
};

// -----------------------------------------------------------------------------------------------

// data=<<<{"result":{"today_runtime":166,"month_runtime":385,"today_energy":2258,"month_energy":2258,"local_time":"2024-11-24 21:28:39","electricity_charge":[0,0,564],"current_power":16082},"error_code":0}>>>
// data=<<<{"result":{"today_runtime":268,"month_runtime":728,"today_energy":0,"month_energy":2688,"local_time":"2024-11-24 23:12:05","electricity_charge":[0,0,0],"current_power":0},"error_code":0}>>>
struct EnergyUsage {
    int error_code;
    String local_time;
    double current_power;
    double today_runtime, today_energy;
    double month_runtime, month_energy;
    double electricity_charge;

    static EnergyUsage fromJson (JsonDocument &doc) {
        const JsonObject &result = doc ["result"];
        JsonArray electricity_charge = result ["electricity_charge"].as<JsonArray> ();
        return EnergyUsage {
            .error_code = doc ["error_code"].as<int> (),
            .local_time = result ["local_time"].as<String> (),
            .current_power = result ["current_power"].as<double> () / 1000,
            .today_runtime = result ["today_runtime"].as<double> () / 60,
            .today_energy = result ["today_energy"].as<double> () / 1000,
            .month_runtime = result ["month_runtime"].as<double> () / 60,
            .month_energy = result ["month_energy"].as<double> () / 1000,
            .electricity_charge = std::accumulate (electricity_charge.begin (), electricity_charge.end (), 0.0, [] (const auto &sum, JsonVariant v) { return sum + v.as<double> () / 1000; })
        };
    }
    String toString () const {
        return "error_code=" + String (error_code) +
               ", local_time=" + local_time +
               ", current_power=" + String (current_power) + "W" +
               ", today:runtime=" + String (today_runtime) + "h/energy=" + String (today_energy) + "kWh" +
               ", month:runtime=" + String (month_runtime) + "h/energy=" + String (month_energy) + "kWh" +
               ", electricity_charge=" + String (electricity_charge) + "£";
    }
};

// -----------------------------------------------------------------------------------------------

// data=<<<{"result":{"local_time":"2024-11-24 21:28:39","data":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"start_timestamp":1732397319,"end_timestamp":1732483719,"interval":60},"error_code":0}>>>
// data=<<<{"result":{"local_time":"2024-11-24 23:12:05","data":[0,0,0,0,0,0,0,0,0,0,0,953,1690,17,14,3,4,3,0,0,0,0,0,0],"start_timestamp":1732403525,"end_timestamp":1732489925,"interval":60},"error_code":0}>>>
struct EnergyData {
    int error_code;
    String local_time;
    time_t start_timestamp, end_timestamp;
    int interval;
    std::vector<double> data;

    static EnergyData fromJson (JsonDocument &doc) {
        const JsonObject &result = doc ["result"];
        JsonArray data = result ["data"].as<JsonArray> ();
        return EnergyData {
            .error_code = doc ["error_code"].as<int> (),
            .local_time = result ["local_time"].as<String> (),
            .start_timestamp = result ["start_timestamp"].as<time_t> (),
            .end_timestamp = result ["end_timestamp"].as<time_t> (),
            .interval = result ["interval"].as<int> (),
            .data = std::accumulate (data.begin (), data.end (), std::vector<double> {}, [] (auto vec, JsonVariant v) { vec.push_back (v.as<double> () / 1000); return vec; })
        };
    }
    String toString () const {
        return "error_code=" + String (error_code) +
               ", local_time=" + local_time +
               ", data=[" + std::accumulate (data.begin () + 1, data.end (), String (data [0]), [] (const auto &a, auto b) { return a + ", " + String (b); }) + "]" +
               ", start=" + String (start_timestamp) +
               ", end=" + String (end_timestamp) +
               ", interval=" + String (interval);
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

struct PlugPowerControl {
protected:
    static std::pair<bool, PowerResponse> set_state (const TapoProtocol &protocol, const bool state) {
        JsonDocument doc;
        doc ["device_on"] = state;
        auto [success, response] = protocol.requestJson ("set_device_info", doc.as<JsonVariant> ());
        return { success, success ? PowerResponse::fromJson (response) : PowerResponse {} };
    }
};
struct PlugNotEnergyMonitoring {
protected:
    static std::pair<bool, DeviceUsage> get_device_usage (const TapoProtocol &protocol) {
        auto [success, response] = protocol.requestJson ("get_device_usage");
        return { success, success ? DeviceUsage::fromJson (response) : DeviceUsage {} };
    }
};
struct PlugEnergyMonitoring {
protected:
    static std::pair<bool, DeviceUsageEnergyMonitoring> get_device_usage (const TapoProtocol &protocol) {
        auto [success, response] = protocol.requestJson ("get_device_usage");
        return { success, success ? DeviceUsageEnergyMonitoring::fromJson (response) : DeviceUsageEnergyMonitoring {} };
    }
    static std::pair<bool, PowerInfo> get_current_power (const TapoProtocol &protocol) {
        auto [success, response] = protocol.requestJson ("get_current_power");
        return { success, success ? PowerInfo::fromJson (response) : PowerInfo {} };
    }
    static std::pair<bool, EnergyUsage> get_energy_usage (const TapoProtocol &protocol) {
        auto [success, response] = protocol.requestJson ("get_energy_usage");
        return { success, success ? EnergyUsage::fromJson (response) : EnergyUsage {} };
    }
    static std::pair<bool, EnergyData> get_energy_data (const TapoProtocol &protocol, const time_t start_timestamp, const time_t end_timestamp, const int interval = 60) {
        JsonDocument doc;
        doc ["start_timestamp"] = start_timestamp;
        doc ["end_timestamp"] = end_timestamp;
        doc ["interval"] = interval;
        auto [success, response] = protocol.requestJson ("get_energy_data", doc.as<JsonVariant> ());
        return { success, success ? EnergyData::fromJson (response) : EnergyData {} };
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class P11x : public Device<PlugPowerControl, PlugEnergyMonitoring> {
public:
    using Device::Device;

    static constexpr int MIN_INTERVAL = 60, MAX_INTERVAL = 43200;

    std::pair<bool, DeviceInfo> get_device_info () const {
        auto [success, response] = protocol_.requestJson ("get_device_info");
        return { success, success ? DeviceInfo::fromJson (response) : DeviceInfo {} };
    }
    std::pair<bool, DeviceUsageEnergyMonitoring> get_device_usage () const {
        return PlugEnergyMonitoring::get_device_usage (protocol_);
    }
    std::pair<bool, PowerResponse> set_power (const bool state) {
        return PlugPowerControl::set_state (protocol_, state);
    }
    std::pair<bool, PowerInfo> get_current_power () const {
        return PlugEnergyMonitoring::get_current_power (protocol_);
    }
    std::pair<bool, EnergyUsage> get_energy_usage () const {
        return PlugEnergyMonitoring::get_energy_usage (protocol_);
    }
    std::pair<bool, EnergyData> get_energy_data (const time_t start_timestamp, const time_t end_timestamp, const int interval = 60) const {
        return PlugEnergyMonitoring::get_energy_data (protocol_, start_timestamp, end_timestamp, interval);
    }
};

// -----------------------------------------------------------------------------------------------

class P10x : public Device<PlugPowerControl, PlugNotEnergyMonitoring> {
public:
    using Device::Device;

    std::pair<bool, DeviceInfo> get_device_info () const {
        auto [success, response] = protocol_.requestJson ("get_device_info");
        return { success, success ? DeviceInfo::fromJson (response) : DeviceInfo {} };
    }
    std::pair<bool, DeviceUsage> get_device_usage () const {
        return PlugNotEnergyMonitoring::get_device_usage (protocol_);
    }
    std::pair<bool, PowerResponse> set_power (const bool state) {
        return PlugPowerControl::set_state (protocol_, state);
    }
};

}    // namespace tapo

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
