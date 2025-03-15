
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

#include <AsyncUDP.h>
#include <map>
#include <cstring>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

namespace tapo {

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static inline constexpr void bytearray_encode_uint8a (const uint8_t *data, const size_t size, uint8_t *bytes) {
    std::memcpy (bytes, data, size);
}
static inline constexpr void bytearray_encode_uint16 (const uint16_t data, uint8_t *bytes) {
    bytes [0] = (data >> 8) & 0xFF;
    bytes [1] = data & 0xFF;
}
static inline constexpr void bytearray_encode_uint32 (const uint32_t data, uint8_t *bytes) {
    bytes [0] = (data >> 24) & 0xFF;
    bytes [1] = (data >> 16) & 0xFF;
    bytes [2] = (data >> 8) & 0xFF;
    bytes [3] = data & 0xFF;
}

static inline constexpr uint16_t bytearray_decode_uint16 (const uint8_t *bytes) {
    return static_cast<uint16_t> (bytes [0]) << 8 | static_cast<uint16_t> (bytes [1]);
}
static inline constexpr uint32_t bytearray_decode_uint32 (const uint8_t *bytes) {
    return static_cast<uint32_t> (bytes [0]) << 24 | static_cast<uint32_t> (bytes [1]) << 16 | static_cast<uint32_t> (bytes [2]) << 8 | static_cast<uint32_t> (bytes [3]);
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class CRC32 {
private:
    uint32_t crc = 0xFFFFFFFF;
    static const uint32_t crc32_table [256];    // CRC32 lookup table for polynomial 0xEDB88320

public:
    uint32_t process (const uint8_t data) {
        crc = (crc >> 8) ^ crc32_table [(crc ^ data) & 0xFF];
        return crc ^ 0xFFFFFFFF;
    }
    uint32_t process (const uint8_t *data, const size_t length) {
        for (size_t i = 0; i < length; i++)
            crc = (crc >> 8) ^ crc32_table [(crc ^ data [i]) & 0xFF];
        return crc ^ 0xFFFFFFFF;
    }
    uint32_t finalize () const {
        return crc ^ 0xFFFFFFFF;
    }
    static uint32_t calculate (const uint8_t *data, const size_t length) {
        CRC32 c;
        return c.process (data, length);
    }
};
const uint32_t CRC32::crc32_table [256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static inline constexpr const char *RSA_MESSAGE_KEY = "rsa_key";
static inline constexpr size_t RSA_MESSAGE_KEY_SIZE = 2048;
static inline constexpr uint32_t RSA_MESSAGE_TDP_RANDOM_BOUND = 268435456;
static inline constexpr uint8_t RSA_MESSAGE_HEADER [16] = { 0x02, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0x11, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x5A, 0x6B, 0x7C, 0x8D };
static inline constexpr size_t RSA_MESSAGE_HEADER_OFFSET_LENGTH = 4;
static inline constexpr size_t RSA_MESSAGE_HEADER_OFFSET_NONCE = 8;
static inline constexpr size_t RSA_MESSAGE_HEADER_OFFSET_CRC32 = 12;
static inline constexpr size_t RSA_MESSAGE_HEADER_OFFSET_CONSTANT0 = 0;
static inline constexpr size_t RSA_MESSAGE_HEADER_LENGTH_CONSTANT0 = 4;
static inline constexpr size_t RSA_MESSAGE_HEADER_OFFSET_CONSTANT1 = 6;
static inline constexpr uint8_t RSA_MESSAGE_HEADER_RESULT_CONSTANT1_0 = 0x02;
static inline constexpr uint8_t RSA_MESSAGE_HEADER_RESULT_CONSTANT1_1 = 0x00;

using Packet = std::pair<uint8_t *, size_t>;

Packet tapo_discovery_packet_build_data (const String &message) {

    const size_t packetSize = sizeof (RSA_MESSAGE_HEADER) + message.length ();
    uint8_t *packetData = new uint8_t [packetSize];
    if (packetData == NULL)
        return {};

    bytearray_encode_uint8a (RSA_MESSAGE_HEADER, sizeof (RSA_MESSAGE_HEADER), packetData);
    bytearray_encode_uint16 (message.length (), &packetData [RSA_MESSAGE_HEADER_OFFSET_LENGTH]);
    bytearray_encode_uint32 (esp_random () % RSA_MESSAGE_TDP_RANDOM_BOUND, &packetData [RSA_MESSAGE_HEADER_OFFSET_NONCE]);
    bytearray_encode_uint8a ((const uint8_t *) message.c_str (), message.length (), &packetData [sizeof (RSA_MESSAGE_HEADER)]);
    bytearray_encode_uint32 (CRC32::calculate (packetData, packetSize), &packetData [RSA_MESSAGE_HEADER_OFFSET_CRC32]);

    return Packet (packetData, packetSize);
}

Packet tapo_discovery_packet_build_rsa (const String &publicKey) {
    JsonDocument doc;
    doc ["params"].to<JsonObject> () [RSA_MESSAGE_KEY] = publicKey;
    String message;
    serializeJson (doc, message);
    return tapo_discovery_packet_build_data (message);
}

bool tapo_discovery_packet_is_valid (const uint8_t *packetData, const size_t packetSize) {
    if (packetSize < sizeof (RSA_MESSAGE_HEADER))
        return false;
    if (std::memcmp (&packetData [RSA_MESSAGE_HEADER_OFFSET_CONSTANT0], &RSA_MESSAGE_HEADER [RSA_MESSAGE_HEADER_OFFSET_CONSTANT0], RSA_MESSAGE_HEADER_LENGTH_CONSTANT0) != 0)
        return false;
    if (! (packetData [RSA_MESSAGE_HEADER_OFFSET_CONSTANT1] == RSA_MESSAGE_HEADER_RESULT_CONSTANT1_0 && packetData [RSA_MESSAGE_HEADER_OFFSET_CONSTANT1 + 1] == RSA_MESSAGE_HEADER_RESULT_CONSTANT1_1))
        return false;
    const uint16_t messageSize = bytearray_decode_uint16 (&packetData [RSA_MESSAGE_HEADER_OFFSET_LENGTH]);
    if (messageSize != (packetSize - sizeof (RSA_MESSAGE_HEADER)))
        return false;
    CRC32 c;
    c.process (&packetData [0], RSA_MESSAGE_HEADER_OFFSET_CRC32);
    c.process (&RSA_MESSAGE_HEADER [RSA_MESSAGE_HEADER_OFFSET_CRC32], sizeof (uint32_t));
    const uint32_t crc32received = bytearray_decode_uint32 (&packetData [RSA_MESSAGE_HEADER_OFFSET_CRC32]);
    const uint32_t crc32computed = c.process (&packetData [sizeof (RSA_MESSAGE_HEADER)], packetSize - sizeof (RSA_MESSAGE_HEADER));
    return crc32received == crc32computed;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class TapoPacketDiscoveryRequest {
    Packet _packet {};

public:
    TapoPacketDiscoveryRequest (const String &publicKey) :
        _packet (tapo_discovery_packet_build_rsa (publicKey)) { }
    ~TapoPacketDiscoveryRequest () {
        if (_packet.first != nullptr)
            delete [] _packet.first;
    }
    bool isValid () const {
        return _packet.first != nullptr && _packet.second > 0;
    }
    const Packet &getPacket () const {
        return _packet;
    }
};

static inline constexpr uint16_t TAPO_DISCOVERY_DEFAULT_PORT = 20002;
static inline constexpr int TAPO_DISCOVERY_DEFAULT_TIMEOUT = 15;
static inline constexpr int TAPO_DISCOVERY_DEFAULT_RESENDS = 6;

static bool send (const TapoPacketDiscoveryRequest &request, AsyncUDP &udp, const uint16_t port) {
    auto packet = request.getPacket ();
    Serial.printf ("(send %d bytes)", packet.second);
    return udp.broadcastTo (packet.first, packet.second, port) == packet.second;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

struct TapoDeviceDiscoveryDetails {
    JsonDocument details;
    String deviceId () const {
        return details ["result"]["device_id"] | "";
    }
    String deviceModel () const {
        return details ["result"]["device_model"] | "";
    }
    IPAddress deviceAddress () const {
        return IPAddress (details ["result"]["ip"] | "");
    }
    void debugDump () const {
        serializeJsonPretty (details, Serial);
    }
};

class TapoPacketDiscoveryResponse {
    JsonDocument _details;
    DeserializationError _error;

public:
    TapoPacketDiscoveryResponse (const uint8_t *data, const size_t size) :
        _error (deserializeJson (_details, (const char *) &data [sizeof (RSA_MESSAGE_HEADER)])) {
    }
    bool isValid () const {
        return ! _error && (_details ["error_code"] | -1) == 0 && _details ["result"];
    }

    TapoDeviceDiscoveryDetails getDetails () const {
        return TapoDeviceDiscoveryDetails { .details = _details };
    }

    static bool isType (const uint8_t *packetData, const size_t packetSize) {
        return tapo_discovery_packet_is_valid (packetData, packetSize);
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class DiscoverUDP {
public:
    using Devices = std::map<IPAddress, TapoDeviceDiscoveryDetails>;

private:
    AsyncUDP _udp;
    const uint16_t _port;
    const int _timeout, _resends;

    TapoPacketDiscoveryRequest _request;
    unsigned long _currentTime, _currentSend;
    Devices _devices;
    bool _listening = false;

public:
    DiscoverUDP (const String &publicKey, const uint16_t port = TAPO_DISCOVERY_DEFAULT_PORT, const int timeout = TAPO_DISCOVERY_DEFAULT_TIMEOUT, const int resends = TAPO_DISCOVERY_DEFAULT_RESENDS) :
        _port (port),
        _timeout (timeout),
        _resends (resends),
        _request (publicKey) {
    }
    ~DiscoverUDP () {
        end ();
    }

    const Devices &devices () const {
        return _devices;
    }

    bool begin () {
        if (! _udp.listen (_port))
            return false;
        _listening = true;
        _udp.onPacket ([this] (AsyncUDPPacket packet) {
            onPacket (packet);
        });
        if (! _request.isValid ())
            return false;
        if (! send (_request, _udp, _port))
            return false;
        _currentSend = _currentTime = millis ();
        return true;
    }
    void end () {
        if (_listening)
            _udp.close (), _listening = false;
    }
    bool process () {
        if ((millis () - _currentTime) > (_timeout * 1000))
            return false;
        if ((millis () - _currentSend) > (_resends * 1000)) {
            _currentSend = millis ();
            if (! send (_request, _udp, _port))
                return false;
        }
        return true;
    }

private:
    void onPacketTapoDiscoveryResponse (const TapoPacketDiscoveryResponse &response) {
        if (! response.isValid ())
            return;
        const auto details = response.getDetails ();
        Serial.printf ("TAPO device: id=%s, model=%s, address=%s\n", details.deviceId ().c_str (), details.deviceModel ().c_str (), details.deviceAddress ().toString ().c_str ());
        details.debugDump ();
        _devices [details.deviceAddress ()] = details;
    }
    void onPacket (AsyncUDPPacket &packet) {
        Serial.printf ("UDP packet: type=%s, length=%d, source=%s:%d, destination=%s:%d\n", packet.isBroadcast () ? "Broadcast" : packet.isMulticast () ? "Multicast"
                                                                                                                                                        : "Unicast",
                       packet.length (),
                       packet.remoteIP ().toString ().c_str (),
                       packet.remotePort (),
                       packet.localIP ().toString ().c_str (),
                       packet.localPort ());

        if (TapoPacketDiscoveryResponse::isType (packet.data (), packet.length ()))
            onPacketTapoDiscoveryResponse (TapoPacketDiscoveryResponse (packet.data (), packet.length ()));
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

struct DiscoverConfig {
    String publicKey;
    uint16_t port = TAPO_DISCOVERY_DEFAULT_PORT;
    int timeout = TAPO_DISCOVERY_DEFAULT_TIMEOUT, resends = TAPO_DISCOVERY_DEFAULT_RESENDS;
};

String generatePublicKey () {
    Serial.printf ("Tapo:: generate public key (%d bytes)... ", RSA_MESSAGE_KEY_SIZE);
    const String publicKey = rsa_public_key_PEM (RSA_MESSAGE_KEY_SIZE);
    Serial.printf ("\n");
    return publicKey;
}

DiscoverUDP::Devices discover (const DiscoverConfig& config) {

    Serial.printf ("Tapo:: discover (port=%d, timeout=%d, resends=%d)... ", config.port, config.timeout, config.resends);

    DiscoverUDP discoverUDP (config.publicKey, config.port, config.timeout, config.resends);
    if (! discoverUDP.begin ()) {
        Serial.printf (" failed (DiscoverUDP::begin)\n");
        return {};
    }
    while (discoverUDP.process ()) {
        Serial.print (".");
        delay (500);
    }
    discoverUDP.end ();

    Serial.printf (" completed (%d devices)\n", discoverUDP.devices ().size ());

    return discoverUDP.devices ();
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

}    // namespace tapo

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
