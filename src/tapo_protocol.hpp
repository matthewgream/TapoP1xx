// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

#include <NetworkClient.h>
#include <HTTPClient.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/aes.h>

#include <array>
#include <vector>
#include <atomic>
#include <stdexcept>

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

#if ! defined(DEBUG_TAPO_PRINTF)
#ifdef DEBUG_TAPO
#define DEBUG_TAPO_PRINTF     Serial.printf
#define DEBUG_TAPO_DUMP(x, y) DEBUG_DUMP (y, x)
template <typename T, size_t N>
void DEBUG_DUMP (const std::array<T, N> &data, const String &label) {
    char buffer [16 * 3 + 2];
    Serial.printf ("%s [%d bytes]:\n", label.c_str (), N);
    for (size_t i = 0; i < N; i++) {
        const int pos = (i % 16) * 3, eol = (i + 1) % 16 == 0 || i == N - 1 ? 1 : 0;
        buffer [pos + 0] = "0123456789ABCDEF" [data [i] >> 4];
        buffer [pos + 1] = "0123456789ABCDEF" [data [i] & 0xF];
        buffer [pos + 2] = eol ? '\0' : ' ';
        if (eol)
            Serial.println (buffer);
    }
}
template <typename T>
void DEBUG_DUMP (const std::vector<T> &data, const String &label) {
    const int N = data.size ();
    char buffer [16 * 3 + 2];
    Serial.printf ("%s [%d bytes]:\n", label.c_str (), N);
    for (size_t i = 0; i < N; i++) {
        const int pos = (i % 16) * 3, eol = (i + 1) % 16 == 0 || i == N - 1 ? 1 : 0;
        buffer [pos + 0] = "0123456789ABCDEF" [data [i] >> 4];
        buffer [pos + 1] = "0123456789ABCDEF" [data [i] & 0xF];
        buffer [pos + 2] = eol ? '\0' : ' ';
        if (eol)
            Serial.println (buffer);
    }
}
#else
#define DEBUG_TAPO_PRINTF(...) \
    do {                       \
    } while (0)
#define DEBUG_TAPO_DUMP(...) \
    do {                     \
    } while (0)
#endif
#endif

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

static constexpr size_t SizeOfHashSHA1 = 20;
static constexpr size_t SizeOfHashSHA256 = 32;
using TypeOfHashData = std::vector<uint8_t>;
using TypeOfHashSHA1 = std::array<uint8_t, SizeOfHashSHA1>;
TypeOfHashSHA1 sha1 (const TypeOfHashData &data) {
    TypeOfHashSHA1 hash;
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init (&ctx);
    mbedtls_sha1_starts (&ctx);
    mbedtls_sha1_update (&ctx, data.data (), data.size ());
    mbedtls_sha1_finish (&ctx, hash.data ());
    mbedtls_sha1_free (&ctx);
    return hash;
}
using TypeOfHashSHA256 = std::array<uint8_t, SizeOfHashSHA256>;
TypeOfHashSHA256 sha256 (const TypeOfHashData &data) {
    TypeOfHashSHA256 hash;
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts (&ctx, 0);
    mbedtls_sha256_update (&ctx, data.data (), data.size ());
    mbedtls_sha256_finish (&ctx, hash.data ());
    mbedtls_sha256_free (&ctx);
    return hash;
}

static constexpr size_t SizeOfAESBlock = 16;
static constexpr size_t SizeOfAESKey = SizeOfAESBlock;
static constexpr size_t SizeOfAESIV = SizeOfAESBlock;
using TypeOfAESData = std::vector<uint8_t>;
using TypeOfAESKey = std::array<uint8_t, SizeOfAESKey>;
using TypeOfAESIV = std::array<uint8_t, SizeOfAESIV>;
TypeOfAESData aes_encrypt (const TypeOfAESData &data, const TypeOfAESKey &key, const TypeOfAESIV &iv) {
    const size_t padding = SizeOfAESBlock - (data.size () % SizeOfAESBlock);
    TypeOfAESData output (data.size () + padding);
    //
    mbedtls_aes_context ctx;
    mbedtls_aes_init (&ctx);
    int ret;
    if ((ret = mbedtls_aes_setkey_enc (&ctx, key.data (), SizeOfAESBlock * 8)) != 0) {
        mbedtls_aes_free (&ctx);
        throw std::runtime_error ("aes_encrypt: failed initialize");
    }
    auto iv_working = iv;
    const size_t content = data.size () - (data.size () % SizeOfAESBlock);
    if (content > 0)
        if ((ret = mbedtls_aes_crypt_cbc (&ctx, MBEDTLS_AES_ENCRYPT, content, iv_working.data (), data.data (), output.data ())) != 0) {
            mbedtls_aes_free (&ctx);
            throw std::runtime_error ("aes_encrypt: failed to encrypt main data");
        }
    if (padding > 0) {
        uint8_t final_block [SizeOfAESBlock] = { 0 };
        const size_t remainder = data.size () % SizeOfAESBlock;
        if (remainder > 0)
            memcpy (final_block, data.data () + content, remainder);
        for (size_t i = remainder; i < SizeOfAESBlock; i++)
            final_block [i] = padding;
        if ((ret = mbedtls_aes_crypt_cbc (&ctx, MBEDTLS_AES_ENCRYPT, SizeOfAESBlock, iv_working.data (), final_block, output.data () + content)) != 0) {
            mbedtls_aes_free (&ctx);
            throw std::runtime_error ("aes_encrypt: failed to encrypt padding");
        }
    }
    mbedtls_aes_free (&ctx);
    //
    return output;
}
TypeOfAESData aes_decrypt (const TypeOfAESData &data, const TypeOfAESKey &key, const TypeOfAESIV &iv) {
    if (data.size () % SizeOfAESBlock != 0)
        throw std::runtime_error ("aes_decrypt: invalid input size");
    TypeOfAESData output (data.size ());
    //
    mbedtls_aes_context ctx;
    mbedtls_aes_init (&ctx);
    int ret;
    if ((ret = mbedtls_aes_setkey_dec (&ctx, key.data (), SizeOfAESBlock * 8)) != 0) {
        mbedtls_aes_free (&ctx);
        throw std::runtime_error ("aes_decrypt: failed initialize");
    }
    auto iv_working = iv;
    if ((ret = mbedtls_aes_crypt_cbc (&ctx, MBEDTLS_AES_DECRYPT, data.size (), iv_working.data (), data.data (), output.data ())) != 0) {
        mbedtls_aes_free (&ctx);
        throw std::runtime_error ("aes_decrypt: failed to decrypt");
    }
    mbedtls_aes_free (&ctx);
    const uint8_t padding = output [output.size () - 1];
    if (padding <= SizeOfAESBlock)
        output.resize (output.size () - padding);
    //
    return output;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

template <typename T, size_t N, typename Iterator>
constexpr std::array<T, N> make_array (Iterator first, Iterator last) {
    std::array<T, N> result;
    std::copy_n (first, N, result.begin ());
    return result;
}

template <typename T, size_t N>
std::array<uint8_t, N> make_random () {
    std::array<T, N> r;
    for (int i = 0; i < N; i++)
        r [i] = random (std::numeric_limits<T>::max () + 1);
    return r;
}

template <typename T>
constexpr size_t container_size (const std::vector<T> &v) { return v.size (); }
template <typename T, size_t N>
constexpr size_t container_size (const std::array<T, N> &) { return N; }
template <typename Container>
auto container_begin (const Container &c) { return c.begin (); }
template <typename... Containers>
constexpr size_t total_size (const Containers &...containers) {
    return (container_size (containers) + ...);
}
template <typename Container>
std::vector<uint8_t> join (const Container &c) {
    std::vector<uint8_t> result;
    result.reserve (container_size (c));
    result.insert (result.end (), container_begin (c), container_begin (c) + container_size (c));
    return result;
}
template <typename Container1, typename... Containers>
std::vector<uint8_t> join (const Container1 &first, const Containers &...rest) {
    std::vector<uint8_t> result;
    result.reserve (total_size (first, rest...));
    result.insert (result.end (), container_begin (first), container_begin (first) + container_size (first));
    (result.insert (result.end (), container_begin (rest), container_begin (rest) + container_size (rest)), ...);
    return result;
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class KlapCipher {
public:
    using Bytes = std::vector<uint8_t>;
    using Seq = int32_t;
    using TypeOfSeq = std::atomic<Seq>;
    static constexpr size_t SizeOfSig = 28;
    using TypeOfSig = std::array<uint8_t, SizeOfSig>;
    static constexpr size_t SizeOfIVPrefix = 12;
    using TypeOfIVPrefix = std::array<uint8_t, SizeOfIVPrefix>;
    static constexpr size_t SizeOfKlapSeed = 16;
    using TypeOfKlapSeed = std::array<uint8_t, SizeOfKlapSeed>;
    static constexpr size_t SizeOfKlapHash = SizeOfHashSHA256;
    using TypeOfKlapHash = std::array<uint8_t, SizeOfKlapHash>;
    static constexpr int MinimumDecryptLength = 32;

private:
    TypeOfAESKey key;
    TypeOfIVPrefix iv_prefix;
    TypeOfSeq seq;
    TypeOfSig sig;

    static TypeOfAESKey build_key (const Bytes &local_hash) {
        const auto hash = sha256 (join (Bytes { 'l', 's', 'k' }, local_hash));
        return make_array<uint8_t, SizeOfAESKey> (hash.begin (), hash.begin () + SizeOfAESKey);
    }
    static std::pair<TypeOfIVPrefix, Seq> build_iv_parts (const Bytes &local_hash) {
        const auto hash = sha256 (join (Bytes { 'i', 'v' }, local_hash));
        const uint8_t *p = hash.data () + hash.size () - 4;
        return { make_array<uint8_t, SizeOfIVPrefix> (hash.begin (), hash.begin () + SizeOfIVPrefix), (Seq (p [0]) << 24) | (Seq (p [1]) << 16) | (Seq (p [2]) << 8) | (Seq (p [3])) };
    }
    static TypeOfSig build_sig (const Bytes &local_hash) {
        const auto hash = sha256 (join (Bytes { 'l', 'd', 'k' }, local_hash));
        return make_array<uint8_t, SizeOfSig> (hash.begin (), hash.begin () + SizeOfSig);
    }
    static TypeOfAESIV build_iv (const TypeOfIVPrefix &iv_prefix, const Seq seq) {
        const auto seq_BE = (std::endian::native == std::endian::little) ? __builtin_bswap32 (seq) : seq;
        const Bytes result = join (iv_prefix, make_array<uint8_t, 4> (reinterpret_cast<const uint8_t *> (&seq_BE), reinterpret_cast<const uint8_t *> (&seq_BE) + 4));
        return make_array<uint8_t, SizeOfAESIV> (result.begin (), result.end ());
    }

public:
    KlapCipher (const TypeOfKlapSeed &local_seed, const TypeOfKlapSeed &remote_seed, const TypeOfKlapHash &user_hash) {
        const auto local_hash = join (local_seed, remote_seed, user_hash);
        const auto [iv_prefix_, seq_] = build_iv_parts (local_hash);
        key = build_key (local_hash);
        iv_prefix = std::move (iv_prefix_);
        seq.store (seq_);
        sig = build_sig (local_hash);
    }
    std::pair<Bytes, Seq> encrypt (const String &data) {
        DEBUG_TAPO_PRINTF ("tapo::KlapCipher::encrypt, size=%d\n", data.length ());
        const auto seq_encrypt = seq.fetch_add (1, std::memory_order_relaxed);
        const auto seq_encrypt_BE = (std::endian::native == std::endian::little) ? __builtin_bswap32 (seq_encrypt) : seq_encrypt;
        const auto ciphertext = aes_encrypt (TypeOfAESData (data.begin (), data.end ()), key, build_iv (iv_prefix, seq_encrypt));
        return { join (sha256 (join (sig, make_array<uint8_t, 4> (reinterpret_cast<const uint8_t *> (&seq_encrypt_BE), reinterpret_cast<const uint8_t *> (&seq_encrypt_BE) + 4), ciphertext)), ciphertext), seq_encrypt };
    }
    String decrypt (const Seq seq_decrypt, const Bytes &data) {
        DEBUG_TAPO_PRINTF ("tapo::KlapCipher::decrypt, size=%d\n", data.size ());
        if (data.size () <= MinimumDecryptLength)
            return String ();
        const auto plaintext = aes_decrypt (TypeOfAESData (data.begin () + MinimumDecryptLength, data.end ()), key, build_iv (iv_prefix, seq_decrypt));
        return String (reinterpret_cast<const char *> (plaintext.data ()), plaintext.size ());
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

class TapoProtocol {
public:
    using Result = std::pair<bool, String>;
    using ResultJson = std::pair<bool, JsonDocument>;

private:
    static String extractCookie (const String &headers) {
        const size_t start = headers.indexOf ("TP_SESSIONID=");
        if (start >= 0) {
            const size_t end = headers.indexOf (';', start);
            if (end >= 0)
                return headers.substring (start, end - start);
        }
        return String ();
    }
    template <typename R>
    static std::pair<bool, int> postWithRetry (const String &context, HTTPClient& http, const uint8_t *data, const size_t size, const int retries) {
        int httpCode, counter = 0;
        do {
            if (counter > 0)
                DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::%s: retry #%d\n", context.c_str (), counter);
            httpCode = http.POST (const_cast<uint8_t *> (data), size);
        } while (httpCode < 0 && counter++ < retries);
        return { httpCode == HTTP_CODE_OK, httpCode };
    }

private:
    NetworkClient& networkClient;
    String url;
    String cookie;
    std::unique_ptr<KlapCipher> cipher;

    String requestBuilder (const String &method, JsonVariant &params) const {
        JsonDocument requestDoc;
        requestDoc ["method"] = method;
        requestDoc ["requestTimeMils"] = time (nullptr) * 1000;
        requestDoc ["params"] = params;
        requestDoc ["terminalUUID"] = "00-00-00-00-00-00";
        String output;
        serializeJson (requestDoc, output);
        return output;
    }

public:
    TapoProtocol (NetworkClient& nc) : networkClient (nc) {}

    ResultJson requestJson (const String &method, JsonVariant &&params = JsonVariant (), const int retries = 3) const {
        JsonDocument doc;

        if (! cipher)
            return ResultJson (false, doc);

        const String request = requestBuilder (method, params);
        const auto [data_request, seq] = cipher->encrypt (request);
        const String url_request (url + "/request?seq=" + String (seq));
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::request: request --> url=%s, size=%d, data=<<<%s>>>\n", url_request.c_str (), request.length (), request.c_str ());
        HTTPClient http;
        http.begin (networkClient, url_request);
        http.addHeader ("Cookie", cookie);
        const auto [requestPostSuccess, _] = postWithRetry<Result> ("request", http, data_request.data (), data_request.size (), retries);
        if (! requestPostSuccess)
            return ResultJson (false, doc);
        if (http.getSize () == 0)
            return ResultJson (false, doc);

        KlapCipher::Bytes data;
        data.resize (http.getSize ());
        if (http.getStream ().readBytes (data.data (), data.size ()) != data.size ())
            return ResultJson (false, doc);
        const String response = cipher->decrypt (seq, data);
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::request: response --> bytes=%d, size=%d, data=<<<%s>>>\n", data.size (), response.length (), response.c_str ());
        deserializeJson (doc, response);
        return ResultJson (true, doc);
    }

public:
    Result login (const String &ip, const String &username, const String &password, const int retries = 3) {
        static const char *HEADERS_TO_COLLECT [1] = { "Set-Cookie" };

        // CONFIGURATION

        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: commence, ip=%s, username=%s, password=%s\n", ip.c_str (), username.c_str (), password.c_str ());
        const auto auth_hash = sha256 (join (sha1 (KlapCipher::Bytes (username.begin (), username.end ())), sha1 (KlapCipher::Bytes (password.begin (), password.end ()))));
        const auto local_seed = make_random<uint8_t, KlapCipher::SizeOfKlapSeed> ();
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: auth hash", auth_hash);
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: local seed", local_seed);

        // HANDSHAKE 1

        const String url_handshake1 ("http://" + ip + "/app/handshake1");
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: handshake1, commence, url=%s\n", url_handshake1.c_str ());
        HTTPClient http;
        http.begin (networkClient, url_handshake1);
        http.collectHeaders (HEADERS_TO_COLLECT, 1);
        const auto [handshake1PostSuccess, handshake1PostCode] = postWithRetry<Result> ("handshake1", http, local_seed.data (), local_seed.size (), retries);
        if (! handshake1PostSuccess)
            return Result (false, "handshake1: invalid response code: " + String (handshake1PostCode));
        KlapCipher::TypeOfKlapSeed remote_seed;
        KlapCipher::TypeOfKlapHash remote_hash;
        if (http.getSize () != (remote_seed.size () + remote_hash.size ()))
            return Result (false, "handshake1: invalid response size: " + String (http.getSize ()));
        cookie = extractCookie (http.header ("Set-Cookie"));
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: handshake1, cookie=%s\n", cookie.c_str ());
        if (cookie.length () == 0)
            return Result (false, "handshake1: invalid cookie: " + http.header ("Set-Cookie"));
        if (http.getStreamPtr ()->readBytes (remote_seed.data (), remote_seed.size ()) != remote_seed.size ())
            return Result (false, "handshake1: invalid seed");
        if (http.getStreamPtr ()->readBytes (remote_hash.data (), remote_hash.size ()) != remote_hash.size ())
            return Result (false, "handshake1: invalid hash");
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: remote seed", remote_seed);
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: remote hash", remote_hash);
        const auto local_hash = sha256 (join (local_seed, remote_seed, auth_hash));
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: local hash", local_hash);
        if (local_hash != remote_hash)
            return Result (false, "handshake1: invalid verification");
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: handshake1, complete\n");

        // HANDSHAKE 2

        const String url_handshake2 ("http://" + ip + "/app/handshake2");
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: handshake2, commence, url=%s\n", url_handshake2.c_str ());
        const auto handshake2_hash = sha256 (join (remote_seed, local_seed, auth_hash));
        DEBUG_TAPO_DUMP ("tapo::TapoProtocol::login: handshake2 hash", handshake2_hash);
        http.begin (networkClient, url_handshake2);
        http.addHeader ("Cookie", cookie);
        auto [handshake2PostSuccess, handshake2PostCode] = postWithRetry<Result> ("handshake2", http, handshake2_hash.data (), handshake2_hash.size (), retries);
        if (! handshake2PostSuccess)
            return Result (false, "handshake2: invalid response code: " + String (handshake2PostCode));
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: handshake2, complete\n");

        // COMPLETED

        url = "http://" + ip + "/app";
        cipher = std::make_unique<KlapCipher> (local_seed, remote_seed, auth_hash);
        DEBUG_TAPO_PRINTF ("tapo::TapoProtocol::login: complete, url=%s\n", url.c_str ());

        return Result (true, "complete");
    }
};

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
