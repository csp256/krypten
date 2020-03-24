#include "krypten.h"
#include <cstring>

// Krypten uses a condensed form of the 
// OS Cryptographically-Secure Pseudo-Random Number Generator 
// (aka CSPRNG)
// to create random keys and initialization vectors. 

// Copyright 2017 Michael Thomas Greer
// Distributed under the Boost Software License, Version 1.0.
// (See copy at http://www.boost.org/LICENSE_1_0.txt )

#include <initializer_list>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>

    #ifdef _MSC_VER
        #pragma comment(lib, "advapi32.lib")
    #endif
#else
    #include <stdio.h>
#endif

namespace duthomhas {

    typedef void* CSPRNG;
    extern "C" {
        CSPRNG csprng_create();
        int csprng_get(CSPRNG, void* dest, unsigned long long size);
        long csprng_get_int(CSPRNG);
        CSPRNG csprng_destroy(CSPRNG);
    }

    #ifdef _WIN32
    extern "C" {
        typedef union {
            CSPRNG     object;
            HCRYPTPROV hCryptProv;
        }
        CSPRNG_TYPE;
        CSPRNG csprng_create() {
            CSPRNG_TYPE csprng;
            if (!CryptAcquireContextA(&csprng.hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
                csprng.hCryptProv = 0;
            return csprng.object;
        }
        int csprng_get(CSPRNG object, void* dest, unsigned long long size) {
            unsigned long long n;
            CSPRNG_TYPE csprng;
            csprng.object = object;
            if (!csprng.hCryptProv) return 0;
            n = size >> 30;
            while (n--) if (!CryptGenRandom(csprng.hCryptProv, 1UL << 30, (BYTE*)dest)) return 0;
            return !!CryptGenRandom(csprng.hCryptProv, size & ((1ULL << 30) - 1), (BYTE*)dest);
        }
        long csprng_get_int(CSPRNG object) {
            long result;
            return csprng_get(object, &result, sizeof(result)) ? result : 0;
        }
        CSPRNG csprng_destroy(CSPRNG object) {
            CSPRNG_TYPE csprng;
            csprng.object = object;
            if (csprng.hCryptProv) CryptReleaseContext(csprng.hCryptProv, 0);
            return 0;
        }
    }
    #else  /* Using /dev/urandom */
    extern "C" {
        typedef union {
            CSPRNG object;
            FILE* urandom;
        }
        CSPRNG_TYPE;
        CSPRNG csprng_create() {
            CSPRNG_TYPE csprng;
            csprng.urandom = fopen("/dev/urandom", "rb");
            return csprng.object;
        }
        int csprng_get(CSPRNG object, void* dest, unsigned long long size) {
            CSPRNG_TYPE csprng;
            csprng.object = object;
            return (csprng.urandom) && (fread((char*)dest, 1, size, csprng.urandom) == size);
        }
        long csprng_get_int(CSPRNG object) {
            long result;
            return csprng_get(object, &result, sizeof(result)) ? result : 0;
        }

        CSPRNG csprng_destroy(CSPRNG object)
        {
            CSPRNG_TYPE csprng;
            csprng.object = object;
            if (csprng.urandom) fclose(csprng.urandom);
            return 0;
        }
    }
    #endif

    //-------------------------------------------------------------------------------------------------
    // The basis for this code was found at
    // https://stackoverflow.com/a/29634934/2706707
    using std::begin;
    using std::end;

    template <typename T>
    class is_iterable
    {
        template <typename U>
        static constexpr auto is_iterable_impl(int)
            -> decltype(
                begin(std::declval <U&>()) != end(std::declval <U&>()),   // begin/end and operator !=
                void(),                                                         // Handle evil operator ,
                ++std::declval <decltype(begin(std::declval <U&>()))&>(), // operator ++
                void(*begin(std::declval <U&>())),                         // operator*
                std::true_type{}
                ) 
        { return std::true_type{}; }

        template <typename U>
        static constexpr std::false_type is_iterable_impl(...) {
            return std::false_type{};
        }
        typedef decltype(is_iterable_impl <T>(0)) type;
    public:
        enum : bool { value = type::value };
    };

    //-------------------------------------------------------------------------------------------------
    struct csprng
    {
        typedef unsigned long result_type;
        static constexpr result_type min() { return std::numeric_limits <result_type> ::min(); }
        static constexpr result_type max() { return std::numeric_limits <result_type> ::max(); }

        template <typename Sseq>
        void seed(Sseq&) { }
        void seed(result_type) { }
        void discard(unsigned long long) { }
    public:
        template <typename Iterator>
        csprng(Iterator begin, Iterator end) :
            internal(csprng_create()),
            sseq(internal, std::distance(begin, end))
        { }
        template <typename T>
        csprng(std::initializer_list <T> xs) :
            internal(csprng_create()),
            sseq(internal, xs.size())
        { }

        struct sseq_type {
            CSPRNG& internal;
            std::size_t seed_seq_size;

            template <typename Iterator>
            void generate(Iterator begin, Iterator end) {
                while (begin != end)
                    *begin++ = csprng_get_int(internal);
            }
            template <typename Iterator>
            void param(Iterator dest) const {
                for (auto n = seed_seq_size; n--; )
                    *dest++ = csprng_get_int(internal);
            }
            sseq_type(CSPRNG& internal, std::size_t seed_seq_size) 
                : internal(internal)
                , seed_seq_size(seed_seq_size)
            { }
            std::size_t size() const { return seed_seq_size; }
        };

    public:
        struct exception : public std::runtime_error {
            exception(const char* message) : std::runtime_error(message) { }
            exception(const std::string& message) : std::runtime_error(message) { }
        };
        csprng() : internal(csprng_create()), sseq(internal, 0) {
            if (!internal) throw exception("duthomhas::CSPRNG: Failed to initialize the OS CSPRNG");
        }
        csprng(const csprng& that) :
            internal(csprng_create()),
            sseq(internal, that.sseq.seed_seq_size) {
            if (!internal) throw exception("duthomhas::CSPRNG: Failed to initialize the OS CSPRNG");
        }
        ~csprng() {
            internal = csprng_destroy(internal);
        }
        template <typename T>
        T* operator () (T* buffer, std::size_t n) {
            if (!csprng_get(internal, (void*)buffer, n * sizeof(T)))
                throw exception("duthomhas::CSPRNG: Failed to read the OS CSPRNG");
            return buffer;
        }
        void* operator () (void* buffer, std::size_t n) {
            return operator () < unsigned char > ((unsigned char*)buffer, n);
        }
        template <typename T>
        operator T () {
            T result;
            return operator () (result);
        }
        result_type operator () () {
            result_type result;
            return *operator () (&result, 1);
        }
        template <typename T>
        typename std::enable_if <std::is_fundamental <typename std::remove_reference <T> ::type> ::value, T&> ::type
        operator () (T&& value) {
            operator () (&value, 1);
            return value;
        }
        template <typename Iterable>
        typename std::enable_if <is_iterable <Iterable> ::value, Iterable&> ::type
        operator () (Iterable&& value) {
            for (auto& v : value) operator () (v);
            return value;
        }
        template <typename T, std::size_t N>
        T* operator () (T* (&array)[N]) {
            for (auto& v : array) operator () (v);
            return &(array[0]);
        }
    private:
        CSPRNG internal;
    public:
        sseq_type sseq;
    };
}


//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

// ^^^ CSPRNG
// vvv Krypten 

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

namespace krypten { 

    static constexpr uint8_t kRounds = 14;
    static constexpr uint8_t kBlocksize = 16;

    constexpr uint8_t aes[256] = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

    // Bitwise rotation to the right
    template <typename T>
    T 
    ROR(T x, const uint64_t n, const uint64_t bits) 
    {
        static_assert(std::is_integral <T>::value, "Error: Value being rotated should be integral.");
        return (x >> n) | ((x & ((1ULL << n) - 1)) << (bits - n));
    }

    // Bitwise rotation to the left
    template <typename T>
    T 
    ROL(const T& x, uint64_t const n, uint64_t const bits) 
    {
        static_assert(std::is_integral <T>::value, "Error: Value being rotated should be integral.");
        return ROR(x, bits - n, bits);
    }

    std::string
    add_pkcs5(const std::string& data, const unsigned int blocksize)
    {
        // Adds PKCS5 Padding
        int pad = ((blocksize - data.size()) % blocksize) % blocksize;
        std::string padding(pad, static_cast<char>(pad));
        return data + padding;
    }

    void
    remove_pkcs5(std::string& data)
    {
        // Removes PKCS Padding
        uint8_t pad = static_cast<uint8_t>(data[data.size() - 1]);
        std::string padding(pad, static_cast<char>(pad));
        if ((pad < data.size()) && (padding == data.substr(data.size() - pad, pad)))
            data = data.substr(0, data.size() - pad);
    }

    template <typename T, typename U>
    void
    memcpy_wrapper(T* dest, U const& source)
    {
        auto s = reinterpret_cast<const T*>(source.data());
        memcpy((void *) dest, s, source.size() * sizeof(typename U::value_type));
    }

    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

    Krypten::Key
    Krypten::random_key()
    {
        duthomhas::csprng rng;
        return rng(Key{});
    }

    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

    Krypten::Krypten(Key const& KEY)
    {
        std::array<uint32_t, 64> key;
        std::copy(KEY.begin(), KEY.end(), key.begin());
        uint8_t n = 8;
        auto q = n;

        constexpr uint8_t b = 240;

        uint8_t i = 1;
        while ((key.size() << 2) < b) {
            uint32_t t = ROL(key[key.size() - 1], 8, 32);
            uint32_t s = 0;

            for (uint8_t j = 0; j < 4; j++) {
                s += aes[static_cast<uint8_t>(t >> (j << 3))] << (j << 3);
            }

            t = s ^ key[key.size() - n];
            t ^= ((1 << (i++ - 1)) % 229) << 24;
            key[q++] = t;

            for (uint8_t j = 0; j < 3; j++) {
                key[q++] = (key[key.size() - 1] ^ key[key.size() - n]);
            }

            s = 0;
            for (uint8_t j = 0; j < 4; j++) {
                s += aes[static_cast<uint8_t>(key[key.size() - 1] >> (j << 3))] << (j << 3);
            }
            key[q++] = (s ^ key[key.size() - n]);

            for (uint8_t j = 0; j < 3; j++) {
                key[q++] = (key[key.size() - 1] ^ key[key.size() - n]);
            }
        }

        for (uint8_t j = 0; j < kRounds + 1; j++) {
            for (uint8_t k = 0; k < 4; k++) {
                keys[j][k] = key[4 * j + k];
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

    std::vector<Krypten::Block>
    Krypten::encrypt(std::string const& data) const
    {
        const std::string temp = add_pkcs5(data, kBlocksize);
        std::vector<Block> in(temp.size() / kBlocksize);
        memcpy_wrapper(in.data(), temp);
        
        duthomhas::csprng rng;
        Block IV = rng(Block{});

        std::vector<Block> out(1 + temp.size() / kBlocksize);
        out[0] = IV;

        for (auto x = 0; x < in.size(); x ++) {
            auto enc = encrypt_block(IV);
            for (auto i = 0; i < 4; i++) out[x + 1][i] = enc[i] ^ in[x][i];
            increment_IV(IV);
        }
        return out;
    } 

    //////////////////////////////////////////////////////////////////////////////

    std::string
    Krypten::decrypt(std::vector<Krypten::Block> const& data) const
    {
        Block IV = data[0];

        std::vector<Block> out(data.size() - 1);

        for (auto x = 1; x < data.size(); x++) {
            auto enc = encrypt_block(IV);
            for (int i = 0; i < 4; i++) out[x - 1][i] = enc[i] ^ data[x][i];
            increment_IV(IV);
        }

        std::string sout;
        sout.resize(out.size() * kBlocksize);
        memcpy_wrapper(sout.data(), out);
        remove_pkcs5(sout);
        return sout;
    }

    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

    void
    Krypten::increment_IV(Block& IV) const
    {
        auto i = IV.size();
        while ((i > 0) && (IV[i - 1] == std::numeric_limits<Block::value_type>::max())) {
            IV[i - 1] = 0;
            i--;
        }

        if (i) IV[i - 1]++;
    }
    
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

    Krypten::Block
    Krypten::encrypt_block(Block const& in) const
    {
        Block data;

        auto shiftrow = [](Block& data) -> void
        {
            Block temp;
            temp.fill(0);
            for (uint8_t x = 0; x < 4; x++) {
                for (uint8_t y = 0; y < 4; y++) {
                    temp[x] += ((data[y] >> ((3 - x) << 3)) & 255) << ((3 - y) << 3);
                }
            }
            for (auto i = 0; i < 4; i++) data[i] = temp[i];

            for (auto x = 0; x < 4; x++) data[x] = ROL(data[x], x << 3, 32);

            temp.fill(0);
            for (uint8_t x = 0; x < 4; x++) {
                for (uint8_t y = 0; y < 4; y++) {
                    temp[x] += ((data[y] >> ((3 - x) << 3)) & 255) << ((3 - y) << 3);
                }
            }
            for (auto i = 0; i < 4; i++) data[i] = temp[i];
        };

        auto mixcolumns = [](Block& data)
        {
            auto GF = [](uint8_t a, uint8_t b)
            {
                uint8_t prim = 0x1b;
                uint8_t p = 0, i = 0;
                while ((i < 8) and (a != 0) and (b != 0)) {
                    if (b & 1) p ^= a;
                    uint8_t hi = a & 0x80;
                    a = (a << 1) & 255;
                    if (hi) a ^= prim;
                    b >>= 1;
                    i += 1;
                }
                return p;
            };

            Block temp;
            for (uint8_t i = 0; i < 4; i++) {
                temp[i] =
                    ((GF(2, (data[i] >> 24) & 255) ^ GF(3, (data[i] >> 16) & 255) ^ ((data[i] >> 8) & 255) ^ (data[i] & 255)) << 24) +
                    ((GF(2, (data[i] >> 16) & 255) ^ GF(3, (data[i] >> 8) & 255) ^ (data[i] & 255) ^ ((data[i] >> 24) & 255)) << 16) +
                    ((GF(2, (data[i] >> 8) & 255) ^ GF(3, data[i] & 255) ^ ((data[i] >> 24) & 255) ^ ((data[i] >> 16) & 255)) << 8) +
                    ((GF(2, data[i] & 255) ^ GF(3, (data[i] >> 24) & 255) ^ ((data[i] >> 16) & 255) ^ ((data[i] >> 8) & 255)));
            }
            data = temp;
        };

        for (uint8_t x = 0; x < 4; x++) data[x] = in[x] ^ keys[0][x];

        for (uint8_t r = 1; r < kRounds; r++) {
            for (uint8_t x = 0; x < 4; x++) data[x] = (aes[data[x] >> 24] << 24) + (aes[(data[x] >> 16) & 255] << 16) + (aes[(data[x] >> 8) & 255] << 8) + aes[data[x] & 255];
            shiftrow(data);
            mixcolumns(data);
            for (uint8_t x = 0; x < 4; x++) data[x] ^= keys[r][x];
        }

        for (uint8_t x = 0; x < 4; x++) data[x] = (aes[data[x] >> 24] << 24) + (aes[(data[x] >> 16) & 255] << 16) + (aes[(data[x] >> 8) & 255] << 8) + aes[data[x] & 255];

        shiftrow(data);

        for (uint8_t x = 0; x < 4; x++) data[x] ^= keys[kRounds][x];

        return data;
    }

    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////

}
