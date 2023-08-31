////////////////////////////////////////////////
// Hardware ID - Know Who You're Dealing With //
// @auth William J. Tomasine II, Josh O'Leary //

// ABSTRACT //
// This module facilitates uniquely identifying devices via reading hardware information.
// Such as peripherial serial numbers, drive configurations, component specs.
// In this specific implementation case, for x86 desktops running Linux.
//
// A Hardware Profile is a structure, containing fields for each Hardware Token collected.
// A Hardware Hash is generated via concatenating the Hardware Profile fields
// into one string, and feeding that to a standard cryptographic hashing algorithm.
//
// This hash uniquely identifies the device, without presenting a privacy hazard to the device owner.
// Use cases:
// Prevent MultiAccounting in online games.
// Detect end-users running VPNs, Virtual Machines etc.
//
// Further Considerations: hardware changes slowly over time.

// LICENSE //
// MIT

// SAMPLES //
#pragma once
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <libudev.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <vector>
#include <dlfcn.h>



#pragma region obfuscation
#ifdef _MSC_VER
#define AY_CAT(X,Y) AY_CAT2(X,Y)
	#define AY_CAT2(X,Y) X##Y
	#define AY_LINE int(AY_CAT(__LINE__,U))
#else
#define AY_LINE __LINE__
#endif

#ifndef OBFUSCATE_DEFAULT_KEY
#define OBFUSCATE_DEFAULT_KEY obfs::generate_key(AY_LINE)
#endif

namespace obfs
{
    using size_type = unsigned long long;
    using key_type = unsigned long long;

    // Generate a pseudo-random key that spans all 8 bytes
    constexpr key_type generate_key(key_type seed)
    {
        // Use the MurmurHash3 64-bit finalizer to hash our seed
        key_type key = seed;
        key ^= (key >> 33);
        key *= 0xff51afd7ed558ccd;
        key ^= (key >> 33);
        key *= 0xc4ceb9fe1a85ec53;
        key ^= (key >> 33);

        // Make sure that a bit in each byte is set
        key |= 0x0101010101010101ull;

        return key;
    }

    // Obfuscates or deobfuscates data with key
    constexpr void cipher(char* data, size_type size, key_type key)
    {
        // Obfuscate with a simple XOR cipher based on key
        for (size_type i = 0; i < size; i++)
        {
            data[i] ^= char((key >> ((i % 8) * 8)) & 0xFF);
        }
    }

    // Obfuscates a string at compile time
    template <size_type N, key_type KEY>
    class obfuscator
    {
    public:
        // Obfuscates the string 'data' on construction
        constexpr obfuscator(const char* data)
        {
            // Copy data
            for (size_type i = 0; i < N; i++)
            {
                m_data[i] = data[i];
            }

            // On construction each of the characters in the string is
            // obfuscated with an XOR cipher based on key
            cipher(m_data, N, KEY);
        }

        constexpr const char* data() const
        {
            return &m_data[0];
        }

        constexpr size_type size() const
        {
            return N;
        }

        constexpr key_type key() const
        {
            return KEY;
        }

    private:

        char m_data[N]{};
    };

    // Handles decryption and re-encryption of an encrypted string at runtime
    template <size_type N, key_type KEY>
    class obfuscated_data
    {
    public:
        obfuscated_data(const obfuscator<N, KEY>& obfuscator)
        {
            // Copy obfuscated data
            for (size_type i = 0; i < N; i++)
            {
                m_data[i] = obfuscator.data()[i];
            }
        }

        ~obfuscated_data()
        {
            // Zero m_data to remove it from memory
            for (size_type i = 0; i < N; i++)
            {
                m_data[i] = 0;
            }
        }

        // Returns a pointer to the plain text string, decrypting it if
        // necessary
        operator char*()
        {
            decrypt();
            return m_data;
        }

        // Manually decrypt the string
        void decrypt()
        {
            if (m_encrypted)
            {
                cipher(m_data, N, KEY);
                m_encrypted = false;
            }
        }

        // Manually re-encrypt the string
        void encrypt()
        {
            if (!m_encrypted)
            {
                cipher(m_data, N, KEY);
                m_encrypted = true;
            }
        }

        // Returns true if this string is currently encrypted, false otherwise.
        bool is_encrypted() const
        {
            return m_encrypted;
        }

    private:

        // Local storage for the string. Call is_encrypted() to check whether or
        // not the string is currently obfuscated.
        char m_data[N];

        // Whether data is currently encrypted
        bool m_encrypted{ true };
    };

    // This function exists purely to extract the number of elements 'N' in the
    // array 'data'
    template <size_type N, key_type KEY = OBFUSCATE_DEFAULT_KEY>
    constexpr auto make_obfuscator(const char(&data)[N])
    {
        return obfuscator<N, KEY>(data);
    }
}

#define OBFUSCATE(data) OBFUSCATE_KEY(data, OBFUSCATE_DEFAULT_KEY)

#define OBFUSCATE_KEY(data, key) \
	[]() -> obfs::obfuscated_data<sizeof(data)/sizeof(data[0]), key>& { \
		static_assert(sizeof(decltype(key)) == sizeof(obfs::key_type), "key must be a 64 bit unsigned integer"); \
		static_assert((key) >= (1ull << 56), "key must span all 8 bytes"); \
		constexpr auto n = sizeof(data)/sizeof(data[0]); \
		constexpr auto obfuscator = obfs::make_obfuscator<n, key>(data); \
		thread_local auto obfuscated_data = obfs::obfuscated_data<n, key>(obfuscator); \
		return obfuscated_data; \
	}()
#pragma endregion

#pragma region cryptograpy
namespace encryption {
/* Public domain sha256 implementation
 * Borrowed from musl libc's cryptography
 * original sha crypt design: http://people.redhat.com/drepper/SHA-crypt.txt
 * in this implementation at least 32bit int is assumed
 * key length **is** limited, the $5$ prefix is mandatory, '\n' and ':' are rejected
 * in the salt and rounds= setting must contain a valid iteration count,
 * on error "*" is returned */

#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>

// Public domain sha256 implementation based on fips180-3
struct sha256 {
    uint64_t len;    // processed message length
    uint32_t h[8];   // hash state
    uint8_t buf[64]; // message block buffer
};
static uint32_t ror(uint32_t n, int k) { return (n>>k) | (n << (32-k)); }
#define Ch(x, y, z)  (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((x & y) | (z & (x|y)))
#define S0(x)        (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22))
#define S1(x)        (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25))
#define R0(x)        (ror(x, 7) ^ ror(x, 18) ^ (x >> 3))
#define R1(x)	     (ror(x,17) ^ ror(x, 19) ^ (x >> 10))
static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
static void processblock(struct sha256 *s, const uint8_t *buf)
{
    uint32_t W[64], t1, t2, a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = (uint32_t)buf[4*i] << 24;
        W[i]|= (uint32_t)buf[4*i+1] >> 16;
        W[i]|= (uint32_t)buf[4*i+2] >> 8;
        W[i]|= buf[4*i+3];
    }
    for (; i < 64; i++)
        W[i] = R1(W[i-2]) + W[i-7] + R0(W[i-15]) + W[i-16];
    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    f = s->h[5];
    g = s->h[6];
    h = s->h[7];
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i];
        t2 = S0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += h;
}
static void pad(struct sha256 *s)
{
    unsigned r = s->len % 64;

    s->buf[r++] = 0x80;
    if (r > 56) {
        memset(s->buf + r, 0, 64 - r);
        r = 0;
        processblock(s, s->buf);
    }
    memset(s->buf + r, 0, 56 - r);
    s->len *= 8;
    s->buf[56] = s->len >> 56;
    s->buf[57] = s->len >> 48;
    s->buf[58] = s->len >> 40;
    s->buf[59] = s->len >> 32;
    s->buf[60] = s->len >> 24;
    s->buf[61] = s->len >> 16;
    s->buf[62] = s->len >> 8;
    s->buf[63] = s->len;
    processblock(s, s->buf);
}
static void sha256_init(struct sha256 *s)
{
    s->len = 0;
    s->h[0] = 0x6a09e667;
    s->h[1] = 0xbb67ae85;
    s->h[2] = 0x3c6ef372;
    s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f;
    s->h[5] = 0x9b05688c;
    s->h[6] = 0x1f83d9ab;
    s->h[7] = 0x5be0cd19;
}
static void sha256_sum(struct sha256 *s, uint8_t *md)
{
    int i;
    pad(s);
    for (i = 0; i < 8; i++) {
        md[4*i]   = s->h[i] >> 24;
        md[4*i+1] = s->h[i] >> 16;
        md[4*i+2] = s->h[i] >> 8;
        md[4*i+3] = s->h[i];
    }
}
static void sha256_update(struct sha256 *s, const void *m, unsigned long len)
{
    const uint8_t *p = (uint8_t*)m;
    unsigned r = s->len % 64;

    s->len += len;
    if (r) {
        if (len < 64 - r) {
            memcpy(s->buf + r, p, len);
            return;
        }
        memcpy(s->buf + r, p, 64 - r);
        len -= 64 - r;
        p += 64 - r;
        processblock(s, s->buf);
    }
    for (; len >= 64; len -= 64, p += 64)
        processblock(s, p);
    memcpy(s->buf, p, len);
}
static const unsigned char b64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static char *to64(char *s, unsigned int u, int n)
{
    while (--n >= 0) {
        *s++ = b64[u % 64];
        u /= 64;
    }
    return s;
}
/* key limit is not part of the original design, added for DoS protection.
 * rounds limit has been lowered (versus the reference/spec), also for DoS
 * protection. runtime is O(klen^2 + klen*rounds) */
#define KEY_MAX 65535
#define SALT_MAX 16
#define ROUNDS_DEFAULT 5000
#define ROUNDS_MIN 1000
#define ROUNDS_MAX 99999
// hash n bytes of the repeated md message digest
static void hashmd(struct sha256 *s, unsigned int n, const void *md) {
    unsigned int i;
    for (i = n; i > 32; i -= 32)
        sha256_update(s, md, 32);
    sha256_update(s, md, i);
}
static char *sha256crypt(const char *key, const char *setting, char *output)
{
    struct sha256 ctx;
    unsigned char md[32], kmd[32], smd[32];
    unsigned int i, r, klen, slen;
    char rounds[20] = "";
    const char *salt;
    char *p;

    // reject large keys
    klen = strnlen(key, KEY_MAX+1);
    if (klen > KEY_MAX)
        return 0;

    // setting: $5%rounds=n$salt$ (rounds=n$ and closing $ are optional)
    if (strncmp(setting, "$5$", 3) != 0)
        return 0;
    salt = setting + 3;

    r = ROUNDS_DEFAULT;
    if (strncmp(salt, "rounds=", sizeof "rounds=" - 1) == 0) {
        unsigned long u;
        char *end;

        // this is a deviation from the reference
        // bad rounds setting is rejected if it is:
        // - empty
        // - unterminated (missing '$')
        // - begins with anything but a decimal digit
        // the reference implementation treats these bad
        // rounds as part of the salt or parse them with
        // strtoul semantics which may cause problems
        // including non-portable hashes that depend on
        // the hosts value of ULONG_MAX
        salt += sizeof "rounds="-1;
        if (!isdigit(*salt))
            return 0;
        u = strtoul(salt, &end, 10);
        if (*end != '$')
            return 0;
        salt = end + 1;
        if (u < ROUNDS_MIN)
            r = ROUNDS_MIN;
        else if (u > ROUNDS_MAX)
            return 0;
        else
            r = u;
        // needed when rounds is zero prefixed or out of bounds
        sprintf(rounds, "rounds=%u$", r);
    }
    for (i = 0; i< SALT_MAX && salt[i] && salt[i] != '$'; i++)
        // reject characters that interfere with /etc/shadow parsing
        if (salt[i] == '\n' || salt[i] == ':')
            return 0;
    slen = i;

    // B = sha(key salt key)
    sha256_init(&ctx);
    sha256_update(&ctx, key, klen);
    sha256_update(&ctx, salt, slen);
    sha256_update(&ctx, key, klen);
    sha256_sum(&ctx, md);

    // A = sha(key salt repeat-B alternate-B-key)
    sha256_init(&ctx);
    sha256_update(&ctx, key, klen);
    sha256_update(&ctx, salt, slen);
    for (i = klen; i > 0; i >>= 1)
        if (i & 1)
            sha256_update(&ctx, md, sizeof md);
        else
            sha256_update(&ctx, key, klen);
    sha256_sum(&ctx, md);

    // DP = sha(repeat-key), this step takes O(klen^2) time
    sha256_init(&ctx);
    for (i = 0; i < klen; i++)
        sha256_update(&ctx, key, klen);
    sha256_sum(&ctx, kmd);

    // DS = sha(repeat-salt)
    sha256_init(&ctx);
    for (i = 0; i < 16 + md[0]; i++)
        sha256_update(&ctx, salt, slen);
    sha256_sum(&ctx, smd);

    // iterate A = f(A,DP,DS), this step takes O(rounds*klen) time

    for (i = 0; i < r; i++) {
        sha256_init(&ctx);
        if (i % 2)
            hashmd(&ctx, klen, kmd);
        else
            sha256_update(&ctx, md, sizeof md);
        if (i % 3)
            sha256_update(&ctx, smd, slen);
        if (i % 7)
            hashmd(&ctx, klen, kmd);
        if (i % 2)
            sha256_update(&ctx, md, sizeof md);
        else
            hashmd(&ctx, klen, kmd);
        sha256_sum(&ctx, md);
    }

    // output is %5%rounds=n$salt$hash
    p = output;
    // Uncomment if you want to print the salt and all that.
    // Unnecessary for current use case.
    //p += sprintf(p, "$5$%s%.*s$", rounds, slen, salt);
    static const unsigned char perm[][3] = {
            0,10,20,21,1,11,12,22,2,3,13,23,24,4,14,15,25,5,6,16,26,27,7,17,18,28,8,9,19,29};
    for (i=0; i<10;i++) p = to64(p,
                                 (md[perm[i][0]]<<16)|(md[perm[i][1]]<<8)|md[perm[i][2]], 4);
    p = to64(p, (md[31]<<8)|md[30], 3);
    *p = 0;
    return output;
}
char *__crypt_sha256(const char *key, const char *setting, char *output)
{
    static const char testkey[] = "Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    static const char testsetting[] = "$5$rounds=1234$abc0123456789$";
    static const char testhash[] = "$5$rounds=1234$abc0123456789$3VfDjP";
    char testbuf[128];
    char *p, *q;

    p = sha256crypt(key, setting, output);
    // self test and stack cleanup
    q = sha256crypt(testkey, testsetting, testbuf);
    if (!p || q != testbuf || memcmp(testbuf, testhash, sizeof testhash))
        return (char*) "*";
    return p;
}
} // End of Namespace

/// Performs SHA256 Cryptographic hash on input str
static std::string encrypt(const std::string str)
{
    char out[420] = {0};
    encryption::__crypt_sha256(str.c_str(), "$5$rounds=1234$abc0123456789$", out);
    return std::string(out);
}


#pragma endregion


// TODO: Refactor HardwareProfile such that each token is hashed separately.
#pragma region HardwareID Header
    namespace tuxID
{

    struct HardwareProfile
    {
        std::vector<std::string> diskSerialCodeHashes;
        std::string isSuperUserHash;
        std::string isVirtualMachineHash;
        std::string moboVendorHash;
        std::string vmVendorHash;
    };

    HardwareProfile getCurrentHardwareProfile();
    std::vector<std::string> getDiskSerialCodes();
    std::string getFileContents(const std::string string);
    std::vector<std::string> getBlockDevices();
    bool getIsLikelyVirtualMachine();
    bool getIsDefinitelyVirtualMachine();
    bool isClientTampering();
    bool isVirtualMachine();
    std::vector<int> isDebuggerAttached();
    std::string getProcessName(int pid);
    bool isSuperUser();
    bool isLDPreload();
    void storeSDLFunctionPointer();
    std::string getMotherboardVendor();
    std::string getVMType();
}

#pragma endregion

#pragma region HardwareID Methods
uintptr_t swapWindowAddress = 0;
void* libSDL = NULL;

template <typename T>
static constexpr auto relativeToAbsolute(std::uintptr_t address) noexcept {
    return (T)(address + 4 + *reinterpret_cast<std::int32_t*>(address));
}
tuxID::HardwareProfile tuxID::getCurrentHardwareProfile() {
    tuxID::HardwareProfile profile;
    std::vector<std::string> diskSerialCodes = getDiskSerialCodes();
    for (int i = 0; i < diskSerialCodes.size(); i++) {
        diskSerialCodes[i] = encrypt(diskSerialCodes[i]);
    }
    profile.diskSerialCodeHashes = diskSerialCodes;
    profile.isSuperUserHash = isSuperUser();
    return profile;
}
std::string tuxID::getVMType() {
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("KVM")))
        return std::string(OBFUSCATE("KVM"));
    if(tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("VirtualBox")))
        return std::string(OBFUSCATE("VirtualBox"));
    if(tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))).find(OBFUSCATE("VMware")) != std::string::npos)
        return std::string(OBFUSCATE("VMware"));
    return std::string(OBFUSCATE("Unknown"));
}

std::string tuxID::getMotherboardVendor()
{
    std::string vendor = tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/sys_vendor")));
    return vendor + " " + encrypt(vendor);
}

bool tuxID::isSuperUser() {
    if (getuid() == 0)
        return true;
    return false;
}

bool tuxID::isLDPreload() {
    if(std::getenv(OBFUSCATE("LD_PRELOAD")))
        return true;
    return false;
}

void tuxID:: storeSDLFunctionPointer() {
    if (tuxID::getFileContents(std::string(OBFUSCATE("/proc/self/maps"))).find(OBFUSCATE("libSDL2-2.0.so.0")) != std::string::npos) {
        swapWindowAddress = relativeToAbsolute<uintptr_t>(uintptr_t(dlsym(libSDL, "SDL_GL_SwapWindow")) + 2);
    }
}
std::vector<std::string> tuxID::getBlockDevices() {
    std::vector<std::string> array;
    for (const auto blockDevice: std::filesystem::directory_iterator(std::string(OBFUSCATE("/dev/disk/by-path")))) {
        if(blockDevice.is_block_file()) {
            array.push_back(blockDevice.path());
            for (int i = 0; i < array.size(); i++) {
                //TODO gather data on external devices separately.
                if((array[i]).find(std::string(OBFUSCATE("-part"))) != std::string::npos ||
                (array[i]).find(std::string(OBFUSCATE("virtio"))) != std::string::npos ||
                (array[i]).find(std::string(OBFUSCATE("-usb"))) != std::string::npos) {
                    array.erase(array.begin()+i);
                }
            }
        }
    }
    if (array.size() == 0)
        return std::vector<std::string>{std::string(OBFUSCATE("NULL"))};
    return array;
}

bool tuxID::isClientTampering() {
    std::string modules = tuxID::getFileContents(std::string(OBFUSCATE("/proc/modules")));
    std::string maps = tuxID::getFileContents(std::string(OBFUSCATE("/proc/self/maps")));
    if (maps.find("libSDL2-2.0.so.0"))
        libSDL = dlopen("libSDL2-2.0.so.0", RTLD_LAZY | RTLD_NOLOAD);
    //LWSS Cartographer
    if (std::ifstream(std::string(OBFUSCATE("/proc/cartographer"))))
        return true;
    if (modules.find(std::string(OBFUSCATE("cartographer"))) != std::string::npos)
        return true;

    //LWSS Tracerhid
    if (modules.find(std::string(OBFUSCATE("tracerhid"))) != std::string::npos)
        return true;

    //vkBasalt, A ReShade implementation for GNU/Linux.
    if (maps.find(std::string(OBFUSCATE("vkbasalt.so"))) != std::string::npos)
        return true;

    //Detect SDL2 SwapWindow Hook.
    //Requires "tuxID::storeSDLFunctionPointer" to be ran directly after SDL2 is initialized in your project.
    if (swapWindowAddress != 0 && maps.find(OBFUSCATE("libSDL2-2.0.so.0"))) {
        if (swapWindowAddress != relativeToAbsolute<uintptr_t>(uintptr_t(dlsym(libSDL,OBFUSCATE("SDL_GL_SwapWindow"))) + 2)) {
            dlclose(libSDL);
            return true;
        }
    }
    return false;
}
//Read entire file into std::string and return
std::string tuxID::getFileContents(const std::string string) {
    size_t pos;
    std::string content;
    std::ifstream file(string);
    if (file) {
        std::ostringstream stringStream;
        stringStream << file.rdbuf();
        content = stringStream.str();

        // The /sys/devices files have blank areas at the bottom!!!!
        while ((pos = content.find(OBFUSCATE("\n"), 0)) != std::string::npos) {
            content.erase(pos, 1);
        }
        return content;
    }
    return std::string(OBFUSCATE("NULL"));
}

std::string tuxID::getProcessName(int pid) {
    //Check if the TracerPID is not 0, Which would be our own process.
    std::ifstream file("/proc/" + std::to_string(pid) + "/status");
    //This will fail if the process was created by the root user & we do not have superuser.
    if(!file.good())
        return "unknown.";
    std::string string;
    std::string name;
    while (file >> string) {
        if (string == std::string(OBFUSCATE("Name:"))) {
            file >> name;
            std::getline(file, string);
        }
        return name;
    }
}
std::vector<int> tuxID::isDebuggerAttached() {
    //Check if the TracerPID is not 0, Which would be our own process.
    std::ifstream file(OBFUSCATE("/proc/self/status"));
    std::string string;
    while (file >> string) {
        if (string == std::string(OBFUSCATE("TracerPid:"))) {
            int pid;
            file >> pid;
            if (pid != 0)
                return std::vector<int>{true,pid};
        }
        std::getline(file, string);
    }
    return std::vector<int>{false};
}

std::vector<std::string> tuxID::getDiskSerialCodes()  {
    struct udev *ud = NULL;
    struct stat statbuf;
    struct udev_device *device = NULL;
    struct udev_list_entry *entry = NULL;
    std::vector<std::string> blockDevices = tuxID::getBlockDevices();
    std::vector<std::string> array;

    for (int i = 0; i < blockDevices.size(); i++) {
        ud = udev_new();
        if (ud == NULL)
            return std::vector<std::string> {(std::string(OBFUSCATE("NULL")))};

        if (0 != stat(blockDevices[i].c_str(), &statbuf))
            return std::vector<std::string> {(std::string(OBFUSCATE("NULL")))};

        device = udev_device_new_from_devnum(ud, 'b', statbuf.st_rdev);
        if (device == NULL)
            return std::vector<std::string> {(std::string(OBFUSCATE("NULL")))};

        entry = udev_device_get_properties_list_entry(device);
        while (NULL != entry) {
            if (0 == strcmp(udev_list_entry_get_name(entry),
                            OBFUSCATE("ID_SERIAL"))) {
                break;
            }

            entry = udev_list_entry_get_next(entry);
        }
        array.push_back(std::string(udev_list_entry_get_value(entry)));
    }
    if(array.size() == 0 || array[0] == std::string(OBFUSCATE("NULL")))
        return std::vector<std::string>{"NULL"};
    sort(array.begin(), array.end());
    array.erase( unique( array.begin(), array.end()), array.end());
    return array;
}

bool tuxID::isVirtualMachine() {
    // Check if the system responds to queries about known Virtual Machine modules.
    // If these modules are nonexistent on the system, we will return 0.

    std::string modules = tuxID::getFileContents(std::string(OBFUSCATE("/proc/modules")));
    // Check for Virtio Module
    // https://developer.ibm.com/articles/l-virtio/
    if (modules.find(std::string(OBFUSCATE("virtio"))) != std::string::npos)
        return true;
    // Check for VirtualBox Guest Additions Module
    // https://www.virtualbox.org/manual/UserManual.html#additions-linux
    if (modules.find(std::string(OBFUSCATE("vboxguest"))) != std::string::npos)
        return true;
    // Check for Cirrus CI Module
    if (modules.find(std::string(OBFUSCATE("cirrus"))) != std::string::npos)
        return true;
    // Check for VirtualBox Video Module
    if (modules.find(std::string(OBFUSCATE("vboxvideo"))) != std::string::npos)
        return true;
    // Check if the motherboard name is "KVM"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("KVM")))
        return true;
    // Check if the motherboard name is "VirtualBox"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("VirtualBox")))
        return true;
    //Check if the motherboard name contains "VMWare"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))).find(std::string(OBFUSCATE("VMware"))) != std::string::npos)
        return true;
    // Check for VMWare Guest Graphics Module
    if (modules.find(std::string(OBFUSCATE("vmwgfx"))) != std::string::npos)
        return true;
    //VMWare module which facilitates things like "drag n' drop".
    if (modules.find(std::string(OBFUSCATE("vmw_vsock_virtio_transport_common"))) != std::string::npos)
        return true;
    if (modules.find(std::string(OBFUSCATE("vmw_balloon"))) != std::string::npos)
        return true;
    //Check if we're inside of a docker container.
    if (tuxID::getFileContents(std::string(OBFUSCATE("/proc/1/sched"))).find(std::string(OBFUSCATE("bash"))) != std::string::npos)
        return true;
    // Check for VirtIO filesystem
    //Keep this one at the end, It is extremely likely that the other checks give it away and this file is usually long.
    if (tuxID::getFileContents(std::string(OBFUSCATE("/proc/self/mounts"))).find(std::string(OBFUSCATE("/dev/vda"))) != std::string::npos)
        return true;
    return false;
}

#pragma endregion