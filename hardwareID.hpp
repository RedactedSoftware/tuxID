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

    namespace tuxID
{

    struct HardwareProfile
    {
        std::string diskSerialCode;
    };


    HardwareProfile getCurrentHardwareProfile();
    std::string getHardwareHash(HardwareProfile);
    std::string getHardwareHash();
    std::vector<std::string> getDiskSerialCodes();
    std::string getFileContents(const std::string string);
    std::vector<std::string> getBlockDevices();
    bool getIsLikelyVirtualMachine();
    bool getIsDefinitelyVirtualMachine();
    bool isKernelTampering();
    bool isVirtualMachine();
    bool isDebuggerAttached();
    bool isSuperUser();
    bool isLDPreload();
}

bool tuxID::isSuperUser() {
    if (getuid() == 0)
        return 1;
    return 0;
}

bool tuxID::isLDPreload() {
    if(std::getenv(OBFUSCATE("LD_PRELOAD")))
        return 1;
    return 0;
}

std::vector<std::string> tuxID::getBlockDevices() {
    std::vector<std::string> array;
    for (const auto blockDevice: std::filesystem::directory_iterator(std::string(OBFUSCATE("/dev/disk/by-path")))) {
        if(blockDevice.is_block_file()) {
            array.push_back(blockDevice.path());
            for (int i = 0; i < array.size(); i++) {
                if((array[i]).find(std::string(OBFUSCATE("-part"))) != std::string::npos || (array[i]).find(std::string(OBFUSCATE("virtio"))) != std::string::npos) {
                    array.erase(array.begin()+i);
                }
            }
        }
    }
    if (array.size() == 0)
        return std::vector<std::string>{std::string(OBFUSCATE("NULL"))};
    return array;
}
bool tuxID::isKernelTampering() {
    //TODO Check dmesg for outputs found within LWSS Cartographer and LWSS tracerhid.
    std::string modules = tuxID::getFileContents(std::string(OBFUSCATE("/proc/modules")));

    //LWSS Cartographer
    if (std::ifstream(std::string(OBFUSCATE("/proc/cartographer"))))
        return 1;
    if(modules.find(std::string(OBFUSCATE("cartographer"))) != std::string::npos)
        return 1;

    //LWSS Tracerhid
    if(modules.find(std::string(OBFUSCATE("tracerhid"))) != std::string::npos)
        return 1;
    return 0;
}
//Read entire file into std::string and return
std::string tuxID::getFileContents(const std::string string) {
    size_t pos;
    std::string content;
    std::ifstream file(string);
    if(file){
        std::ostringstream stringStream;
        stringStream << file.rdbuf();
        content = stringStream.str();

        // The /sys/devices files have blank areas at the bottom!!!!
        while ((pos= content.find(OBFUSCATE("\n"), 0)) != std::string::npos) {
            content.erase(pos, 1);
        }
        return content;
    }
    return NULL;
}

bool tuxID::isDebuggerAttached() {
    //Check if the TracerPID is not 0, Which would be our own process.
    //This only works if the debugger was not attached after execution has started.
    //TODO detect if debugger is attached after execution has started.
    std::ifstream file(OBFUSCATE("/proc/self/status"));
    std::string string;
    while (file >> string) {
        if (string == std::string(OBFUSCATE("TracerPid:"))) {
            int pid;
            file >> pid;
            if (pid != 0)
                return 1;
        }
        std::getline(file, string);
    }
    return 0;
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
        array.erase( unique( array.begin(), array.end()), array.end());
    }
    if(array.size() == 0 || array[0] == std::string(OBFUSCATE("NULL")))
        return std::vector<std::string>{"NULL"};
    return array;
}

bool tuxID::isVirtualMachine() {
    // Check if the system responds to queries about known Virtual Machine modules.
    // If these modules are nonexistent on the system, we will return 0.

    std::string modules = tuxID::getFileContents(std::string(OBFUSCATE("/proc/modules")));
    // Check for Virtio Module
    // https://developer.ibm.com/articles/l-virtio/
    if (modules.find(std::string(OBFUSCATE("virtio"))) != std::string::npos)
        return 1;
    // Check for VirtualBox Guest Additions Module
    // https://www.virtualbox.org/manual/UserManual.html#additions-linux
    if (modules.find(std::string(OBFUSCATE("vboxguest"))) != std::string::npos)
        return 1;
    // Check for Cirrus CI Module
    if (modules.find(std::string(OBFUSCATE("cirrus"))) != std::string::npos)
        return 1;
    // Check for VirtualBox Video Module
    if (modules.find(std::string(OBFUSCATE("vboxvideo"))) != std::string::npos)
        return 1;
    // Check if the motherboard name is "KVM"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("KVM")))
        return 1;
    // Check if the motherboard name is "VirtualBox"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))) == std::string(OBFUSCATE("VirtualBox")))
        return 1;
    //Check if the motherboard name contains "VMWare"
    if (tuxID::getFileContents(std::string(OBFUSCATE("/sys/devices/virtual/dmi/id/product_name"))).find(std::string(OBFUSCATE("VMware"))) != std::string::npos)
        return 1;
    // Check for VMWare Guest Graphics Module
    if (modules.find(std::string(OBFUSCATE("vmwgfx"))) != std::string::npos)
        return 1;
    //VMWare module which facilitates things like "drag n' drop".
    if (modules.find(std::string(OBFUSCATE("vmw_vsock_virtio_transport_common"))) != std::string::npos)
        return 1;
    if (modules.find(std::string(OBFUSCATE("vmw_balloon"))) != std::string::npos)
        return 1;
    //Check if we're inside of a docker container.
    if (tuxID::getFileContents(std::string(OBFUSCATE("/proc/1/sched"))).find(std::string(OBFUSCATE("bash"))) != std::string::npos)
        return 1;
    // Check for VirtIO filesystem
    //Keep this one at the end, It is extremely likely that the other checks give it away and this file is usually long.
    if (tuxID::getFileContents(std::string(OBFUSCATE("/proc/self/mounts"))).find(std::string(OBFUSCATE("/dev/vda"))) != std::string::npos)
        return 1;
    return 0;
}