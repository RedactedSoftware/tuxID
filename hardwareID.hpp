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
    std::string getDiskSerialCode();
    bool scanDMIData(std::string string);
    bool getIsLikelyVirtualMachine();
    bool getIsDefinitelyVirtualMachine();
    bool isVirtualMachine();
    bool isDebuggerAttached();
    bool isSuperUser();
    bool shellCommandReturns(const char* command);
    bool shellCommandReturns(const std::string);
}

bool tuxID::isSuperUser() {
    if (getuid() == 0)
        return 1;
    return 0;
}
bool tuxID::scanDMIData(const std::string string) {
    if (!isSuperUser())
        return 0;
    std::string command = std::string(OBFUSCATE("dmidecode | grep "));
    command = command.append(string);
    FILE *shellCommand = popen(command.c_str(), "r");
    char buf[16];
    if (fread (buf, 1, sizeof (buf), shellCommand) > 0) {
        return 1;
    }
    return 0;
}


// Runs a shell command & returns 1 if the command returns any result
// Returns 0 if the command returns nothing
bool tuxID::shellCommandReturns(const char* command) {
    FILE *shellCommand = popen(command, "r");
    char buf[16];
    if (fread (buf, 1, sizeof (buf), shellCommand) > 0) {
        return 1;
    }
    return 0;
}
bool tuxID::shellCommandReturns(const std::string command) {
    return tuxID::shellCommandReturns(command.c_str());
}

std::string tuxID::getDiskSerialCode()  {
    struct udev *ud = NULL;
    struct stat statbuf;
    struct udev_device *device = NULL;
    struct udev_list_entry *entry = NULL;

    ud = udev_new();
    if (NULL == ud) {
        fprintf(stderr, OBFUSCATE("Failed to init udev.\n"));
        return std::string(OBFUSCATE("unavailable"));
    }
    // TODO: Detect drive type.
    std::string diskTypes[5] = {std::string (OBFUSCATE("/dev/sda")), std::string (OBFUSCATE("/dev/sdb")), std::string (OBFUSCATE("/dev/mmcblk0")), std::string (OBFUSCATE("/dev/nvme0"))};
    int arrayPosition = 0;
    while(0 != stat(diskTypes[arrayPosition].c_str(), &statbuf)){
        arrayPosition = arrayPosition + 1;
    }
    if (0 != stat(diskTypes[arrayPosition].c_str(), &statbuf)) {
	return std::string(OBFUSCATE("unavailable"));
    }
    device = udev_device_new_from_devnum(ud, 'b', statbuf.st_rdev);
    if (NULL == device) {
        return std::string(OBFUSCATE("unavailable"));
    }

    entry = udev_device_get_properties_list_entry(device);
    while (NULL != entry) {
        if (0 == strcmp(udev_list_entry_get_name(entry),
                        OBFUSCATE("ID_SERIAL"))) {
            break;
        }

        entry = udev_list_entry_get_next(entry);
    }
    //printf(udev_list_entry_get_value(entry));
    return std::string(udev_list_entry_get_value(entry));
}

bool tuxID::isVirtualMachine() {
    // Check if the system responds to queries about known Virtual Machine modules.
    // If these modules are nonexistent on the system, we will return 0.


    // Check for Virtio Module
    // https://developer.ibm.com/articles/l-virtio/
    if (tuxID::shellCommandReturns(std::string(OBFUSCATE("lsmod | grep virtio"))))
        return 1;
    // Check for VirtualBox Module
    // https://www.virtualbox.org/manual/UserManual.html#additions-linux
    if (tuxID::shellCommandReturns(OBFUSCATE("lsmod | grep vboxguest")))
        return 1;
    // Check for  VMWare Guest Graphics Module
    if (tuxID::shellCommandReturns(OBFUSCATE("lsmod | grep vmwgfx")))
        return 1;
    // Check for Cirrus CI Module
    if(tuxID::shellCommandReturns(OBFUSCATE("lsmod | grep cirrus")))
        return 1;
    // Check for VirtualBox Video Module
    if(tuxID::shellCommandReturns(OBFUSCATE("lsmod | grep vboxvideo")))
        return 1;
    // Check for QEMU module
    if(tuxID::shellCommandReturns(OBFUSCATE("lsmod | grep qemu")))
        return 1;
    // Check for virtualized filesystem
    if (tuxID::shellCommandReturns(OBFUSCATE("cat /etc/fstab | grep /dev/vda")))
        return 1;
    // Poke the "BIOS" "ROM" To check for KVM Tag
    std::string (OBFUSCATE("string"));
    if (tuxID::scanDMIData(std::string (OBFUSCATE("string"))))
        return 1;
    // Poke the "BIOS" "ROM" To check for VirtualBox Tag
    if (tuxID::scanDMIData(std::string(OBFUSCATE("VirtualBox"))))
        return 1;

    return 0;
}

bool tuxID::isDebuggerAttached() {

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
        return false;
}