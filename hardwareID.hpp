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
// Further Considerations: hardware changes slowly over time, but hashes

// LICENSE //
// MIT

// SAMPLES //

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <libudev.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <unistd.h>

#include "obfuscation.hpp"

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
    bool scanDMIData(std::string);
    std::string readDMIData(std::string);
    bool isVirtualMachine();
    bool isDebuggerAttached();
    bool isSuperUser();
    bool shellCommandReturns(const char* command);
    bool shellCommandReturns(const std::string);
    bool isLDPreload();
}

bool tuxID::isSuperUser() {
    if (getuid() == 0)
        return 1;
    return 0;
}

// Alternatively, SMBIOS I/O can be implemented as a CPP Library
// To probably achieve platform
// https://github.com/dell/libsmbios

// @see: https://en.wikipedia.org/wiki/Dmidecode
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

std::string tuxID::readDMIData(const std::string keyword)
{
    if (!isSuperUser())
        return 0;
    // TODO: Research dmidecode source code
    std::string command = "dmidecode | grep -w '";
    command = command.append(keyword);
    command = command.append("'");
    FILE *shellCommand = popen(command.c_str(), "r");
    char buf[1024]; // Use larger buffer because we want to actually read the result.
    if (fread (buf, 1, sizeof (buf), shellCommand) > 0)
        return std::string(buf);
    return "";
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
    if (tuxID::scanDMIData(std::string (OBFUSCATE("KVM"))))
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
        return 0;
}

bool tuxID::isLDPreload() {
        if(std::getenv(OBFUSCATE("LD_PRELOAD")))
            return 1;
    return 0;
}
