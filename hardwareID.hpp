/// Hardware ID -
// @auth William J. Tomasine II, Josh O'Leary
// This module facilitates uniquely identifying devices by tokens pulled from hardware.
// In this specific implementation case, for x86 desktops running Linux.

// A Hardware Hash is generated via concatenating the Hardware Profile fields
// into one string, and feeding that to a standard cryptographic hashing algorithm.

// This hash uniquely identifies the device, without presenting a privacy hazard to the device owner.
// Use cases:
// Prevent MultiAccounting in online games.
// Detect end-users running VPNs, Virtual Machines etc.

// Further Considerations: hardware changes slowly over time, but hashes


// TODO LIST:
// Decide on names HardwareID or TuxID

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <libudev.h>
#include <sys/stat.h>
#include <sys/stat.h>


namespace Stepbro::HardwareID
{

    struct HardwareProfile
    {
        std::string diskSerialCode;
    };


    HardwareProfile getCurrentHardwareProfile();
    std::string getHardwareHash(HardwareProfile);
    std::string getHardwareHash();
    std::string getDiskSerialCode();
    bool getIsLikelyVirtualMachine();
    bool getIsDefinitelyVirtualMachine();
    bool isVirtualMachine();
}


std::string Stepbro::HardwareID::getDiskSerialCode()  {
    struct udev *ud = NULL;
    struct stat statbuf;
    struct udev_device *device = NULL;
    struct udev_list_entry *entry = NULL;

    ud = udev_new();
    if (NULL == ud) {
        fprintf(stderr, "Failed to init udev.\n");
        exit(1);
    }
    if (0 != stat("/dev/sda", &statbuf)) {
        fprintf(stderr, "Failed to stat /dev/sda.\n");
        exit(1);
    }
    device = udev_device_new_from_devnum(ud, 'b', statbuf.st_rdev);
    if (NULL == device) {
        fprintf(stderr, "Failed to open /dev/sda.\n");
        exit(1);
    }

    entry = udev_device_get_properties_list_entry(device);
    while (NULL != entry) {
        if (0 == strcmp(udev_list_entry_get_name(entry),
                        "ID_SERIAL")) {
            break;
        }

        entry = udev_list_entry_get_next(entry);
    }
    //printf(udev_list_entry_get_value(entry));
    return std::string(udev_list_entry_get_value(entry));
}

bool Stepbro::HardwareID::isVirtualMachine() {
    //modprobe for virtio
    FILE *fd = popen("lsmod | grep virtio", "r");
    char buf[16];
    if (fread (buf, 1, sizeof (buf), fd) > 0) {
        return 1;
    }

    //modprobe for virtio
    fd = popen("cat /etc/fstab | grep vda", "r");
    buf[16];
    if (fread (buf, 1, sizeof (buf), fd) > 0) {
        return 1;
    }


    return 0;
}