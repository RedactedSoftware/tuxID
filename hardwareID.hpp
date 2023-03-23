#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <libudev.h>
#include <sys/stat.h>
#include <sys/stat.h>



const char* diskSerial()  {
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
    return udev_list_entry_get_value(entry);
}

bool isVirtualMachine() {
    //modprobe for virtio
    FILE *fd = popen("lsmod | grep virtio", "r");
    char buf[16];
    if (fread (buf, 1, sizeof (buf), fd) > 0) {
        return 1;
    }

    //modprobe for virtio
    FILE *fd = popen("cat /etc/fstab | grep vda", "r");
    char buf[16];
    if (fread (buf, 1, sizeof (buf), fd) > 0) {
        return 1;
    }


    return 0;
}