#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << "HardwareID Demo" << std::endl;
    std::cout << "Disk Serial Code (SATA): " << tuxID::getDiskSerialCode("/dev/sda")    << std::endl;
    std::cout << "Disk Serial Code (IDE): "  << tuxID::getDiskSerialCode("/dev/hda")    << std::endl;
    std::cout << "Disk Serial Code (NVMe): " << tuxID::getDiskSerialCode("/dev/nvme")   << std::endl;
    std::cout << "Disk Serial Code (eMMC): " << tuxID::getDiskSerialCode("/dev/mmcblk") << std::endl;
    std::cout << "VM Detected: " << tuxID::isVirtualMachine() << std::endl;
   return 0;
}
