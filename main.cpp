#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << "HardwareID Demo" << std::endl;
    std::cout << "Disk Serial Code (SATA): " << Stepbro::HardwareID::getDiskSerialCode("/dev/sda")    << std::endl;
    std::cout << "Disk Serial Code (IDE): "  << Stepbro::HardwareID::getDiskSerialCode("/dev/hda")    << std::endl;
    std::cout << "Disk Serial Code (NVMe): " << Stepbro::HardwareID::getDiskSerialCode("/dev/nvme")   << std::endl;
    std::cout << "Disk Serial Code (eMMC): " << Stepbro::HardwareID::getDiskSerialCode("/dev/mmcblk") << std::endl;
    std::cout << "VM Detected: " << Stepbro::HardwareID::isVirtualMachine() << std::endl;
   return 0;
}
