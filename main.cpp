#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << "HardwareID Demo" << std::endl;
    std::cout << "BIOS Vendor: " << tuxID::readDMIData("Vendor:") << std::endl;
    std::cout << "Disk Serial Code: " << tuxID::getDiskSerialCode()  << std::endl;
    std::cout << "Is SuperUser: " << tuxID::isSuperUser() << std::endl;
    std::cout << "VM Detected: " << tuxID::isVirtualMachine() << std::endl;
    if (tuxID::scanDMIData("VirtualBox")) {
        std::cout << "Virtual Machine Type: VirtualBox" << std::endl;
    }
    if (tuxID::scanDMIData("KVM")) {
        std::cout << "Virtual Machine Type: KVM" << std::endl;
    }
   return 0;
}
