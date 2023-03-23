#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << "HardwareID Demo" << std::endl;
    std::cout << "Disk Serial Code" << tuxID::getDiskSerialCode()  << std::endl;
    std::cout << "VM Detected: " << tuxID::isVirtualMachine() << std::endl;
   return 0;
}
