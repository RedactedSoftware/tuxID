#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << "HardwareID Demo" << std::endl;
    std::cout << "Disk Serial Code: " << Stepbro::HardwareID::getDiskSerialCode() << std::endl;
    std::cout << "VM Detected: " << Stepbro::HardwareID::isVirtualMachine() << std::endl;
   return 0;
}