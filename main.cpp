#include "hardwareID.hpp"
#include <iostream>

int main()
{
    std::cout << OBFUSCATE("HardwareID Demo") << std::endl;
    std::cout << OBFUSCATE("Disk Serial Code: ") << tuxID::getDiskSerialCode()  << std::endl;
    std::cout << OBFUSCATE("Is SuperUser: ") << tuxID::isSuperUser() << std::endl;
    std::cout << OBFUSCATE("VM Detected: ") << tuxID::isVirtualMachine() << std::endl;
    std::cout << OBFUSCATE("Debugger Attached: ") << tuxID::isDebuggerAttached() << std::endl;
    std::cout << OBFUSCATE("LD_PRELOAD: ") << tuxID::isLDPreload() << std::endl;
    if (tuxID::scanDMIData(std::string (OBFUSCATE("VirtualBox")))) {
        std::cout << std::string (OBFUSCATE("Virtual Machine Type: VirtualBox")) << std::endl;
    }
    if (tuxID::scanDMIData("KVM")) {
        std::cout << std::string (OBFUSCATE("Virtual Machine Type: KVM")) << std::endl;
    }
   return 0;
}
