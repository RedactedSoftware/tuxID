#include "hardwareID.hpp"
#include <iostream>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>

int main()
{
    std::cout << OBFUSCATE("HardwareID Demo") << std::endl;
    // TODO: Implement string::trim
    std::cout << tuxID::readDMIData("Currently Installed Language:");
    std::cout << tuxID::readDMIData("Range Size:");
    std::cout << tuxID::readDMIData("Family");
    std::cout << tuxID::readDMIData("Socket");

    std::cout << OBFUSCATE("BIOS: ") << tuxID::readDMIData("Vendor:") << ".";
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
