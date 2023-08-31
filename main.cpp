#include "hardwareID.hpp"
#include <iostream>

int main()
{
    tuxID::storeSDLFunctionPointer();
    std::cout << OBFUSCATE("HardwareID Demo") << std::endl;
    std::cout << OBFUSCATE("Disk Serial Codes: ");
    for (int i = 0; i < tuxID::getDiskSerialCodes().size(); i++) {
        std::cout << tuxID::getDiskSerialCodes()[i];
        if(i < tuxID::getDiskSerialCodes().size() -1)
            std::cout << OBFUSCATE(", ");
        if(i == tuxID::getDiskSerialCodes().size() -1)
            std::cout << std::endl;
    }
    std::cout << OBFUSCATE("Motherboard Vendor: ") << tuxID::getMotherboardVendor() << std::endl;
    std::cout << OBFUSCATE("Is SuperUser: ") << tuxID::isSuperUser() << std::endl;
    std::cout << OBFUSCATE("VM Detected: ") << tuxID::isVirtualMachine() << std::endl;
    if (tuxID::isVirtualMachine())
        std::cout << OBFUSCATE("VM Type: ") << tuxID::getVMType() << std::endl;
    std::cout << OBFUSCATE("Debugger Attached: ") << tuxID::isDebuggerAttached()[0] << std::endl;
    if (tuxID::isDebuggerAttached()[0] == true)
        std::cout << OBFUSCATE("Debugger Name: ") << tuxID::getProcessName(tuxID::isDebuggerAttached()[1]) << std::endl;
    std::cout << OBFUSCATE("LD_PRELOAD: ") << tuxID::isLDPreload() << std::endl;
    std::cout << OBFUSCATE("Client Tampering: ") << tuxID::isClientTampering() << std::endl;
   return 0;
}
