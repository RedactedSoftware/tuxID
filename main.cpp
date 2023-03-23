#include "hardwareID.hpp"

int main()
{
      fprintf(stdout,"\n");
      fprintf(stdout,diskSerial());
      if(!isVirtualMachine()) {
          fprintf(stdout,"\nNot a VM.");
      } else {
          fprintf(stdout,"\nVirtual Machine.");
      }
   return 0;
}