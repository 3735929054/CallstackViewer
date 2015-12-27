#include <iostream>
#include "DbgUtility.h"
#include <ctime>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << "\\[PROGRAM PATH]" << std::endl;;
        return -1;
    }

    DbgUtility dbg_utility;
    dbg_utility.setTargetFileName(argv[1]);
    dbg_utility.setSingleStep(true);
    std::cout << dbg_utility.GetTargetFileName() << std::endl;
    if (!dbg_utility.doDebuggerProc())
        std::cout << GetLastError() << std::endl;

    return 0;
}