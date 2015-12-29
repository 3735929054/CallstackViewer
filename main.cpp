#include <iostream>
#include "DbgUtility.h"
#include "PEparser.h"
#include <ctime>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << "\\[PROGRAM PATH]" << std::endl;;
        return -1;
    }

    PEparser parser;
    parser.setFilePath(argv[1]);
    parser.parse();
    std::list<iatInformation> list = parser.getIatInformationList();

    auto iter = list.begin();
    while (iter != list.end())
    {
        DbgUtility::dbgPrint("[%p] %s", iter->dwAddress, iter->szFuncName.c_str());
        iter++;
    }

    DbgUtility dbg_utility;
    dbg_utility.setTargetFileName(argv[1]);
    dbg_utility.setSingleStep(true);
    std::cout << dbg_utility.GetTargetFileName() << std::endl;
    if (!dbg_utility.doDebuggerProc())
        std::cout << GetLastError() << std::endl;

    return 0;
}