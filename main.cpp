#include <iostream>
#include "DbgUtility.h"
#include "PEparser.h"
#include <ctime>

class test : public DbgUtility
{
public:
    test()
    {
        fopen_s(&m_out, "eipRecord.txt", "w");
    }

    ~test()
    {
        fclose(m_out);
    }

    void onExcuteOnceInstruction(DEBUG_EVENT& _event)
    {
        BYTE arrInstruction[6] = { NULL, };
        char buf[256];
        DWORD dwMemAddr;
        DWORD dwFuncAddr;

        ReadProcessMemory(processInformation.hProcess, (LPVOID)context.Eip, arrInstruction, 6, NULL);
        memcpy_s(&dwMemAddr, sizeof(dwMemAddr), &arrInstruction[1], 4);
        ReadProcessMemory(processInformation.hProcess, (LPVOID)dwMemAddr, &dwFuncAddr, 4, NULL);
        sprintf_s(buf, sizeof(buf), "[%p] %s:%p\n", context.Eip, peParser.getProcNameWidthAddr(dwFuncAddr).c_str(), dwFuncAddr);

        fputs(buf, m_out);
    }

private:
    FILE *m_out;
};

int main(int argc, char *argv[])
{
    //if (argc < 2)
    //{
    //    std::cout << "Usage: " << argv[0] << "\\[PROGRAM PATH]" << std::endl;;
    //    return -1;
    //}

    test dbg_utility;
    dbg_utility.setFilePath(argv[1]);
    dbg_utility.setTrapFlag(true);
    std::cout << dbg_utility.GetTargetFileName() << std::endl;
    if (!dbg_utility.start())
        std::cout << GetLastError() << std::endl;

    return 0;
}