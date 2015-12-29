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
        if (0xe8 == arrInstruction[0])
        {
            memcpy_s(&dwMemAddr, sizeof(dwMemAddr), &arrInstruction[1], 4);
            ReadProcessMemory(processInformation.hProcess, (LPVOID)dwMemAddr, &dwFuncAddr, 4, NULL);
            sprintf_s(buf, sizeof(buf), "[%p] %s:%p\n", context.Eip, peParser.getProcNameWidthAddr(dwFuncAddr).c_str(), dwFuncAddr);
        }
        else if (!memcmp(arrInstruction, "\xff\x15", 2))
        {
            memcpy_s(&dwMemAddr, sizeof(dwMemAddr), &arrInstruction[2], 4);
            ReadProcessMemory(processInformation.hProcess, (LPVOID)dwMemAddr, &dwFuncAddr, 4, NULL);
            sprintf_s(buf, sizeof(buf), "[%p] %s:%p\n", context.Eip, peParser.getProcNameWidthAddr(dwFuncAddr).c_str(), dwFuncAddr);
        }
        else if (!memcmp(arrInstruction, "\xff\x25", 2))
        {
            memcpy_s(&dwMemAddr, sizeof(dwMemAddr), &arrInstruction[2], 4);
            ReadProcessMemory(processInformation.hProcess, (LPVOID)dwMemAddr, &dwFuncAddr, 4, NULL);
            sprintf_s(buf, sizeof(buf), "[%p] %s:%p\n", context.Eip, peParser.getProcNameWidthAddr(dwFuncAddr).c_str(), dwFuncAddr);
        }
        else {
            return;
        }

        if (!strstr(buf, "(unknown)")) fputs(buf, m_out);
    }

private:
    FILE *m_out;
};

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << "\\[PROGRAM PATH]" << std::endl;;
        return -1;
    }

    test dbg_utility;
    dbg_utility.setFilePath(argv[1]);
    dbg_utility.setSingleStep(true);
    std::cout << dbg_utility.GetTargetFileName() << std::endl;
    if (!dbg_utility.doDebuggerProc())
        std::cout << GetLastError() << std::endl;

    return 0;
}