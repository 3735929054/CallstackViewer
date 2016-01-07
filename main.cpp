#include <iostream>
#include "DbgUtility.h"
#include "PEparser.h"
#include <ctime>
#include <list>

class CallFlowRecorder : public DbgUtility
{
public:
    CallFlowRecorder()
    {
        fopen_s(&m_out, "eipRecord.txt", "w");
        m_width = -1;
        m_called = false;
    }

    ~CallFlowRecorder()
    {
        fclose(m_out);
    }

    void onExcuteOnceInstruction(DEBUG_EVENT& _event) override
    {
        BYTE opcode[6] = { 0, };
        ReadProcessMemory(dbgProcInfo.hProcess, (LPVOID)dbgContext.Eip, (LPVOID)opcode, 6, NULL);

        if (m_called)
        {
            ReadProcessMemory(dbgProcInfo.hProcess, (LPVOID)dbgContext.Esp, (LPVOID)&m_callList.back()->dwRetAddr, sizeof(DWORD), NULL);
            m_called = false;
        }

        DWORD dwCallAddr = 0;
        switch (opcode[0])
        {
        case 0xe8:
            dwCallAddr = *(DWORD*)&opcode[1];
            m_called = true;
            m_width++;
            break;
        case 0xff:
            switch (opcode[1])
            {
            case 0x15: // call ds
                dwCallAddr = *(DWORD*)&opcode[2];
                m_called = true;
                m_width++;
                break;

            //-- call [REG]
            case 0xd0: //-- call eax
                dwCallAddr = dbgContext.Eax;
                m_called = true;
                m_width++;
                break;
            case 0xd1: //-- call ecx
                dwCallAddr = dbgContext.Ecx;
                m_called = true;
                m_width++;
                break;
            case 0xd2: //-- call edx
                dwCallAddr = dbgContext.Edx;
                m_called = true;
                m_width++;
                break;
            case 0xd3: //-- call ebx
                dwCallAddr = dbgContext.Ebx;
                m_called = true;
                m_width++;
                break;
            case 0xd4: //-- call esp
                dwCallAddr = dbgContext.Esp;
                m_called = true;
                m_width++;
                break;
            case 0xd5: //-- call ebp
                dwCallAddr = dbgContext.Ebp;
                m_called = true;
                m_width++;
                break;
            case 0xd6: //-- call esi
                dwCallAddr = dbgContext.Esi;
                m_called = true;
                m_width++;
                break;
            case 0xd7: //-- call edi
                dwCallAddr = dbgContext.Edi;
                m_called = true;
                m_width++;
                break;
            case 0x55: //-- call stack segment
                m_called = true;
                m_width++;
                break;
            default:
                break;
            }
            break;

        // RETN
        case 0xc3:
        case 0xc2:
        case 0xf2:
            m_width--;
            break;
        default:
            break;
        }

        if (m_called)
        {
            ci *tmp = new ci;
            tmp->dwCallAddr = dwCallAddr;
            tmp->dwCurAddr = dbgContext.Eip;
            tmp->nLoopCount = 1;
            tmp->dwRetAddr = NULL;
            tmp->w = m_width;

            m_callList.push_back(tmp);
        }
    }

    void onExitProcess(DEBUG_EVENT& _event) override
    {
        auto iter = m_callList.begin();
        while (iter != m_callList.end())
        {
            ci *tmp = *iter;
            int w = tmp->w * 2;
            char buf[256];

            for (int i = 0; i < w; ++i)
                fputs("\t", m_out);
            sprintf_s(buf, 256, "+R--0x%08x---+\n", tmp->dwRetAddr);
            fputs(buf, m_out);

            for (int i = 0; i < w; ++i)
                fputs("\t", m_out);
            sprintf_s(buf, 256, "|    [%06d]    |\n", tmp->nLoopCount);
            fputs(buf, m_out);

            for (int i = 0; i < w; ++i)
                fputs("\t", m_out);
            sprintf_s(buf, 256, "+C--0x%08x---+\n", tmp->dwCallAddr);
            fputs(buf, m_out);

            iter++;
        }
    }

private:
    typedef struct _CALL_INFO_
    {
        DWORD dwCurAddr;
        DWORD dwCallAddr;
        DWORD dwRetAddr;
        int nLoopCount;
        int w;
    } ci;

    FILE *m_out;
    unsigned int m_width;
    bool m_called;

    std::list<_CALL_INFO_*> m_callList;
};

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << "\\[PROGRAM PATH]" << std::endl;;
        return -1;
    }

    CallFlowRecorder dbg_utility;
    dbg_utility.setFilePath(argv[1]);
    dbg_utility.setTrapFlag(true);
    std::cout << dbg_utility.GetTargetFileName() << std::endl;
    if (!dbg_utility.start())
        std::cout << GetLastError() << std::endl;

    return 0;
}