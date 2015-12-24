#pragma once

#include <Windows.h>
#include <functional>
#include <string>
#include <list>

// 로드된 dll의 정보(이름, 주소)를 저장할 구조체
typedef struct LOAD_DLL_INFO
{
    char *pName;
    LPVOID lpBaseAddr;
} loadDllInfo;

typedef struct ORIGINAL_INSTRUCTION_INFO
{
    BYTE chOpcode;
    DWORD dwAddress;
} originalOpInfo;

// i386 opcode
enum OPCODE_SET
{
    CALL_1 = 0xE8,
    CALL_2 = 0xFF15
};

class DbgUtility
{
public:
    // *NON-STATIC
        // variable
    std::function<void()> onBreakpoint, onCreateProcess, onExitProcess;

        // functions
    DbgUtility(std::string process_name = "");
    ~DbgUtility();
    bool doDebuggerProc();
    std::string GetTargetFileName();
    HANDLE GetWindowsHandle();
    void setTargetFileName(const char *file_name);
    void setTargetFileName(std::string& file_name);
    UINT setBreakpoints();

    // *STATIC
        // variables
    
        // functions
    static void dbgPrint(const char *format, ...);
    static void dbgPrint(const wchar_t *format, ...);
    static DWORD getProcessIdFromeName(std::string& process_name);
    static HANDLE getWindowsHandleFromeName(std::string& process_name);
    static bool checkRemoteDbgPresent(HANDLE hProc);
    static std::string getFileNameFromeHandle(HANDLE hFile);

private:
    std::string m_targetFileName;
    PROCESS_INFORMATION m_procInfo;
    STARTUPINFO m_startInfo;
    std::list<loadDllInfo> loadDllList;
    std::list<originalOpInfo> replacedOpcodeList;
};