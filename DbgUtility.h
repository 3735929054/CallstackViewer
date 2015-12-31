#pragma once

#include <Windows.h>
#include <functional>
#include <string>
#include <list>
#include "PEparser.h"

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
    virtual void onExcuteOnceInstruction(DEBUG_EVENT& _event);
    virtual void onCreateProcess(DEBUG_EVENT& _event);
    virtual void onExitProcess(DEBUG_EVENT& _event);

    DbgUtility(std::string process_name = "");
    ~DbgUtility();

    bool start();
    void stop();
    void resume();

    std::string GetTargetFileName();
    HANDLE GetWindowsHandle();
    void setFilePath(const char *file_name);
    void setFilePath(std::string& file_name);
    void setTrapFlag(bool _enable);
    CONTEXT getCurrentDebuggeeContext();
    PROCESS_INFORMATION getDebuggeeProcInfo();

    static void dbgPrint(const char *format, ...);
    static void dbgPrint(const wchar_t *format, ...);
    static DWORD getProcessIdFromeName(std::string& process_name);
    static HANDLE getWindowsHandleFromeName(std::string& process_name);
    static bool checkRemoteDbgPresent(HANDLE hProc);
    static std::string getFileNameFromeHandle(HANDLE hFile);

private:
    std::string m_filePath;
    STARTUPINFO m_startInfo;
    std::list<loadDllInfo> loadDllList;
    std::list<originalOpInfo> replacedOpcodeList;

    bool m_trapFlag;
    bool m_stop;
    bool m_resume;
    
    LPVOID m_oep;
    HANDLE m_module;
    BYTE m_breakPoint, m_INT3;

protected:
    CONTEXT context;
    PROCESS_INFORMATION processInformation;
    PEparser peParser;
};