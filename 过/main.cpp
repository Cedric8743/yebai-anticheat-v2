/*
 * 夜白过检测 1.0 + 微验卡密验证
 * Compile: x86_64-w64-mingw32-g++ -mwindows -municode -static -o YebaiAntiCheat.exe main.cpp -lwininet -ladvapi32 -lcomctl32 -lshell32 -lwinhttp -lcomdlg32
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <process.h>
#include <shellapi.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <random>
#include <chrono>
#include <iomanip>
#include <shlobj.h>
#include <objbase.h>
#include "res/json.hpp"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comdlg32.lib")

using namespace std;
using json = nlohmann::json;

// ====== 微验配置 ======
const string WY_APPID = "61572";
const string WY_APPKEY = "g11eaea18d487e7b40ab6a53926";
const int WY_SUCCESS_CODE = 91309;
const string WY_HOST = "wy.llua.cn";

// ====== 配置 ======
#define WIN_WIDTH      420
#define WIN_HEIGHT     355
#define ACE_FOLDER     L"C:\\Program Files\\AntiCheatExpert"
#define GAME_PROC      L"NRC-Win64-Shipping.exe"

// ====== 全局 ======
static HWND g_hStatus = NULL;
static HWND g_hBtnStart = NULL;
static HWND g_hBtnExit = NULL;
static HWND g_hMainWnd = NULL;
static volatile LONG g_Running = 0;
static HANDLE g_hMonThread = NULL;
static WCHAR g_szLog[8192] = {0};
static CRITICAL_SECTION g_csLog;

// ====== 机器码生成 ========
static string GetWeiyanDataPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path))) {
        string fullPath = string(path) + "\\Weiyan";
        CreateDirectoryA(fullPath.c_str(), NULL);
        return fullPath + "\\.imei";
    }
    return "C:\\ProgramData\\Weiyan\\.imei";
}

static string generateUUID() {
    UUID uuid;
    CoCreateGuid(&uuid);
    char buf[64];
    sprintf(buf, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid.Data1, uuid.Data2, uuid.Data3,
        uuid.Data4[0], uuid.Data4[1], uuid.Data4[2], uuid.Data4[3],
        uuid.Data4[4], uuid.Data4[5], uuid.Data4[6], uuid.Data4[7]);
    return string(buf);
}

static string readIMEIFromFile(const string& path) {
    ifstream file(path);
    if (file.is_open()) {
        string imei;
        getline(file, imei);
        file.close();
        return imei;
    }
    return "";
}

static void saveIMEIToFile(const string& path, const string& imei) {
    ofstream file(path);
    if (file.is_open()) {
        file << imei << endl;
        file.close();
    }
}

static string getIMEI() {
    string path = GetWeiyanDataPath();
    string imei = readIMEIFromFile(path);
    if (imei.empty()) {
        imei = generateUUID();
        saveIMEIToFile(path, imei);
    }
    return imei;
}

// ====== MD5 ======
typedef struct {
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];
} MD5_CTX;

static void MD5Init(MD5_CTX* context) {
    context->count[0] = 0; context->count[1] = 0;
    context->state[0] = 0x67452301; context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE; context->state[3] = 0x10325476;
}

static void MD5Encode(unsigned char* output, unsigned int* input, unsigned int len);
static void MD5Update(MD5_CTX* context, unsigned char* input, unsigned int inputlen) {
    unsigned int i = 0, index = 0, partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;
    if (context->count[0] < (inputlen << 3)) context->count[1]++;
    context->count[1] += inputlen >> 29;
    if (inputlen >= partlen) {
        memcpy(&context->buffer[index], input, partlen);
        for (i = partlen; i + 64 <= inputlen; i += 64);
        index = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputlen - i);
}

static void MD5Final(MD5_CTX* context, unsigned char digest[16]) {
    unsigned int index = (context->count[0] >> 3) & 0x3F;
    unsigned int padlen = (index < 56) ? (56 - index) : (120 - index);
    unsigned char bits[8];
    bits[0] = 0x80;
    MD5Update(context, bits, 1);
    if (padlen > 1) {
        bits[0] = 0;
        MD5Update(context, bits, padlen - 1);
    }
    MD5Update(context, (unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    MD5Encode(context->buffer, (unsigned int*)digest, 16);
}

static void MD5Encode(unsigned char* output, unsigned int* input, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xFF;
        output[j + 1] = (input[i] >> 8) & 0xFF;
        output[j + 2] = (input[i] >> 16) & 0xFF;
        output[j + 3] = (input[i] >> 24) & 0xFF;
    }
}

static string getMd5(const string& inputStr) {
    static char _SignMd5[33];
    unsigned char _Decrypt[16];
    MD5_CTX md5c;
    MD5Init(&md5c);
    MD5Update(&md5c, (unsigned char*)inputStr.c_str(), (unsigned int)inputStr.length());
    MD5Final(&md5c, _Decrypt);
    for (int i = 0; i < 16; i++)
        sprintf(&_SignMd5[i * 2], "%02x", _Decrypt[i]);
    return string(_SignMd5);
}

// ====== HTTP POST (WinHTTP) ======
static string httppost(const string& hostname, const string& url, const string& cs) {
    string result;
    HINTERNET session = WinHttpOpen(L"WeiyanClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return "WinHttpOpen failed";

    wstring wHost(hostname.begin(), hostname.end());
    HINTERNET connect = WinHttpConnect(session, wHost.c_str(), 80, 0);
    if (!connect) { WinHttpCloseHandle(session); return "WinHttpConnect failed"; }

    wstring wUrl(url.begin(), url.end());
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", wUrl.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!request) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return "WinHttpOpenRequest failed"; }

    wstring wCs(cs.begin(), cs.end());
    BOOL success = WinHttpSendRequest(request,
        L"Content-Type: application/x-www-form-urlencoded\r\n", (DWORD)-1,
        (LPVOID)wCs.c_str(), (DWORD)wCs.length(), (DWORD)wCs.length(), 0);
    if (!success) { WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return "WinHttpSendRequest failed"; }

    success = WinHttpReceiveResponse(request, NULL);
    if (!success) { WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return "WinHttpReceiveResponse failed"; }

    string responseBody;
    DWORD dwSize = 0, dwDownloaded = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(request, &dwSize)) break;
        if (!dwSize) break;
        vector<char> buffer(dwSize + 1);
        if (!WinHttpReadData(request, &buffer[0], dwSize, &dwDownloaded)) break;
        buffer[dwSize] = 0;
        responseBody.append(&buffer[0], dwSize);
    } while (dwSize > 0);

    size_t bodyStart = responseBody.find("\r\n\r\n");
    result = (bodyStart != string::npos) ? responseBody.substr(bodyStart + 4) : responseBody;

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return result.empty() ? "No response" : result;
}

// ====== 微验卡密验证 ======
static bool VerifyLicense(const string& kami) {
    cout << ">>>正在验证卡密..." << endl;

    string _Imei = getIMEI();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(100000, 999999);
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();

    string _Time = std::to_string(timestamp);
    string _Value = std::to_string(dist(gen));

    string postData = "app=" + WY_APPID +
        "&kami=" + kami +
        "&markcode=" + _Imei +
        "&t=" + _Time +
        "&value=" + _Value;

    string response = httppost(WY_HOST, "api/?id=kmlogon", postData);
    cout << "响应: " << response << endl;

    try {
        json j = json::parse(response);
        if (j["code"] == WY_SUCCESS_CODE) {
            cout << "验证成功!" << endl;
            return true;
        } else {
            cout << "验证失败: " << j["msg"].get<string>() << endl;
            return false;
        }
    } catch (...) {
        cout << "解析响应失败" << endl;
        return false;
    }
}

// ====== UI 日志 ======
static void AddLog(const WCHAR* fmt, ...) {
    WCHAR buf[512];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 512, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_csLog);
    int l = (int)wcslen(g_szLog);
    if (l > 6000) memmove(g_szLog, g_szLog + 2000, sizeof(WCHAR) * 6000);
    wcscat(g_szLog, buf);
    wcscat(g_szLog, L"\r\n");
    if (g_hStatus) {
        SetWindowTextW(g_hStatus, g_szLog);
        SendMessageW(g_hStatus, EM_SETSEL, -1, -1);
        SendMessageW(g_hStatus, EM_SCROLLCARET, 0, 0);
    }
    LeaveCriticalSection(&g_csLog);
}
static void ClsLog() {
    EnterCriticalSection(&g_csLog);
    g_szLog[0] = 0;
    if (g_hStatus) SetWindowTextW(g_hStatus, L"");
    LeaveCriticalSection(&g_csLog);
}

// ====== 进程检测 ======
static int IsRunning(const WCHAR* n) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    int f = 0;
    while (ok) {
        if (wcsicmp(pe.szExeFile, n) == 0) { f = 1; break; }
        ok = Process32Next(h, &pe);
    }
    CloseHandle(h);
    return f;
}

// ====== 杀游戏进程 ======
static void KillGame() {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {sizeof(PROCESSENTRY32W)};
    BOOL ok = Process32FirstW(h, &pe);
    while (ok) {
        if (wcsicmp(pe.szExeFile, GAME_PROC) == 0) {
            HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            break;
        }
        ok = Process32Next(h, &pe);
    }
    CloseHandle(h);
}

// ====== 执行命令行并等待 ======
static int RunCmd(WCHAR* cmd, int waitMs) {
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, waitMs);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

// ====== 删除文件夹（带重试）======
static int DelFolder() {
    WCHAR cmd[1024];
    int retry;
    for (retry = 0; retry < 3; retry++) {
        if (retry > 0) Sleep(2000);
        wsprintfW(cmd, L"takeown /F \"C:\\Program Files\\AntiCheatExpert\\*\" /R /D Y 2>nul");
        RunCmd(cmd, 8000);
        wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /grant Users:F /C 2>nul");
        RunCmd(cmd, 8000);
        wsprintfW(cmd, L"cmd /c rmdir /S /Q \"C:\\Program Files\\AntiCheatExpert\" 2>nul");
        RunCmd(cmd, 8000);
        if (GetFileAttributesW(ACE_FOLDER) == INVALID_FILE_ATTRIBUTES) return 0;
    }
    return -1;
}

// ====== 锁住文件夹权限 =======
static int LockFolder() {
    WCHAR cmd[1024];
    AddLog(L"[Lock] step1: grant admin...");
    wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /grant:r Administrators:(F)");
    RunCmd(cmd, 10000);
    AddLog(L"[Lock] step2: deny all...");
    wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /inheritance:r /deny Everyone:(F)");
    RunCmd(cmd, 10000);
    AddLog(L"[Lock] done");
    return 0;
}

// ====== 解锁文件夹权限 =======
static int UnlockFolder() {
    WCHAR cmd[1024];
    wsprintfW(cmd, L"takeown /F \"C:\\Program Files\\AntiCheatExpert\" /R /D Y 2>nul");
    RunCmd(cmd, 10000);
    wsprintfW(cmd, L"icacls \"C:\\Program Files\\AntiCheatExpert\" /T /reset /C 2>nul");
    RunCmd(cmd, 10000);
    return 0;
}

// ====== 监控线程 ======
static unsigned __stdcall MonThrd(void* a) {
    (void)a;
    AddLog(L"【1/4】正在清理残留...");
    DelFolder();
    AddLog(L"【1/4】清理完成");
    AddLog(L"【2/4】等待游戏启动...");

    DWORD st = GetTickCount();
    while (g_Running) {
        if (IsRunning(GAME_PROC)) { AddLog(L"【2/4】检测到游戏进程!"); break; }
        if (GetTickCount() - st > 600000) {
            AddLog(L"【2/4】等待超时");
            InterlockedExchange(&g_Running, 0);
            if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
            _endthreadex(0); return 0;
        }
        Sleep(500);
    }
    if (!g_Running) { AddLog(L"【2/4】用户取消"); _endthreadex(0); return 0; }

    AddLog(L"【3/4】过检测执行中...");
    Sleep(5000);

    LockFolder();
    AddLog(L"【3/4】过检测执行成功!");

    AddLog(L"【4/4】监控中...");
    while (g_Running) {
        if (!IsRunning(GAME_PROC)) {
            Sleep(1500);
            if (!IsRunning(GAME_PROC)) {
                AddLog(L"【4/4】游戏已退出!");
                break;
            }
            AddLog(L"【4/4】游戏恢复，继续监控...");
        }
        Sleep(1000);
    }

    if (g_Running) {
        AddLog(L"正在清理...");
        UnlockFolder();
        DelFolder();
        KillGame();
    }

    AddLog(L"=== 完成 ===");
    InterlockedExchange(&g_Running, 0);
    if (g_hBtnStart) { EnableWindow(g_hBtnStart, 1); SetWindowTextW(g_hBtnStart, L"开始过检测"); }
    Sleep(800);
    if (g_hMainWnd) PostMessageW(g_hMainWnd, WM_CLOSE, 0, 0);
    _endthreadex(0);
    return 0;
}

static void StartMon() {
    if (g_hMonThread) { CloseHandle(g_hMonThread); g_hMonThread = NULL; }
    InterlockedExchange(&g_Running, 1);
    ClsLog();
    AddLog(L"=== 夜白过检测 ===");
    AddLog(L"请启动游戏...");
    unsigned tid = 0;
    g_hMonThread = (HANDLE)_beginthreadex(NULL, 0, MonThrd, NULL, 0, &tid);
    if (!g_hMonThread) { AddLog(L"[!] 线程启动失败"); InterlockedExchange(&g_Running, 0); }
}

static void StopMon() {
    if (g_Running) {
        InterlockedExchange(&g_Running, 0);
    }
}

// ====== 清理线程 ======
static unsigned __stdcall CleanupThrd(void* a) {
    (void)a;
    Sleep(300);
    UnlockFolder();
    DelFolder();
    KillGame();
    Sleep(300);
    PostQuitMessage(0);
    return 0;
}

// ====== 主窗口 ======
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HFONT hFTitle = 0, hFNorm = 0;
    if (msg == WM_CREATE) {
        hFTitle = CreateFontW(22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        hFNorm = CreateFontW(13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        CreateWindowW(L"static", L"夜白过检测 1.0",
            WS_CHILD | WS_VISIBLE | SS_CENTER, 60, 8, 300, 35, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"static", L"Log:",
            WS_CHILD | WS_VISIBLE, 15, 50, 40, 20, hwnd, NULL, NULL, NULL);
        g_hStatus = CreateWindowW(L"edit", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            15, 72, WIN_WIDTH - 30, WIN_HEIGHT - 160, hwnd, (HMENU)10, NULL, NULL);
        g_hBtnStart = CreateWindowW(L"button", L"开始过检测",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 30, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)20, NULL, NULL);
        g_hBtnExit = CreateWindowW(L"button", L"退出程序",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, WIN_WIDTH - 180, WIN_HEIGHT - 75, 150, 35, hwnd, (HMENU)21, NULL, NULL);
        SendMessageW(GetDlgItem(hwnd, 10), WM_SETFONT, (WPARAM)hFTitle, TRUE);
        SendMessageW(GetDlgItem(hwnd, 11), WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnStart, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageW(g_hBtnExit, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        AddLog(L"=== 夜白过检测 1.0 ===");
        AddLog(L"点击【开始过检测】按钮");
        AddLog(L"然后启动游戏即可");
        return 0;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == 20) {
            if (!g_Running) {
                StartMon();
                SetWindowTextW(g_hBtnStart, L"停止过检测");
            } else {
                StopMon();
                SetWindowTextW(g_hBtnStart, L"开始过检测");
                CloseHandle((HANDLE)_beginthreadex(NULL, 0, CleanupThrd, NULL, 0, NULL));
            }
        }
        if (LOWORD(wp) == 21) {
            StopMon();
            CloseHandle((HANDLE)_beginthreadex(NULL, 0, CleanupThrd, NULL, 0, NULL));
        }
    }
    if (msg == WM_CLOSE) {
        AddLog(L"正在清理...");
        UnlockFolder();
        DelFolder();
        KillGame();
        if (g_Running) StopMon();
        Sleep(200);
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ====== 权限 ======
static int IsAdmin() {
    HANDLE hToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return 0;
    TOKEN_GROUPS* tg = (TOKEN_GROUPS*)malloc(1024);
    DWORD sz = 1024;
    int isAdm = 0;
    if (GetTokenInformation(hToken, TokenGroups, tg, 1024, &sz)) {
        for (DWORD i = 0; i < tg->GroupCount; i++) {
            if (!tg->Groups[i].Sid) continue;
            SID_NAME_USE snu;
            WCHAR name[256] = {0}, dom[256] = {0};
            DWORD nsz = 256, dsz = 256;
            if (LookupAccountSidW(NULL, tg->Groups[i].Sid, name, &nsz, dom, &dsz, &snu)) {
                if (wcscmp(name, L"Administrators") == 0 || wcscmp(name, L"Admin") == 0) { isAdm = 1; break; }
            }
        }
    }
    free(tg);
    CloseHandle(hToken);
    return isAdm;
}

static int RequestElevation() {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {sizeof(sei), SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI};
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei);
}

// ====== 全局变量用于卡密验证 ==========
static int g_LicenseResult = 0;  // 0=未验证, 1=成功, 2=失败
static HWND g_hLicenseEdit = NULL;

// ====== 卡密对话框窗口过程 ======
static LRESULT CALLBACK LicenseDialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
    {
        HINSTANCE hInst = ((CREATESTRUCT*)lp)->hInstance;
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        CreateWindowW(L"static", L"请输入卡密：",
            WS_CHILD | WS_VISIBLE, 20, 20, 200, 25, hwnd, NULL, hInst, NULL);
        g_hLicenseEdit = CreateWindowW(L"edit", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            20, 50, 260, 28, hwnd, (HMENU)100, hInst, NULL);
        CreateWindowW(L"button", L"验证",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            60, 90, 80, 32, hwnd, (HMENU)1, hInst, NULL);
        CreateWindowW(L"button", L"取消",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            160, 90, 80, 32, hwnd, (HMENU)2, hInst, NULL);
        SendMessageW(g_hLicenseEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetFocus(g_hLicenseEdit);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == 1) {  // 验证按钮
            char buf[256] = {0};
            GetWindowTextA(g_hLicenseEdit, buf, 256);
            string kami = buf;
            if (!kami.empty()) {
                if (VerifyLicense(kami)) {
                    g_LicenseResult = 1;
                    DestroyWindow(hwnd);
                } else {
                    MessageBoxA(hwnd, "卡密验证失败，请检查卡密是否正确！", "验证失败", MB_ICONERROR);
                }
            } else {
                MessageBoxA(hwnd, "请输入卡密！", "提示", MB_ICONWARNING);
            }
            return TRUE;
        }
        if (LOWORD(wp) == 2) {  // 取消按钮
            g_LicenseResult = 2;
            DestroyWindow(hwnd);
            return TRUE;
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ====== WinMain ======
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hp, LPWSTR cl, int ns) {
    (void)hp; (void)cl; (void)ns;

    // ========== 注册卡密对话框窗口类 ==========
    WNDCLASSEXW lc = {0};
    lc.cbSize = sizeof(WNDCLASSEXW);
    lc.lpfnWndProc = LicenseDialogProc;
    lc.hInstance = hInst;
    lc.hCursor = LoadCursor(NULL, IDC_ARROW);
    lc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    lc.lpszClassName = L"LicenseDialogClass";
    RegisterClassExW(&lc);

    // ========== 创建卡密对话框窗口 ==========
    HWND hLicenseDlg = CreateWindowExW(
        0, L"LicenseDialogClass", L"卡密验证",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (GetSystemMetrics(SM_CXSCREEN) - 320) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - 160) / 2,
        320, 160, NULL, NULL, hInst, NULL);

    ShowWindow(hLicenseDlg, SW_SHOW);
    UpdateWindow(hLicenseDlg);

    // ========== 卡密验证消息循环 ==========
    MSG m;
    while (g_LicenseResult == 0 && GetMessage(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessage(&m);
    }

    // ========== 验证结果处理 ==========
    if (g_LicenseResult != 1) {
        // 验证失败或取消，退出程序
        return 0;
    }

    InitializeCriticalSection(&g_csLog);

    // ========== 请求管理员权限 ==========
    if (!IsAdmin()) {
        if (RequestElevation()) return 0;
    }

    WNDCLASSEXW mwc = {0};
    mwc.cbSize = sizeof(WNDCLASSEXW);
    mwc.style = CS_HREDRAW | CS_VREDRAW;
    mwc.lpfnWndProc = MainProc;
    mwc.hInstance = hInst;
    mwc.hCursor = LoadCursor(NULL, IDC_ARROW);
    mwc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    mwc.lpszClassName = L"YeBaiMain";
    if (!RegisterClassExW(&mwc)) { MessageBoxW(NULL, L"注册失败", L"错误", MB_OK); return 1; }

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hMain = CreateWindowExW(0, L"YeBaiMain", L"夜白过检测 1.0",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        (sw - WIN_WIDTH) / 2, (sh - WIN_HEIGHT) / 2,
        WIN_WIDTH, WIN_HEIGHT, NULL, NULL, hInst, NULL);
    if (!hMain) { MessageBoxW(NULL, L"创建窗口失败", L"错误", MB_OK); return 1; }
    g_hMainWnd = hMain;
    ShowWindow(hMain, SW_SHOW);
    UpdateWindow(hMain);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    DeleteCriticalSection(&g_csLog);
    return 0;
}
