#include "agent.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
#endif

namespace SziMonitor {

    InventoryAgent::InventoryAgent(const std::string& endpointUrl, const std::string& apiToken)
        : m_endpointUrl(endpointUrl), m_apiToken(apiToken) {}

    std::wstring InventoryAgent::Utf8ToWide(const std::string& utf8Str) {
#ifdef _WIN32
        if (utf8Str.empty()) return std::wstring();
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Str.data(), static_cast<int>(utf8Str.size()), nullptr, 0);
        if (sizeNeeded <= 0) return std::wstring();
        std::wstring result(sizeNeeded, 0);
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8Str.data(), static_cast<int>(utf8Str.size()), &result[0], sizeNeeded);
        return result;
#else
        return std::wstring(utf8Str.begin(), utf8Str.end());
#endif
    }

    std::string InventoryAgent::WideToUtf8(const std::wstring& wideStr) {
#ifdef _WIN32
        if (wideStr.empty()) return std::string();
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), static_cast<int>(wideStr.size()), nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) return std::string();
        std::string result(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), static_cast<int>(wideStr.size()), &result[0], sizeNeeded, nullptr, nullptr);
        return result;
#else
        return std::string(wideStr.begin(), wideStr.end());
#endif
    }

    std::string InventoryAgent::EscapeJsonString(const std::string& input) {
        std::ostringstream ss;
        for (char c : input) {
            switch (c) {
                case '\"': ss << "\\\""; break;
                case '\\': ss << "\\\\"; break;
                case '\b': ss << "\\b";  break;
                case '\f': ss << "\\f";  break;
                case '\n': ss << "\\n";  break;
                case '\r': ss << "\\r";  break;
                case '\t': ss << "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
                    } else {
                        ss << c;
                    }
            }
        }
        return ss.str();
    }

    std::string InventoryAgent::GetLocalHostname() const {
#ifdef _WIN32
        wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        DWORD size = _countof(buffer);
        if (GetComputerNameW(buffer, &size) && size > 0) {
            return WideToUtf8(std::wstring(buffer, size));
        }
#endif
        return "UNKNOWN-ENDPOINT";
    }

    std::string InventoryAgent::GetSmbiosUuid() const {
#ifdef _WIN32
        // Query raw SMBIOS firmware table ('RSMB') for persistent motherboard UUID
        DWORD bufSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (bufSize > 8) {
            std::vector<BYTE> buffer(bufSize, 0);
            if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), bufSize) == bufSize) {
                const BYTE* p = buffer.data() + 8;
                const BYTE* end = buffer.data() + bufSize;
                while (p + 4 <= end) {
                    BYTE type = p[0];
                    BYTE length = p[1];
                    if (length < 4 || p + length > end) break;
                    // Type 1 is System Information, UUID is at offset 0x08 (16 bytes)
                    if (type == 1 && length >= 0x18) {
                        const BYTE* u = p + 8;
                        char uuidStr[40] = {0};
                        snprintf(uuidStr, sizeof(uuidStr),
                            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                            u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
                            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                        return std::string(uuidStr);
                    }
                    p += length;
                    while (p + 1 < end && (p[0] != 0 || p[1] != 0)) p++;
                    p += 2;
                }
            }
        }
#endif
        return GetMachineGuid();
    }

    std::string InventoryAgent::GetMachineGuid() const {
#ifdef _WIN32
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {0};
            DWORD bufSize = sizeof(buffer) - 1;
            DWORD valueType = 0;
            LSTATUS status = RegQueryValueExA(hKey, "MachineGuid", nullptr, &valueType, reinterpret_cast<LPBYTE>(buffer), &bufSize);
            RegCloseKey(hKey);
            if (status == ERROR_SUCCESS && (valueType == REG_SZ || valueType == REG_EXPAND_SZ) && bufSize > 1) {
                buffer[bufSize] = '\0';
                return std::string(buffer);
            }
        }
#endif
        return "UNIDENTIFIED-HWID";
    }

    std::string InventoryAgent::GetWindowsVersionString() const {
#ifdef _WIN32
        HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            auto fxPtr = reinterpret_cast<RtlGetVersionPtr>(GetProcAddress(hMod, "RtlGetVersion"));
            if (fxPtr != nullptr) {
                RTL_OSVERSIONINFOW rovi = {0};
                rovi.dwOSVersionInfoSize = sizeof(rovi);
                if (fxPtr(&rovi) == 0) {
                    std::ostringstream os;
                    os << "Windows NT " << rovi.dwMajorVersion << "." << rovi.dwMinorVersion
                       << " (Build " << rovi.dwBuildNumber << ")";
                    return os.str();
                }
            }
        }
#endif
        return "Windows OS";
    }

    uint64_t InventoryAgent::GetTotalMemoryMb() const {
#ifdef _WIN32
        MEMORYSTATUSEX memInfo = {0};
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return static_cast<uint64_t>(memInfo.ullTotalPhys / (1024ULL * 1024ULL));
        }
#endif
        return 0;
    }

    SystemTelemetry InventoryAgent::CollectTelemetry() const {
        SystemTelemetry data{};
        data.hostname     = GetLocalHostname();
        data.hardwareId   = GetSmbiosUuid();
        data.machineGuid  = GetMachineGuid();
        data.osVersion    = GetWindowsVersionString();
        data.totalRamMb   = GetTotalMemoryMb();
        data.agentVersion = "1.2.0";
        return data;
    }

    std::string InventoryAgent::BuildJsonPayload(const SystemTelemetry& data) const {
        std::ostringstream json;
        json << "{\n"
             << "  \"hostname\": \"" << EscapeJsonString(data.hostname) << "\",\n"
             << "  \"hardware_id\": \"" << EscapeJsonString(data.hardwareId) << "\",\n"
             << "  \"machine_guid\": \"" << EscapeJsonString(data.machineGuid) << "\",\n"
             << "  \"os_version\": \"" << EscapeJsonString(data.osVersion) << "\",\n"
             << "  \"total_ram_mb\": " << data.totalRamMb << ",\n"
             << "  \"agent_version\": \"" << EscapeJsonString(data.agentVersion) << "\"\n"
             << "}";
        return json.str();
    }

    bool InventoryAgent::SyncWithServer(const std::string& jsonPayload) const {
#ifdef _WIN32
        std::wstring wideUrl = Utf8ToWide(m_endpointUrl);
        if (wideUrl.empty()) {
            std::cerr << "[ERROR] Endpoint URL UTF-8 conversion failed.\n";
            return false;
        }

        URL_COMPONENTS urlComp = {0};
        urlComp.dwStructSize = sizeof(urlComp);
        wchar_t hostName[256] = {0};
        wchar_t urlPath[1024] = {0};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);

        if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.length()), 0, &urlComp)) {
            std::cerr << "[ERROR] Invalid endpoint URL format (WinHttpCrackUrl error: " << GetLastError() << ").\n";
            return false;
        }

        // Enforce HTTPS only to protect Bearer token in transit
        if (urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
            std::cerr << "[SECURITY] Plaintext HTTP is rejected. Endpoint must use HTTPS.\n";
            return false;
        }

        HINTERNET hSession = WinHttpOpen(L"SziMonitorAgent/1.2", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        // Configure strict timeouts (resolve: 5s, connect: 5s, send: 10s, receive: 10s)
        WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

        HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
        if (!hConnect) {
            std::cerr << "[ERROR] WinHttpConnect failed (code: " << GetLastError() << ").\n";
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Disable automatic redirects to prevent Bearer token leakage to untrusted origins
        DWORD disableRedirects = WINHTTP_DISABLE_REDIRECTS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirects, sizeof(disableRedirects));

        std::wstring wideToken = Utf8ToWide(m_apiToken);
        std::wstring headers = L"Authorization: Bearer " + wideToken + L"\r\nContent-Type: application/json; charset=utf-8\r\n";

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            static_cast<DWORD>(-1L),
            const_cast<char*>(jsonPayload.c_str()),
            static_cast<DWORD>(jsonPayload.size()),
            static_cast<DWORD>(jsonPayload.size()),
            0
        );

        if (!bResults) {
            std::cerr << "[ERROR] WinHttpSendRequest failed (network/TLS error code: " << GetLastError() << ").\n";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        if (WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
        } else {
            std::cerr << "[ERROR] WinHttpReceiveResponse failed (code: " << GetLastError() << ").\n";
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (statusCode >= 200 && statusCode < 300) {
            return true;
        }

        std::cerr << "[ERROR] Server rejected synchronization with HTTP status: " << statusCode << "\n";
        return false;
#else
        return false;
#endif
    }

} // namespace SziMonitor

int main(int argc, char* argv[]) {
    const char* envEndpoint = std::getenv("SZI_API_URL");
    const char* envToken    = std::getenv("SZI_API_TOKEN");

    if (!envEndpoint || !envToken) {
        std::cerr << "[ERROR] Environment variables SZI_API_URL and SZI_API_TOKEN must be configured.\n";
        return 1;
    }

    SziMonitor::InventoryAgent agent(envEndpoint, envToken);
    auto telemetry = agent.CollectTelemetry();
    std::string payload = agent.BuildJsonPayload(telemetry);

    if (agent.SyncWithServer(payload)) {
        std::cout << "[OK] Endpoint telemetry synchronized successfully.\n";
        return 0;
    }

    return 2;
}
