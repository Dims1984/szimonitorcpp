#include "agent.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
#endif

namespace SziMonitor {

    InventoryAgent::InventoryAgent(const std::string& endpointUrl, const std::string& apiToken)
        : m_endpointUrl(endpointUrl), m_apiToken(apiToken) {}

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
                        ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                    } else {
                        ss << c;
                    }
            }
        }
        return ss.str();
    }

    std::string InventoryAgent::GetLocalHostname() const {
#ifdef _WIN32
        char buffer[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        DWORD size = sizeof(buffer);
        if (GetComputerNameA(buffer, &size)) {
            return std::string(buffer, size);
        }
#endif
        return "UNKNOWN-ENDPOINT";
    }

    std::string InventoryAgent::GetHardwareIdentifier() const {
#ifdef _WIN32
        HKEY hKey;
        // Read persistent hardware/BIOS SystemProductName or MachineGuid from registry
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {0};
            DWORD bufSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "ComputerHardwareId", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &bufSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(buffer);
            }
            RegCloseKey(hKey);
        }

        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            char buffer[256] = {0};
            DWORD bufSize = sizeof(buffer);
            if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(buffer), &bufSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(buffer);
            }
            RegCloseKey(hKey);
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
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            return static_cast<uint64_t>(memInfo.ullTotalPhys / (1024 * 1024));
        }
#endif
        return 0;
    }

    SystemTelemetry InventoryAgent::CollectTelemetry() const {
        SystemTelemetry data;
        data.hostname     = GetLocalHostname();
        data.serialNumber = GetHardwareIdentifier();
        data.osVersion    = GetWindowsVersionString();
        data.totalRamMb   = GetTotalMemoryMb();
        data.agentVersion = "1.1.0";
        return data;
    }

    std::string InventoryAgent::BuildJsonPayload(const SystemTelemetry& data) const {
        std::ostringstream json;
        json << "{\n"
             << "  \"hostname\": \"" << EscapeJsonString(data.hostname) << "\",\n"
             << "  \"serial_number\": \"" << EscapeJsonString(data.serialNumber) << "\",\n"
             << "  \"os_version\": \"" << EscapeJsonString(data.osVersion) << "\",\n"
             << "  \"total_ram_mb\": " << data.totalRamMb << ",\n"
             << "  \"agent_version\": \"" << EscapeJsonString(data.agentVersion) << "\"\n"
             << "}";
        return json.str();
    }

    bool InventoryAgent::SyncWithServer(const std::string& jsonPayload) const {
#ifdef _WIN32
        std::wstring wideUrl(m_endpointUrl.begin(), m_endpointUrl.end());
        URL_COMPONENTS urlComp = {0};
        urlComp.dwStructSize = sizeof(urlComp);

        wchar_t hostName[256] = {0};
        wchar_t urlPath[1024] = {0};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);

        if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.length()), 0, &urlComp)) {
            std::cerr << "[ERROR] Invalid endpoint URL format.\n";
            return false;
        }

        HINTERNET hSession = WinHttpOpen(L"SziMonitorAgent/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlComp.lpszUrlPath, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring authHeader = L"Authorization: Bearer " + std::wstring(m_apiToken.begin(), m_apiToken.end()) + L"\r\nContent-Type: application/json\r\n";
        BOOL bResults = WinHttpSendRequest(
            hRequest,
            authHeader.c_str(),
            static_cast<DWORD>(-1L),
            const_cast<char*>(jsonPayload.c_str()),
            static_cast<DWORD>(jsonPayload.size()),
            static_cast<DWORD>(jsonPayload.size()),
            0
        );

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        if (bResults && WinHttpReceiveResponse(hRequest, nullptr)) {
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return (statusCode >= 200 && statusCode < 300);
#else
        return false;
#endif
    }

} // namespace SziMonitor

int main(int argc, char* argv[]) {
    const char* envEndpoint = std::getenv("SZI_API_URL");
    const char* envToken    = std::getenv("SZI_API_TOKEN");

    if (!envEndpoint || !envToken) {
        std::cerr << "[ERROR] Environment variables SZI_API_URL and SZI_API_TOKEN must be set.\n";
        return 1;
    }

    SziMonitor::InventoryAgent agent(envEndpoint, envToken);
    auto telemetry = agent.CollectTelemetry();
    std::string payload = agent.BuildJsonPayload(telemetry);

    if (agent.SyncWithServer(payload)) {
        std::cout << "[OK] Endpoint telemetry synchronized successfully.\n";
        return 0;
    }

    std::cerr << "[ERROR] Telemetry synchronization failed.\n";
    return 2;
}