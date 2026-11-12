#include "agent.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
        return "";
    }

    std::string InventoryAgent::GetSmbiosSystemUuid() const {
#ifdef _WIN32
        DWORD bufSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
        if (bufSize < 8) return "";

        std::vector<BYTE> buffer(bufSize, 0);
        if (GetSystemFirmwareTable('RSMB', 0, buffer.data(), bufSize) != bufSize) {
            return "";
        }

        // RawSMBIOSData header: byte 1 = MajorVersion, byte 2 = MinorVersion, bytes 4..7 = Length (DWORD)
        const BYTE majorVer = buffer[1];
        const BYTE minorVer = buffer[2];
        DWORD tableLength = 0;
        std::memcpy(&tableLength, buffer.data() + 4, sizeof(DWORD));

        if (tableLength == 0 || tableLength > bufSize - 8) {
            tableLength = bufSize - 8;
        }

        const BYTE* p = buffer.data() + 8;
        const BYTE* end = p + tableLength;

        while (end - p >= 4) {
            const BYTE type = p[0];
            const BYTE length = p[1];

            if (length < 4 || end - p < length) {
                break; // Malformed SMBIOS structure header
            }

            // Type 1 (System Information) with UUID field present (minimum length 0x18)
            if (type == 1 && length >= 0x18) {
                const BYTE* u = p + 8;
                bool allZero = true;
                bool allFF   = true;
                for (int i = 0; i < 16; ++i) {
                    if (u[i] != 0x00) allZero = false;
                    if (u[i] != 0xFF) allFF   = false;
                }

                if (!allZero && !allFF) {
                    char uuidStr[37] = {0};
                    bool useMixedEndian = (majorVer > 2) || (majorVer == 2 && minorVer >= 6);
                    if (useMixedEndian) {
                        std::snprintf(uuidStr, sizeof(uuidStr),
                            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                            u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6],
                            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                    } else {
                        std::snprintf(uuidStr, sizeof(uuidStr),
                            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
                            u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
                    }
                    return std::string(uuidStr);
                }
            }

            // Advance past formatted section to unformatted string-set (terminated by double NUL)
            const BYTE* strPtr = p + length;
            bool foundDoubleNull = false;
            while (end - strPtr >= 2) {
                if (strPtr[0] == 0 && strPtr[1] == 0) {
                    strPtr += 2;
                    foundDoubleNull = true;
                    break;
                }
                ++strPtr;
            }

            if (!foundDoubleNull) {
                break; // Truncated string table, stop parsing safely
            }
            p = strPtr;
        }
#endif
        return "";
    }

    std::string InventoryAgent::GetMachineGuid() const {
#ifdef _WIN32
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
            char buffer[128] = {0};
            DWORD bufSize = sizeof(buffer);
            DWORD valueType = 0;
            LSTATUS status = RegQueryValueExA(hKey, "MachineGuid", nullptr, &valueType, reinterpret_cast<LPBYTE>(buffer), &bufSize);
            RegCloseKey(hKey);

            // Strictly require REG_SZ and verify that a NUL terminator exists within the returned bytes
            if (status == ERROR_SUCCESS && valueType == REG_SZ && bufSize >= 32 && bufSize <= sizeof(buffer)) {
                const void* nullPos = std::memchr(buffer, '\0', bufSize);
                if (nullPos != nullptr) {
                    std::string guid(buffer);
                    if (guid.length() >= 32 && guid.length() <= 38) {
                        return guid;
                    }
                }
            }
        }
#endif
        return "";
    }

    HardwareIdentity InventoryAgent::ResolveHardwareIdentity() const {
        HardwareIdentity id{};
        id.systemUuid  = GetSmbiosSystemUuid();
        id.machineGuid = GetMachineGuid();

        if (!id.systemUuid.empty() && !id.machineGuid.empty()) {
            id.identitySource = "smbios_uuid";
        } else if (!id.systemUuid.empty()) {
            id.identitySource = "smbios_uuid_only";
        } else if (!id.machineGuid.empty()) {
            id.identitySource = "machine_guid_fallback";
        } else {
            id.identitySource = "none";
        }
        return id;
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
        data.identity     = ResolveHardwareIdentity();
        data.osVersion    = GetWindowsVersionString();
        data.totalRamMb   = GetTotalMemoryMb();
        data.agentVersion = "1.3.0";
        return data;
    }

    std::string InventoryAgent::BuildJsonPayload(const SystemTelemetry& data) const {
        std::ostringstream json;
        json << "{\n"
             << "  \"hostname\": \"" << EscapeJsonString(data.hostname) << "\",\n"
             << "  \"hardware_id\": \"" << EscapeJsonString(data.identity.GetPrimaryHardwareId()) << "\",\n"
             << "  \"system_uuid\": \"" << EscapeJsonString(data.identity.systemUuid) << "\",\n"
             << "  \"machine_guid\": \"" << EscapeJsonString(data.identity.machineGuid) << "\",\n"
             << "  \"identity_source\": \"" << EscapeJsonString(data.identity.identitySource) << "\",\n"
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
        wchar_t extraInfo[1024] = {0};
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);
        urlComp.lpszExtraInfo = extraInfo;
        urlComp.dwExtraInfoLength = _countof(extraInfo);

        if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.length()), 0, &urlComp)) {
            std::cerr << "[ERROR] Invalid endpoint URL format (WinHttpCrackUrl error: " << GetLastError() << ").\n";
            return false;
        }

        if (urlComp.nScheme != INTERNET_SCHEME_HTTPS) {
            std::cerr << "[SECURITY] Plaintext HTTP is rejected. Endpoint must use HTTPS.\n";
            return false;
        }

        // Preserve both path and query string (e.g., /api.php?tenant=company1)
        std::wstring fullRequestTarget(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        if (urlComp.dwExtraInfoLength > 0) {
            fullRequestTarget.append(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
        }
        if (fullRequestTarget.empty()) {
            fullRequestTarget = L"/";
        }

        HINTERNET hSession = WinHttpOpen(L"SziMonitorAgent/1.3", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            std::cerr << "[ERROR] WinHttpOpen failed (code: " << GetLastError() << ").\n";
            return false;
        }

        if (!WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000)) {
            std::cerr << "[ERROR] WinHttpSetTimeouts failed (code: " << GetLastError() << ").\n";
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
        if (!hConnect) {
            std::cerr << "[ERROR] WinHttpConnect failed (code: " << GetLastError() << ").\n";
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", fullRequestTarget.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            std::cerr << "[ERROR] WinHttpOpenRequest failed (code: " << GetLastError() << ").\n";
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Fail-closed if disabling redirects fails
        DWORD disableRedirects = WINHTTP_DISABLE_REDIRECTS;
        if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &disableRedirects, sizeof(disableRedirects))) {
            std::cerr << "[SECURITY] Failed to disable HTTP redirects (code: " << GetLastError() << "). Aborting.\n";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring wideToken = Utf8ToWide(m_apiToken);
        if (wideToken.empty()) {
            std::cerr << "[ERROR] API token UTF-8 conversion failed.\n";
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

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
            if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
                std::cerr << "[ERROR] WinHttpQueryHeaders failed (code: " << GetLastError() << ").\n";
            }
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

    // Fail-closed: never send shared placeholder IDs if hardware/OS identification fails
    if (telemetry.hostname.empty() || !telemetry.identity.IsValid()) {
        std::cerr << "[CRITICAL] Failed to resolve valid endpoint hostname or hardware identity. Aborting sync.\n";
        return 3;
    }

    std::string payload = agent.BuildJsonPayload(telemetry);
    if (agent.SyncWithServer(payload)) {
        std::cout << "[OK] Endpoint telemetry synchronized (source: " << telemetry.identity.identitySource << ").\n";
        return 0;
    }

    return 2;
}
