#pragma once

#include <string>
#include <cstdint>

namespace SziMonitor {

    struct SystemTelemetry {
        std::string hostname{};
        std::string hardwareId{};
        std::string machineGuid{};
        std::string osVersion{};
        uint64_t    totalRamMb{0};
        std::string agentVersion{"1.2.0"};
    };

    class InventoryAgent {
    public:
        InventoryAgent(const std::string& endpointUrl, const std::string& apiToken);
        ~InventoryAgent() = default;

        SystemTelemetry CollectTelemetry() const;
        std::string BuildJsonPayload(const SystemTelemetry& data) const;
        bool SyncWithServer(const std::string& jsonPayload) const;

    private:
        std::string m_endpointUrl;
        std::string m_apiToken;

        std::string GetLocalHostname() const;
        std::string GetSmbiosUuid() const;
        std::string GetMachineGuid() const;
        std::string GetWindowsVersionString() const;
        uint64_t    GetTotalMemoryMb() const;

        static std::string EscapeJsonString(const std::string& input);
        static std::wstring Utf8ToWide(const std::string& utf8Str);
        static std::string WideToUtf8(const std::wstring& wideStr);
    };

} // namespace SziMonitor
