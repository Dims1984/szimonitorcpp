#pragma once

#include <string>
#include <cstdint>

namespace SziMonitor {

    struct SystemTelemetry {
        std::string hostname;
        std::string serialNumber;
        std::string osVersion;
        uint64_t    totalRamMb;
        std::string agentVersion;
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
        std::string GetHardwareIdentifier() const;
        std::string GetWindowsVersionString() const;
        uint64_t    GetTotalMemoryMb() const;

        static std::string EscapeJsonString(const std::string& input);
    };

} // namespace SziMonitor