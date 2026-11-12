#pragma once

#include <string>

namespace SziMonitor {

    struct SystemTelemetry {
        std::string hostname;
        std::string serialNumber;
        std::string osVersion;
        std::string agentVersion;
    };

    class InventoryAgent {
    public:
        InventoryAgent(const std::string& endpointUrl, const std::string& apiToken);
        ~InventoryAgent() = default;

        // Collects basic hardware and OS telemetry
        SystemTelemetry CollectTelemetry() const;

        // Formats telemetry into a JSON payload
        std::string BuildJsonPayload(const SystemTelemetry& data) const;

        // Sends payload to the central synchronization API
        bool SyncWithServer(const std::string& jsonPayload) const;

    private:
        std::string m_endpointUrl;
        std::string m_apiToken;

        std::string GetLocalHostname() const;
        std::string GetMotherboardUuid() const;
        std::string GetWindowsVersionString() const;
    };

} // namespace SziMonitor