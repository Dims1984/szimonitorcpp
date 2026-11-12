#include "agent.h"
#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace SziMonitor {

    InventoryAgent::InventoryAgent(const std::string& endpointUrl, const std::string& apiToken)
        : m_endpointUrl(endpointUrl), m_apiToken(apiToken) {}

    std::string InventoryAgent::GetLocalHostname() const {
#ifdef _WIN32
        char buffer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(buffer);
        if (GetComputerNameA(buffer, &size)) {
            return std::string(buffer, size);
        }
#endif
        return "UNKNOWN-HOST";
    }

    std::string InventoryAgent::GetMotherboardUuid() const {
        // Placeholder for WMI Win32_ComputerSystemProduct UUID query
        return "00000000-0000-0000-0000-000000000000";
    }

    std::string InventoryAgent::GetWindowsVersionString() const {
        return "Windows NT (x64)";
    }

    SystemTelemetry InventoryAgent::CollectTelemetry() const {
        SystemTelemetry data;
        data.hostname = GetLocalHostname();
        data.serialNumber = GetMotherboardUuid();
        data.osVersion = GetWindowsVersionString();
        data.agentVersion = "1.0.4";
        return data;
    }

    std::string InventoryAgent::BuildJsonPayload(const SystemTelemetry& data) const {
        std::ostringstream json;
        json << "{\n"
             << "  \"hostname\": \"" << data.hostname << "\",\n"
             << "  \"serial_number\": \"" << data.serialNumber << "\",\n"
             << "  \"os_version\": \"" << data.osVersion << "\",\n"
             << "  \"agent_version\": \"" << data.agentVersion << "\"\n"
             << "}";
        return json.str();
    }

    bool InventoryAgent::SyncWithServer(const std::string& jsonPayload) const {
        std::cout << "[INFO] Preparing telemetry sync to: " << m_endpointUrl << "\n";
        std::cout << "[DEBUG] Payload:\n" << jsonPayload << "\n";
        // WinHTTP / libcurl transport implementation placeholder
        return true;
    }

} // namespace SziMonitor

int main(int argc, char* argv[]) {
    // Public placeholder configuration (override via CLI args or env vars in production)
    const std::string apiEndpoint = "https://api.example.com/v1/sync";
    const std::string apiToken    = "YOUR_PUBLIC_PLACEHOLDER_TOKEN";

    SziMonitor::InventoryAgent agent(apiEndpoint, apiToken);
    
    auto telemetry = agent.CollectTelemetry();
    std::string payload = agent.BuildJsonPayload(telemetry);

    if (agent.SyncWithServer(payload)) {
        std::cout << "[OK] Telemetry synchronized successfully.\n";
        return 0;
    }

    std::cerr << "[ERROR] Failed to synchronize telemetry.\n";
    return 1;
}