#pragma once

#include <string>
#include <cstdint>

namespace SziMonitor {

    struct HardwareIdentity {
        std::string systemUuid{};
        std::string machineGuid{};
        std::string identitySource{"none"};

        bool IsValid() const {
            return !systemUuid.empty() || !machineGuid.empty();
        }

        std::string GetPrimaryHardwareId() const {
            return !systemUuid.empty() ? systemUuid : machineGuid;
        }
    };

    struct SystemTelemetry {
        std::string      hostname{};
        HardwareIdentity identity{};
        std::string      osVersion{};
        uint64_t         totalRamMb{0};
        std::string      agentVersion{"1.3.0"};
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

        std::string      GetLocalHostname() const;
        std::string      GetSmbiosSystemUuid() const;
        std::string      GetMachineGuid() const;
        HardwareIdentity ResolveHardwareIdentity() const;
        std::string      GetWindowsVersionString() const;
        uint64_t         GetTotalMemoryMb() const;

        static std::string  EscapeJsonString(const std::string& input);
        static std::wstring Utf8ToWide(const std::string& utf8Str);
        static std::string  WideToUtf8(const std::wstring& wideStr);
    };

} // namespace SziMonitor
