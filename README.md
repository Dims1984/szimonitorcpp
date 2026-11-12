# szimonitorcpp

**szimonitorcpp** is a lightweight, open-source system monitoring and hardware inventory agent written in C++ with a PHP/SQLite backend synchronization API.

## Features
- **Automated Hardware Auditing:** Collects system serial numbers, hostnames, and OS configuration metrics.
- **Lightweight Footprint:** Runs natively on Windows endpoints without heavy runtime dependencies.
- **Centralized Sync:** Synchronizes endpoint telemetry with a lightweight SQLite database (`inventory.db`) via a RESTful PHP API.
- **Security & Compliance:** Designed for system administrators to maintain accurate infrastructure visibility and endpoint security hygiene.

## Architecture
- **Client Agent:** Native C++ (WinAPI / WMI queries)
- **Backend API:** PHP 8+ / Nginx
- **Database:** SQLite3

## License
Distributed under the MIT License.
