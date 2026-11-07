# Secrust — Endpoint Security & Monitoring Platform

**A centralized security monitoring platform with a Windows endpoint agent.**

Secrust is a security monitoring platform designed to help organizations manage endpoints, collect security telemetry, monitor endpoint health, and manage access through organization-based role controls.

It combines a Go-based backend and web dashboard with a separate Windows SystemMonitor agent that communicates with the Secrust server.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Repositories](#repositories)
- [Backend Installation](#backend-installation)
- [Windows Agent Setup](#windows-agent-setup)
- [Agent-to-Server Connection](#agent-to-server-connection)
- [Agent Authentication](#agent-authentication)
- [Heartbeat and Telemetry](#heartbeat-and-telemetry)
- [Agent Key Rotation](#agent-key-rotation)
- [API Overview](#api-overview)
- [Security](#security)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

## Overview

Secrust provides a central place to manage organizations and their endpoints. The Windows agent runs on monitored Windows systems and communicates with the Secrust backend.

The platform is being developed around:

- Organization and user management.
- Role-based access control (RBAC).
- Endpoint registration and credential management.
- Security event telemetry.
- Endpoint heartbeat and availability monitoring.
- A web dashboard for monitoring and administration.

## Key Features

### Platform

- Go-based backend.
- Web-based dashboard.
- Organization management.
- Role-based access control.
- User and invitation management.
- SQLite database with versioned migrations.

### Windows SystemMonitor Agent

- Windows endpoint monitoring.
- Windows security event collection.
- Security event forwarding to Secrust.
- Agent authentication using individual credentials.
- Heartbeat communication with the backend.
- Windows Service execution.

### Endpoint Security

- Randomly generated agent credentials.
- SHA-256 credential hashing on the server.
- Credential-based endpoint authentication.
- Agent key rotation.
- Organization-scoped endpoint management.

## Architecture

```text
              SECRUST PLATFORM
                     |
        +------------+------------+
        |                         |
   Web Dashboard              Go Backend
        |                         |
        |                   Authentication
        |                         |
        |                    RBAC / Org
        |                         |
        |                  Endpoint API
        |                         |
        |                    SQLite DB
        |                         |
        +------------+------------+
                     |
                HTTP / HTTPS
                     |
          Windows SystemMonitor
                     |
          +----------+----------+
          |                     |
     Event Collector       Heartbeat Client
          |                     |
    Windows Events          Agent Status
          |                     |
          +----------+----------+
                     |
              Secrust Server
```

The Windows agent and Secrust backend are maintained as separate codebases.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Go |
| Web framework | Gin |
| Database | SQLite |
| SQLite driver | modernc.org/sqlite |
| Frontend | HTML, CSS, JavaScript |
| Agent | Go |
| Operating system | Windows |
| Authentication | Session authentication and agent credentials |
| Database changes | SQL migrations |

## Repositories

| Component | Repository |
|---|---|
| Secrust backend | https://github.com/paragishere/secrust-rebuild |
| Windows SystemMonitor agent | https://github.com/paragishere/SystemMonitor |

### Secrust Backend

GitHub: https://github.com/paragishere/secrust-rebuild

### Windows SystemMonitor Agent

GitHub: https://github.com/paragishere/SystemMonitor

The agent is maintained separately from the backend. Clone it independently when developing or deploying the Windows component.

## Backend Installation

### Prerequisites

- Go installed.
- Git installed.
- Windows, Linux, or macOS development environment.
- A terminal or PowerShell.

### Clone the repository

```bash
git clone https://github.com/paragishere/secrust-rebuild.git
cd secrust-rebuild
```

### Install dependencies

```bash
go mod download
```

### Configure environment

Create a local `.env` file using the project's supported environment variables.

Example development configuration:

```env
PORT=8080
DATABASE_PATH=./data/secrust.db
ENVIRONMENT=development
```

For production, configure a strong `SESSION_SECRET` of at least 32 characters. Keep secrets in environment variables or an appropriate secret manager, never in Git.

### Run the backend

```bash
go run ./cmd/server
```

For local development, the server is expected at:

```text
http://localhost:8080
```

Set the agent's `server_url` to the reachable Secrust server address. `localhost` works only when the agent and backend run on the same machine; for a different Windows endpoint, use the backend machine's reachable LAN address or deployed HTTPS URL.

Health check:

```text
http://localhost:8080/health
```

## Windows Agent Setup

The SystemMonitor agent is a separate Go application.

### Prerequisites

- Windows 10 or Windows 11.
- Go toolchain.
- Git.
- PowerShell.
- Appropriate permissions for Windows event collection and service installation.

### Clone the agent repository

Clone the confirmed Windows agent repository:

```powershell
git clone https://github.com/paragishere/SystemMonitor.git
cd SystemMonitor\agent
```

### Build the agent

```powershell
go mod download
go build -o system-agent.exe .
```

Run the agent using the execution mode supported by the current build. For a local foreground demonstration, start with:

```powershell
.\system-agent.exe
```

If the build supports service mode, it can also be launched with:

```powershell
.\system-agent.exe service
```

For an installed Windows service, use an elevated PowerShell window:

```powershell
Get-Service SystemMonitorAgent
Start-Service SystemMonitorAgent
Get-Service SystemMonitorAgent
```

To stop it:

```powershell
Stop-Service SystemMonitorAgent
```

### Agent configuration

The installed Windows service reads its configuration from:

```text
C:\ProgramData\SystemMonitor\config.json
```

The Windows service is named `SystemMonitorAgent`.

Configuration structure:

```json
{
  "server_url": "http://localhost:8080",
  "host_id": "YOUR_REGISTERED_HOST_ID",
  "agent_key": "YOUR_AGENT_KEY"
}
```

**Important:** This is a template only. Obtain the host ID and agent key through the authenticated Secrust registration workflow. Never commit a real configuration file or agent key.

## Agent-to-Server Connection

The connection follows this workflow:

1. An authorized organization administrator registers a Windows endpoint through Secrust.
2. Secrust generates a host ID and a random agent credential.
3. The server stores the SHA-256 hash of the credential, not its plaintext value.
4. The raw agent key is returned once during registration.
5. The administrator securely configures the Windows agent.
6. The agent sends authenticated heartbeat and telemetry requests.
7. Secrust validates the agent credential and associates accepted data with the registered endpoint.

```text
Windows Agent
     |
     | X-Agent-Key
     |
     v
Secrust Agent Authentication
     |
     | SHA-256 credential lookup
     |
     v
Active Endpoint Validation
     |
     v
Telemetry / Heartbeat Handler
     |
     v
Database
```

## Agent Authentication

The agent authenticates using the `X-Agent-Key` HTTP header.

Conceptual request:

```http
POST /api/endpoint/heartbeat
X-Agent-Key: YOUR_AGENT_KEY
Content-Type: application/json
```

The backend hashes the received credential using SHA-256 and looks up the matching active endpoint.

Only active registered hosts with valid credentials should be accepted.

## Heartbeat and Telemetry

The Windows agent communicates with the backend through separate operations:

### Heartbeat

```http
POST /api/endpoint/heartbeat
```

Used to report that the endpoint agent is active and communicating with Secrust.

### Event telemetry

```http
POST /api/endpoint/events
```

Used to forward collected endpoint events to the backend.

The dashboard can use endpoint heartbeat information to display host availability.

## Agent Key Rotation

Secrust supports endpoint credential rotation through an authenticated administrative route:

```http
POST /api/endpoints/:hostID/rotate-key
```

The route is restricted to authorized organization administrators/managers and requires the CSRF header. The raw replacement key is returned only once; securely update the Windows agent configuration after rotation.

Rotation workflow:

1. An authorized administrator requests key rotation.
2. Secrust generates a new random credential.
3. The server stores its SHA-256 hash.
4. The old credential is invalidated by replacing its hash.
5. The new raw credential is returned once.
6. The administrator securely updates the agent configuration.

The new key must be protected like a password. Never publish it in source code, screenshots, logs, or GitHub.

## API Overview

| Endpoint | Purpose |
|---|---|
| `POST /api/endpoint/heartbeat` | Agent heartbeat |
| `POST /api/endpoint/events` | Submit endpoint telemetry |
| `POST /api/endpoints/:hostID/rotate-key` | Rotate endpoint credential |

Administrative registration routes are authenticated and role-restricted. Refer to the current backend route definitions for the exact registration path and request schema.

## Security

Security is a core design consideration.

- Store only hashed agent credentials on the backend.
- Return raw agent credentials only during the authorized registration or rotation operation.
- Restrict endpoint administration by organization and role.
- Require CSRF protection on authenticated administrative operations.
- Reject invalid or inactive agent credentials.
- Keep `.env`, `config.json`, plaintext keys, logs containing secrets, and private certificates out of Git.
- Use HTTPS when deploying outside a trusted local development environment.
- Rotate credentials immediately if they are exposed.

## Development

### Run tests

```bash
go test ./...
```

### Format Go code

```bash
gofmt -w .
```

### Check Git changes

```bash
git status
```

Before committing, verify that no credentials, local configuration, database files, logs, or compiled executables are staged.

## Roadmap

The project is actively under feature and UI development.

Potential development areas:

- Endpoint monitoring dashboard improvements.
- Better telemetry visualization.
- Endpoint health and heartbeat history.
- Agent deployment and update workflow.
- More detailed security event analysis.
- Alerting and notification capabilities.
- Additional endpoint management controls.
- Production deployment hardening.

## Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement and test your changes.
4. Ensure secrets and generated binaries are excluded.
5. Submit a Pull Request with a clear description.

## License

Add the project's chosen license before public distribution.

## Maintainer

**Parag Malvi**

Secrust — Endpoint Security & Monitoring Platform
