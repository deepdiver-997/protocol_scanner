# Protocol Scanner Architecture

## Overview

Protocol Scanner is a high-performance, modular network protocol scanner designed for email service discovery and fingerprinting.

## Core Design Principles

1. **Separation of Concerns**: Each module has a single, well-defined responsibility
2. **Interface-Based Design**: Protocol implementations use abstract interfaces
3. **Zero-Cost Abstraction**: Performance overhead minimized through careful design
4. **Configuration-Driven**: Behavior controlled through JSON configuration
5. **Extensibility**: Adding new protocols requires minimal code changes

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Layer                          │
│  ┌──────────────────────────────────────────────────┐    │
│  │         main.cpp (Program Entry)                │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Core Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
│  │   Scanner    │  │  TaskQueue   │  │ Progress │  │
│  └──────────────┘  └──────────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  Protocol Layer                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────┐  │
│  │   SMTP   │  │   POP3   │  │   IMAP   │  │HTTP│  │
│  └──────────┘  └──────────┘  └──────────┘  └────┘  │
│         ↑             ↑             ↑            ↑      │
│         └─────────────┴─────────────┴────────────┘      │
│                     IProtocol Interface                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│               Infrastructure Layer                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────┐  │
│  │  DNS Resolver│ │Port Scanner│ │   Logger  │ │Config│  │
│  └──────────┘  └──────────┘  └──────────┘  └────┘  │
│         ↓             ↓             ↓            ↑      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────┐  │
│  │ Boost.Asio │ │  dig/lib  │ │  File/Std│ │JSON│  │
│  └──────────┘  └──────────┘  └──────────┘  └────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Module Details

### Core Module (`core/`)

**Files:**
- `scanner.h` - Main scanner orchestration
- `task_queue.h` - Thread-safe task queue

**Responsibilities:**
- Coordinate scanning operations
- Manage thread pools
- Handle progress tracking

### Protocol Module (`protocols/`)

**Files:**
- `protocol_base.h` - Protocol interface and factory
- `smtp_protocol.h/cpp` - SMTP implementation
- `pop3_protocol.h/cpp` - POP3 implementation
- `imap_protocol.h/cpp` - IMAP implementation
- `http_protocol.h/cpp` - HTTP implementation

**Responsibilities:**
- Implement protocol-specific probing
- Parse protocol capabilities
- Extract service banners

### DNS Module (`dns/`)

**Files:**
- `dns_resolver.h` - DNS resolver interface
- `dig_resolver.cpp` - dig command implementation

**Responsibilities:**
- Resolve A records
- Query MX records
- Handle DNS errors

### Network Module (`network/`)

**Files:**
- `port_scanner.h` - Port scanning utilities

**Responsibilities:**
- Check port accessibility
- Measure response times
- Handle connection timeouts

### Vendor Module (`vendor/`)

**Files:**
- `vendor_detector.h` - Vendor detection logic

**Responsibilities:**
- Load vendor patterns
- Match banners to vendors
- Generate vendor statistics

### Output Module (`output/`)

**Files:**
- `result_handler.h` - Result formatting
- `report_generator.h` - Report generation

**Responsibilities:**
- Format results (JSON, CSV, Text, HTML)
- Generate summary reports
- Write output files

### Common Module (`common/`)

**Files:**
- `logger.h` - Logging system

**Responsibilities:**
- Provide logging interface
- Manage log levels
- Handle log output

## Data Flow

```
1. CLI parses arguments
   ↓
2. Scanner creates task queue
   ↓
3. Worker threads pop tasks
   ↓
4. For each target:
   a. DNS resolver queries A and MX records
   b. Port scanner checks accessibility
   c. Protocol implementations probe services
   d. Vendor detector identifies service
   ↓
5. Results aggregated and formatted
   ↓
6. Output written to files
```

## Extension Points

### Adding a New Protocol

1. Create protocol class inheriting from `IProtocol`
2. Implement all virtual methods
3. Register with `REGISTER_PROTOCOL` macro
4. Add source file to `CMakeLists.txt`
