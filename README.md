# Embedded-SecLink (ESL)

**High-Performance Security Middleware for Resource-Constrained Embedded Systems**

## Project Overview (專案概述)

ESL 是一個專為嵌入式環境 (如 OBU 車載單元、衛星終端) 設計的輕量級 C++ 安全中介軟體。它旨在填補底層密碼學原語 (OpenSSL/mcl) 與上層應用協定 (V2X/Satellite) 之間的鴻溝，提供安全、高效且易於整合的通訊安全層。

##  Core Features (核心功能 - 規劃中)

### 1. V2X/Satellite Protocol Support (協定支援)

- **Optimized BLS Signatures**: 實作針對 V2X 場景優化的 BLS12-381 簽章聚合 (Aggregation) 與批次驗證 (Batch Verification)。
- **Custom Protocol Frames**: 定義並處理輕量級的安全通訊封包格式。

### 2. Embedded-First Engineering (嵌入式優先設計)

- **Resource Management**: 採用 RAII 技術管理金鑰生命週期，確保敏感資料在使用後立即從記憶體中清除 (Secure Wipe)。
- **Zero-Copy Semantics**: 大量使用 `std::span` 與 `std::string_view`，最小化記憶體拷貝，提升傳輸吞吐量。

### 3. System Integration (系統整合)

- **Modern CMake Build System**: 支援 Config-mode `find_package`，一行指令即可整合至現有專案。
- **Cross-Platform Ready**: 架構設計考量 x86 (模擬) 與 ARM (實機) 的跨平台編譯需求。

##  Tech Stack (技術堆疊)

- **Language**: C++17 (Modern C++ Features)
- **Build System**: CMake 3.15+
- **Testing**: GoogleTest + CTest
- **Cryptography Backend**: mcl / OpenSSL (Pluggable Architecture)

---

_Started in Nov 2025 as a high-performance firmware portfolio project._
