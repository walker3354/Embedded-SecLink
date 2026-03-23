# Embedded-SecLink (ESL)

**Embedded-SecLink (ESL)** 是一個專為嵌入式系統（尤其是 V2X 車聯網環境）設計的輕量級安全通訊框架。它整合了現代密碼學演算法（ECC、BLS、AES）與資料結構（Merkle Tree），旨在提供一個可移植、易於整合的 C++ 安全函式庫。

本專案是碩士論文的(XXXXXXX)所使用的核心套件，目標是在計算資源受限的 OBU（On-Board Unit）上實現高效的安全群組通訊。

本專案目前已經確認可以在以下平台編譯以及執行：windows11(MSVC) WSL(Ubuntu 20.04 Ubuntu 18.04) Armv7 32bit(交叉編譯)

---

## 核心套件

- **ECC Core**: 基於 `micro-ecc` 的橢圓曲線加密核心（SECP256R1），支援 ECDH 金鑰交換與 ECDSA 簽章。
- **BLS Core**: 基於 `blst` 的 BLS12-381 簽章核心，支援**聚合簽章（Signature Aggregation）**，大幅降低群組通訊頻寬。
- **AES Core**: 基於 `tiny-AES-c` 的對稱式加密核心（AES-128/256 CBC），包含 PKCS7 Padding 處理。
- **Hash Tree**: 實作 Merkle Tree 用於資料完整性驗證與輕量化證明。
- **Utils**: 包含高精度計時器（Stopwatch）、時間工具（TimeUtils）與隨機數生成器（Random）。

---

## 技術堆疊

本專案基於 **Modern CMake（3.12+）** 構建，並整合以下開源專案：

- **[blst](https://github.com/supranational/blst)** (Apache-2.0 / MIT): 高效能 BLS12-381 配對加密庫。
- **[micro-ecc](https://github.com/kmackay/micro-ecc)** (BSD-2-Clause): 針對嵌入式優化的 ECC 庫。
- **[tiny-AES-c](https://github.com/kokke/tiny-AES-c)** (Public Domain): 輕量級 C 語言 AES 實作。
- **[PicoSHA2](https://github.com/okdshin/PicoSHA2)** (MIT): Header-only SHA256 實作。
- **[nlohmann/json](https://github.com/nlohmann/json)** (MIT): Header-only JSON 解析庫。
- **[GoogleTest](https://github.com/google/googletest)** (BSD-3-Clause): 單元測試框架（僅 `ESL_BUILD_TESTS=ON` 時啟用）。

---

## 建置與安裝

### 系統需求

- CMake >= 3.12
- C++17 Compiler（MSVC、GCC、Clang）
- Git（FetchContent 需要）

### 建置 SDK

```bash
# 1. 建立建置目錄
mkdir build && cd build

# 2. 設定（Release 模式，安裝到 sdk_output）
cmake .. -DCMAKE_INSTALL_PREFIX="../sdk_output"

# 3. 編譯
cmake --build . --config Release

# 4. 安裝
cmake --install . --config Release
```
