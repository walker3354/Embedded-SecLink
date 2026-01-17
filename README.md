# Embedded-SecLink (ESL)

**Embedded-SecLink (ESL)** 是一個專為嵌入式系統 (尤其是 V2X 車聯網環境) 設計的輕量級安全通訊框架。它整合了現代密碼學演算法 (ECC, BLS, AES) 與資料結構 (Merkle Tree)，旨在提供一個可移植、易於整合的 C++ 安全函式庫。

本專案是碩士論文《XXXXXXXXXXXXXXXXXXXXXX》的核心實作部分，目標是在計算資源受限的 OBU (On-Board Unit) 上實現高效的安全群組通訊。

## 核心功能 (Key Features)

- **ECC Core**: 基於 `micro-ecc` 的橢圓曲線加密核心 (SECP256R1)，支援 ECDH 金鑰交換與 ECDSA 簽章。
- **BLS Core**: 基於 `mcl` 的 BLS12-381 簽章核心，支援**聚合簽章 (Signature Aggregation)**，大幅降低群組通訊頻寬。
- **AES Core**: 基於 `tiny-AES-c` 的對稱式加密核心 (AES-128/256 CBC)，包含 PKCS7 Padding 處理。
- **Hash Tree**: 實作 Merkle Tree 用於資料完整性驗證與輕量化證明。
- **Utils**: 包含高精度計時器 (Stopwatch) 與隨機數生成器。

## 技術堆疊 (Tech Stack)

本專案基於 **Modern CMake (3.15+)** 構建，並整合以下開源專案：

- **[mcl](https://github.com/herumi/mcl)** (BSD-3-Clause): 高效能配對加密庫，用於 BLS 簽章。
- **[micro-ecc](https://github.com/kmackay/micro-ecc)** (BSD-2-Clause): 針對嵌入式優化的 ECC 庫。
- **[tiny-AES-c](https://github.com/kokke/tiny-AES-c)** (Public Domain): 輕量級 C 語言 AES 實作。
- **[PicoSHA2](https://github.com/okdshin/PicoSHA2)** (MIT): Header-only SHA256 實作。
- **[GoogleTest](https://github.com/google/googletest)**: 單元測試框架。

## 建置與安裝 (Build & Install)

本專案支援標準 CMake 安裝流程，可生成包含標頭檔與靜態庫的 SDK。

### 1. 系統需求

- CMake >= 3.15
- C++17 Compiler (MSVC, GCC, Clang)

### 2. 製作 SDK (Windows/Linux)

```bash
# 1. 建立建置目錄
mkdir build && cd build

# 2. 設定安裝路徑 (例如安裝到專案根目錄下的 sdk_output)
cmake .. -DCMAKE_INSTALL_PREFIX="../sdk_output"

# 3. 編譯 (Release 模式)
cmake --build . --config Release

# 4. 安裝 (生成 SDK)
cmake --install . --config Release
```

執行完畢後，你將在 `sdk_output` 目錄下看到完整的 SDK 結構：

- `lib/`: 包含 `esl.lib` (或 `libesl.a`) 及其相依庫。
- `include/esl/`: 包含所有標頭檔。
- `lib/cmake/esl/`: 包含 CMake 設定檔 (`eslTargets.cmake`)。

### 3. 選項設定

在 CMake Configure 階段可調整以下參數：

| 選項                 | 預設值 | 說明                                       |
| :------------------- | :----- | :----------------------------------------- |
| `ESL_BUILD_SHARED`   | `OFF`  | 建置動態庫 (.dll/.so) 還是靜態庫 (.lib/.a) |
| `ESL_BUILD_TESTS`    | `ON`   | 是否下載 GoogleTest 並建置測試程式         |
| `ESL_BUILD_EXAMPLES` | `ON`   | 是否建置範例程式                           |

## 如何在你的專案中使用 (Integration)

一旦生成了 SDK，你可以在另一個 CMake 專案中輕鬆引用 ESL。

**CMakeLists.txt 範例:**

```cmake
cmake_minimum_required(VERSION 3.15)
project(MyOBUApp)

# 指定 ESL SDK 的位置 (讓 find_package 找得到)
# 你也可以在執行 cmake 時透過 -Desl_DIR="..." 指定
set(esl_DIR "path/to/sdk_output/lib/cmake/esl")

# 尋找 ESL 套件
find_package(esl REQUIRED)

add_executable(my_app main.cpp)

# 連結 ESL (標頭檔路徑會自動加入)
target_link_libraries(my_app PRIVATE esl::esl)
```

## 授權 (License)

本專案原始碼採用 MIT License。
所使用的第三方庫遵循其各自的授權條款 (BSD/MIT/Public Domain)。
