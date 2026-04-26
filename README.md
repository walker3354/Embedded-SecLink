# Embedded-SecLink (ESL)

![](/ESL_logo.jpg "ESL logo")
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

## 來源依賴

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

### 方式二：透過 FetchContent 自動下載（開發環境）

適合開發階段，CMake 會自動從 GitHub 拉取並編譯 ESL，不需要預先安裝。

```cmake
cmake_minimum_required(VERSION 3.12)
project(MyOBUApp)

include(FetchContent)
FetchContent_Declare(
    esl
    GIT_REPOSITORY https://github.com/walker3354/Embedded-SecLink.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(esl)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE esl::esl)
```

> **注意**：`GIT_TAG` 建議指定固定的 commit SHA 或 release tag（例如 `v1.1.0`）而非 `main`，避免 upstream 更新造成建置不穩定。

### 專案結構 (Directory Structure)

```text
sdk_output/
├── include/esl/
│   ├── crypto/
│   │   ├── BlsCore.hpp
│   │   └── EccCore.hpp
│   └── utils/
│       ├── HashTree.hpp
│       ├── Random.hpp
│       ├── Stopwatch.hpp
│       ├── TimeUtils.hpp
│       └── json.hpp
└── lib/
    ├── esl.lib ( Windows ) 或 libesl.a ( Linux )
    └── cmake/esl/
        ├── EslConfig.cmake
        ├── EslConfigVersion.cmake
        └── EslTargets.cmake
```

### 建置選項

| 選項                 | 預設值 | 說明                                        |
| :------------------- | :----- | :------------------------------------------ |
| `ESL_BUILD_SHARED`   | `OFF`  | 建置動態庫（.dll/.so）而非靜態庫（.lib/.a） |
| `ESL_BUILD_TESTS`    | `OFF`  | 下載 GoogleTest 並建置單元測試              |
| `ESL_BUILD_EXAMPLES` | `ON`   | 建置範例程式                                |
| `ESL_STRICT_MODE`    | `OFF`  | 啟用嚴格編譯警告（-Wall -Wextra -Werror）   |

---

## 在你的專案中使用

安裝完成後，在其他 CMake 專案中引用 ESL：

```cmake
cmake_minimum_required(VERSION 3.12)
project(MyOBUApp)

# 指定 ESL SDK 位置
set(esl_DIR "path/to/sdk_output/lib/cmake/esl")

find_package(esl REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE esl::esl)
```

或在執行 cmake 時透過參數指定：

```bash
cmake .. -Desl_DIR="path/to/sdk_output/lib/cmake/esl"
```

---

## 授權

本專案原始碼採用 MIT License。
所使用的第三方庫遵循其各自的授權條款（Apache-2.0 / BSD / MIT / Public Domain）。
