#pragma once
#include <memory>

namespace esl::crypto {
    class EccCore {
        private:
            struct Impl;
            std::unique_ptr<Impl> m_impl;

        public:
            EccCore(bool dev_mode = false);
            ~EccCore();
            // copy not allow
            EccCore(const EccCore&) = delete;
            EccCore& operator=(const EccCore&) = delete;
            // move define
            EccCore(EccCore&&) noexcept;
            EccCore& operator=(EccCore&&) noexcept;
    };
} // namespace esl::crypto