#ifndef SDB_TYPES_HPP
#define SDB_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace sdb {
    using byte64 = std::array<std::byte, 8>;
    using byte128 = std::array<std::byte, 16>;

    class virt_addr {
    public:
        virt_addr() = default;
        explicit virt_addr(std::uint64_t addr)
            : addr_(addr) {}

        operator std::uint64_t() const {
            return addr_;
        }

        std::uint64_t addr() const {
            return addr_;
        }

        virt_addr operator+(std::int64_t offset) const {
            return virt_addr(addr_ + offset);
        }
        virt_addr operator-(std::int64_t offset) const {
            return virt_addr(addr_ - offset);
        }
        virt_addr& operator+=(std::int64_t offset) {
            addr_ += offset;
            return *this;
        }
        virt_addr& operator-=(std::int64_t offset) {
            addr_ -= offset;
            return *this;
        }
        bool operator==(const virt_addr& other) const {
            return addr_ == other.addr_;
        }
        bool operator!=(const virt_addr& other) const {
            return addr_ != other.addr_;
        }
        bool operator<(const virt_addr& other) const {
            return addr_ < other.addr_;
        }
        bool operator<=(const virt_addr& other) const {
            return addr_ <= other.addr_;
        }
        bool operator>(const virt_addr& other) const {
            return addr_ > other.addr_;
        }
        bool operator>=(const virt_addr& other) const {
            return addr_ >= other.addr_;
        }

    private:
        std::uint64_t addr_ = 0;
    };
}

#endif