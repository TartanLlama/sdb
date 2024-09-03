#ifndef SDB_WATCHPOINT_HPP
#define SDB_WATCHPOINT_HPP

#include <cstdint>
#include <cstddef>
#include <libsdb/types.hpp>

namespace sdb {
    class process;

    class watchpoint {
    public:
        watchpoint() = delete;
        watchpoint(const watchpoint&) = delete;
        watchpoint& operator=(const watchpoint&) = delete;

        using id_type = std::int32_t;
        id_type id() const { return id_; }

        void enable();
        void disable();
        void remove() {}

        bool is_enabled() const { return is_enabled_; }
        virt_addr address() const { return address_; }
        stoppoint_mode mode() const { return mode_; }
        std::size_t size() const { return size_; }

        bool at_address(virt_addr addr) const {
            return address_ == addr;
        }
        bool in_range(virt_addr low, virt_addr high) const {
            return low <= address_ and high > address_;
        }

        std::uint64_t data() const { return data_; }
        std::uint64_t previous_data() const { return previous_data_; }

        void update_data();

    private:
        friend process;
        watchpoint(
            process& proc, virt_addr address,
            stoppoint_mode mode, std::size_t size);

        id_type id_;
        process* process_;
        virt_addr address_;
        stoppoint_mode mode_;
        std::size_t size_;
        bool is_enabled_;
        int hardware_register_index_ = -1;

        std::uint64_t data_ = 0;
        std::uint64_t previous_data_ = 0;
    };
}

#endif