#ifndef SDB_STACK_HPP
#define SDB_STACK_HPP

#include <vector>
#include <libsdb/dwarf.hpp>
#include <libsdb/types.hpp>
#include <libsdb/registers.hpp>

namespace sdb {
    class target;
    struct stack_frame {
        registers regs;
        virt_addr backtrace_report_address;
        die func_die;
        bool inlined = false;
        source_location location;
    };

    class stack {
    public:
        stack(target* tgt) : target_(tgt) {}
        void reset_inline_height();
        std::vector<sdb::die> inline_stack_at_pc() const;
        std::uint32_t inline_height() const { return inline_height_; }
        const target& get_target() const { return *target_; }
        void simulate_inlined_step_in() {
            --inline_height_;
            current_frame_ = inline_height_;
        }

        void unwind();
        void up() { ++current_frame_; }
        void down() { --current_frame_; }

        span<const stack_frame> frames() const;
        bool has_frames() const { return !frames_.empty(); }
        const stack_frame& current_frame() const { return frames_[current_frame_]; }
        std::size_t current_frame_index() const {
            return current_frame_ - inline_height_;
        }

        const registers& regs() const;
        virt_addr get_pc() const;

    private:
        void create_branch_frames(
            const sdb::registers& regs,
            const std::vector<sdb::die> inline_stack,
            file_addr pc);

        void create_leaf_frame(
            const registers& regs,
            const std::vector<sdb::die> inline_stack,
            file_addr pc,
            bool inlined);

        target* target_ = nullptr;
        std::uint32_t inline_height_ = 0;
        std::vector<stack_frame> frames_;
        std::size_t current_frame_ = 0;
    };
}

#endif