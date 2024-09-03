#ifndef SDB_STACK_HPP
#define SDB_STACK_HPP

#include <vector>
#include <libsdb/dwarf.hpp>

namespace sdb {
    class target;
    class stack {
    public:
        stack(target* tgt) : target_(tgt) {}
        void reset_inline_height();
        std::vector<sdb::die> inline_stack_at_pc() const;
        std::uint32_t inline_height() const { return inline_height_; }
        const target& get_target() const { return *target_; }
        void simulate_inlined_step_in() {
            --inline_height_;
        }

    private:
        target* target_ = nullptr;
        std::uint32_t inline_height_ = 0;
    };
}

#endif