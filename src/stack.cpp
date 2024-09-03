#include <libsdb/stack.hpp>
#include <libsdb/target.hpp>

std::vector<sdb::die>
sdb::stack::inline_stack_at_pc() const {
    auto pc = target_->get_pc_file_address();
    if (!pc.elf_file()) return {};
    return pc.elf_file()->get_dwarf().inline_stack_at_address(pc);
}

void sdb::stack::reset_inline_height() {
    auto stack = inline_stack_at_pc();

    inline_height_ = 0;
    auto pc = target_->get_pc_file_address();
    for (auto it = stack.rbegin();
        it != stack.rend() and it->low_pc() == pc;
        ++it) {
        ++inline_height_;
    }
}