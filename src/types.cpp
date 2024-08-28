#include <libsdb/types.hpp>
#include <libsdb/elf.hpp>
#include <cassert>

sdb::virt_addr sdb::file_addr::to_virt_addr() const {
    assert(elf_ && "to_virt_addr called on null address");
    auto section = elf_->get_section_containing_address(*this);
    if (!section) return virt_addr{};
    return virt_addr{ addr_ + elf_->load_bias().addr() };
}

sdb::file_addr sdb::virt_addr::to_file_addr(const elf& obj) const {
    auto section = obj.get_section_containing_address(*this);
    if (!section) return file_addr{};
    return file_addr{ obj, addr_ - obj.load_bias().addr() };
}