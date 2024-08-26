#include <Zydis/Zydis.h>
#include <libsdb/disassembler.hpp>

std::vector<sdb::disassembler::instruction> sdb::disassembler::disassemble(
    std::size_t n_instructions,
    std::optional<virt_addr> address) {
    std::vector<instruction> ret;
    ret.reserve(n_instructions);

    if (!address) {
        address.emplace(process_->get_pc());
    }
    auto code = process_->read_memory_without_traps(
        *address, n_instructions * 15);

    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instr;

    while (ZYAN_SUCCESS(ZydisDisassembleATT(
        ZYDIS_MACHINE_MODE_LONG_64, address->addr(),
        code.data() + offset, code.size() - offset, &instr))
        and n_instructions > 0)
    {
        ret.push_back(instruction{ *address, std::string(instr.text) });
        offset += instr.info.length;
        *address += instr.info.length;
        --n_instructions;
    }

    return ret;
}