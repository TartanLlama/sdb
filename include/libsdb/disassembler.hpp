#ifndef SDB_DISASSEMBLER_HPP
#define SDB_DISASSEMBLER_HPP

#include <libsdb/process.hpp>
#include <optional>

namespace sdb {
    class disassembler {
        struct instruction {
            virt_addr address;
            std::string text;
        };

    public:
        disassembler(process& proc) : process_(&proc) {}

        std::vector<instruction> disassemble(
            std::size_t n_instructions,
            std::optional<virt_addr> address = std::nullopt);

    private:
        process* process_;
    };
}

#endif