#ifndef SDB_TARGET_HPP
#define SDB_TARGET_HPP

#include <memory>
#include <libsdb/elf.hpp>
#include <libsdb/process.hpp>
#include <libsdb/stack.hpp>
#include <libsdb/dwarf.hpp>
#include <libsdb/breakpoint.hpp>
#include <link.h>

namespace sdb {
    class target {
    public:
        target() = delete;
        target(const target&) = delete;
        target& operator=(const target&) = delete;

        static std::unique_ptr<target> launch(
            std::filesystem::path path,
            std::optional<int> stdout_replacement = std::nullopt);
        static std::unique_ptr<target> attach(pid_t pid);

        process& get_process() { return *process_; }
        const process& get_process() const { return *process_; }
        void notify_stop(const sdb::stop_reason& reason);
        file_addr get_pc_file_address() const;

        stack& get_stack() { return stack_; }
        const stack& get_stack() const { return stack_; }

        sdb::stop_reason step_in();
        sdb::stop_reason step_out();
        sdb::stop_reason step_over();

        sdb::line_table::iterator line_entry_at_pc() const;
        sdb::stop_reason run_until_address(virt_addr address);

        struct find_functions_result {
            std::vector<die> dwarf_functions;
            std::vector<std::pair<const elf*, const Elf64_Sym*>> elf_functions;
        };
        find_functions_result find_functions(std::string name) const;

        breakpoint& create_address_breakpoint(
            virt_addr address,
            bool hardware = false, bool internal = false);
        breakpoint& create_function_breakpoint(
            std::string function_name,
            bool hardware = false, bool internal = false);
        breakpoint& create_line_breakpoint(
            std::filesystem::path file, std::size_t line,
            bool hardware = false, bool internal = false);


        stoppoint_collection<breakpoint>&
            breakpoints() { return breakpoints_; }
        const stoppoint_collection<breakpoint>&
            breakpoints() const { return breakpoints_; }

        std::string function_name_at_address(
            virt_addr address) const;

        std::optional<r_debug> read_dynamic_linker_rendezvous() const;

        elf_collection& get_elves() { return elves_; }
        const elf_collection& get_elves() const { return elves_; }
        elf& get_main_elf() { return *main_elf_; }
        const elf& get_main_elf() const { return *main_elf_; }

        std::vector<line_table::iterator> get_line_entries_by_line(
            std::filesystem::path path, std::size_t line) const;
    private:
        target(std::unique_ptr<process> proc, std::unique_ptr<elf> obj)
            : process_(std::move(proc))
            , stack_(this)
            , main_elf_(obj.get()) {
            elves_.push(std::move(obj));
        }

        void resolve_dynamic_linker_rendezvous();
        void reload_dynamic_libraries();

        std::unique_ptr<process> process_;
        elf_collection elves_;
        elf* main_elf_;
        stack stack_;
        stoppoint_collection<breakpoint> breakpoints_;
        virt_addr dynamic_linker_rendezvous_address_;
    };
}

#endif