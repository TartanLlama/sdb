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
    struct thread {
        thread(thread_state* state, stack frames)
            : state(state), frames(std::move(frames)) {}
        thread_state* state;
        stack frames;
    };

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
        file_addr get_pc_file_address(std::optional<pid_t> otid = std::nullopt) const;

        stack& get_stack(std::optional<pid_t> otid = std::nullopt) {
            auto tid = otid.value_or(process_->current_thread());
            return threads_.at(tid).frames;
        }
        const stack& get_stack(std::optional<pid_t> otid = std::nullopt) const {
            return const_cast<target*>(this)->get_stack(otid);
        }
        sdb::stop_reason step_in(std::optional<pid_t> otid = std::nullopt);
        sdb::stop_reason step_out(std::optional<pid_t> otid = std::nullopt);
        sdb::stop_reason step_over(std::optional<pid_t> otid = std::nullopt);

        sdb::line_table::iterator line_entry_at_pc(std::optional<pid_t> otid = std::nullopt) const;
        sdb::stop_reason run_until_address(virt_addr address, std::optional<pid_t> otid = std::nullopt);

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

        std::unordered_map<pid_t, thread>& threads() {
            return threads_;
        }
        const std::unordered_map<pid_t, thread>& threads() const {
            return threads_;
        }

        void notify_thread_lifecycle_event(const sdb::stop_reason& reason);

        std::vector<std::byte> read_location_data(
            const dwarf_expression::result& loc, std::size_t size,
            std::optional<pid_t> otid = std::nullopt) const;
    private:
        target(std::unique_ptr<process> proc, std::unique_ptr<elf> obj)
            : process_(std::move(proc))
            , main_elf_(obj.get()) {
            elves_.push(std::move(obj));
            auto pid = process_->pid();
            for (auto& [tid, state] : process_->thread_states()) {
                threads_.emplace(tid, thread(&state, stack{ this, tid }));
            }
        }

        void resolve_dynamic_linker_rendezvous();
        void reload_dynamic_libraries();

        std::unique_ptr<process> process_;
        elf_collection elves_;
        elf* main_elf_;
        stoppoint_collection<breakpoint> breakpoints_;
        virt_addr dynamic_linker_rendezvous_address_;
        std::unordered_map<pid_t, thread> threads_;
    };
}

#endif