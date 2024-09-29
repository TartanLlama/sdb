#include <libsdb/target.hpp>
#include <libsdb/types.hpp>
#include <csignal>
#include <optional>
#include <libsdb/disassembler.hpp>
#include <libsdb/bit.hpp>
#include <cxxabi.h>
#include <fstream>
#include <libsdb/type.hpp>
#include <libsdb/parse.hpp>

namespace {
    std::filesystem::path dump_vdso(
        const sdb::process& proc, sdb::virt_addr address) {
        char tmp_dir[] = "/tmp/sdb-XXXXXX";
        mkdtemp(tmp_dir);
        auto vdso_dump_path = std::filesystem::path(tmp_dir) / "linux-vdso.so.1";
        std::ofstream vdso_dump(vdso_dump_path, std::ios::binary);

        auto vdso_header = proc.read_memory_as<Elf64_Ehdr>(address);
        auto vdso_size = vdso_header.e_shoff +
            vdso_header.e_shentsize * vdso_header.e_shnum;
        auto vdso_bytes = proc.read_memory(address, vdso_size);
        vdso_dump.write(
            reinterpret_cast<const char*>(vdso_bytes.data()), vdso_bytes.size());
        return vdso_dump_path;
    }

    std::unique_ptr<sdb::elf> create_loaded_elf(
        const sdb::process& proc, const std::filesystem::path& path) {
        auto auxv = proc.get_auxv();
        auto obj = std::make_unique<sdb::elf>(path);
        obj->notify_loaded(
            sdb::virt_addr(auxv[AT_ENTRY] - obj->get_header().e_entry));
        return obj;
    }
}

std::unique_ptr<sdb::target>
sdb::target::launch(
    std::filesystem::path path, std::optional<int> stdout_replacement) {
    auto proc = process::launch(path, true, stdout_replacement);
    auto obj = create_loaded_elf(*proc, path);
    auto tgt = std::unique_ptr<target>(
        new target(std::move(proc), std::move(obj)));
    tgt->get_process().set_target(tgt.get());
    auto entry_point = virt_addr{ tgt->get_process().get_auxv()[AT_ENTRY] };
    auto& entry_bp = tgt->create_address_breakpoint(entry_point, false, true);
    entry_bp.install_hit_handler([target = tgt.get()] {
        target->resolve_dynamic_linker_rendezvous();
        return true;
        });
    entry_bp.enable();
    return tgt;
}

std::unique_ptr<sdb::target>
sdb::target::attach(pid_t pid) {
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc = process::attach(pid);
    auto obj = create_loaded_elf(*proc, elf_path);
    auto tgt = std::unique_ptr<target>(
        new target(std::move(proc), std::move(obj)));
    tgt->get_process().set_target(tgt.get());
    tgt->resolve_dynamic_linker_rendezvous();
    return tgt;
}

sdb::file_addr sdb::target::get_pc_file_address(
    std::optional<pid_t> otid) const {
    return process_->get_pc(otid).to_file_addr(elves_);
}

void sdb::target::notify_stop(const sdb::stop_reason& reason) {
    threads_.at(reason.tid).frames.unwind();
}

sdb::stop_reason sdb::target::step_in(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto& thread = threads_.at(tid);
    if (stack.inline_height() > 0) {
        stack.simulate_inlined_step_in();
        stop_reason reason (tid, process_state::stopped, SIGTRAP, trap_type::single_step);
        thread.state->reason = reason;
        return reason;
    }

    auto orig_line = line_entry_at_pc(tid);
    do {
        auto reason = process_->step_instruction(tid);
        if (!reason.is_step()) return reason;
    } while ((line_entry_at_pc(tid) == orig_line
        or line_entry_at_pc(tid)->end_sequence)
        and line_entry_at_pc(tid) != line_table::iterator{});

    auto pc = get_pc_file_address(tid);
    if (pc.elf_file() != nullptr) {
        auto& dwarf = pc.elf_file()->get_dwarf();
        auto func = dwarf.function_containing_address(pc);
        if (func and func->low_pc() == pc) {
            auto line = line_entry_at_pc();
            if (line != line_table::iterator{}) {
                ++line;
                return run_until_address(line->address.to_virt_addr(), tid);
            }
        }
    }

    stop_reason reason(
        tid, process_state::stopped, SIGTRAP, trap_type::single_step);
    thread.state->reason = reason;
    return reason;
}

sdb::line_table::iterator
sdb::target::line_entry_at_pc(std::optional<pid_t> otid) const {
    auto pc = get_pc_file_address(otid);
    if (!pc.elf_file()) return line_table::iterator();
    auto cu = pc.elf_file()->get_dwarf().compile_unit_containing_address(pc);
    if (!cu) return line_table::iterator();
    return cu->lines().get_entry_by_address(pc);
}

sdb::stop_reason sdb::target::run_until_address(
    virt_addr address, std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    breakpoint_site* breakpoint_to_remove = nullptr;
    if (!process_->breakpoint_sites().contains_address(address)) {
        breakpoint_to_remove = &process_->create_breakpoint_site(
            address, false, true);
        breakpoint_to_remove->enable();
    }

    process_->resume(tid);
    auto reason = process_->wait_on_signal(tid);
    if (reason.is_breakpoint()
        and process_->get_pc(tid) == address) {
        reason.trap_reason = trap_type::single_step;
    }

    if (breakpoint_to_remove) {
        process_->breakpoint_sites().remove_by_address(
            breakpoint_to_remove->address());
    }

    threads_.at(tid).state->reason = reason;
    return reason;
}


sdb::stop_reason sdb::target::step_over(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& thread = threads_.at(tid);
    auto& stack = get_stack(tid);
    auto orig_line = line_entry_at_pc(tid);
    disassembler disas(*process_);
    sdb::stop_reason reason;
    do {
        auto inline_stack = stack.inline_stack_at_pc();
        auto at_start_of_inline_frame = stack.inline_height() > 0;

        if (at_start_of_inline_frame) {
            auto frame_to_skip = inline_stack[inline_stack.size() - stack.inline_height()];
            auto return_address = frame_to_skip.high_pc().to_virt_addr();
            reason = run_until_address(return_address, tid);
            if (!reason.is_step()
                or process_->get_pc(tid) != return_address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else if (auto instructions = disas.disassemble(2, process_->get_pc(tid));
            instructions[0].text.rfind("call") == 0) {
            reason = run_until_address(instructions[1].address);
            if (!reason.is_step()
                or process_->get_pc(tid) != instructions[1].address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else {
            reason = process_->step_instruction(tid);
            if (!reason.is_step()) {
                thread.state->reason = reason;
                return reason;
            }
        }
    } while ((line_entry_at_pc(tid) == orig_line
        or line_entry_at_pc(tid)->end_sequence)
        and line_entry_at_pc(tid) != line_table::iterator{});
    thread.state->reason = reason;
    return reason;
}

sdb::stop_reason sdb::target::step_out(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto inline_stack = stack.inline_stack_at_pc();
    auto has_inline_frames = inline_stack.size() > 1;
    auto at_inline_frame = stack.inline_height() < inline_stack.size() - 1;

    if (has_inline_frames and at_inline_frame) {
        auto current_frame = inline_stack[inline_stack.size() - stack.inline_height() - 1];
        auto return_address = current_frame.high_pc().to_virt_addr();
        return run_until_address(return_address, tid);
    }

	auto& regs = stack.frames()[stack.current_frame_index() + 1].regs;
	virt_addr return_address{ regs.read_by_id_as<std::uint64_t>(register_id::rip) };

    sdb::stop_reason reason;
    for (auto frames = stack.frames().size();
        stack.frames().size() >= frames;) {
        reason = run_until_address(return_address, tid);
        if (!reason.is_breakpoint()
            or process_->get_pc() != return_address) {
            return reason;
        }
    }
    return reason;
}

sdb::target::find_functions_result
sdb::target::find_functions(std::string name) const {
    find_functions_result result;

    elves_.for_each([&](auto& elf) {
        auto dwarf_found = elf.get_dwarf().find_functions(name);
        if (dwarf_found.empty()) {
            auto elf_found = elf.get_symbols_by_name(name);
            for (auto sym : elf_found) {
                result.elf_functions.push_back(std::pair{ &elf, sym });
            }
        }
        else {
            result.dwarf_functions.insert(
                result.dwarf_functions.end(),
                dwarf_found.begin(), dwarf_found.end());
        }
        });

    return result;
}

sdb::breakpoint&
sdb::target::create_address_breakpoint(
    virt_addr address, bool hardware, bool internal) {
    return breakpoints_.push(
        std::unique_ptr<address_breakpoint>(
            new address_breakpoint(
                *this, address, hardware, internal)));
}

sdb::breakpoint&
sdb::target::create_function_breakpoint(
    std::string function_name, bool hardware, bool internal) {
    return breakpoints_.push(
        std::unique_ptr<function_breakpoint>(
            new function_breakpoint(
                *this, function_name, hardware, internal)));
}

sdb::breakpoint&
sdb::target::create_line_breakpoint(
    std::filesystem::path file, std::size_t line,
    bool hardware, bool internal) {
    return breakpoints_.push(
        std::unique_ptr<line_breakpoint>(
            new line_breakpoint(
                *this, file, line, hardware, internal)));
}

std::string sdb::target::function_name_at_address(virt_addr address) const {
    auto file_address = address.to_file_addr(elves_);
    auto obj = file_address.elf_file();
    if (!obj) return "";
    auto func = obj->get_dwarf().function_containing_address(file_address);
    auto elf_filename = obj->path().filename().string();
    std::string func_name = "";

    if (func and func->name()) {
        func_name = *func->name();
    }
    else if (auto elf_func = obj->get_symbol_containing_address(file_address);
        elf_func and ELF64_ST_TYPE(elf_func.value()->st_info) == STT_FUNC) {
        func_name = obj->get_string(elf_func.value()->st_name);
    }

    if (!func_name.empty()) {
        return elf_filename + "`" + func_name;
    }
    return "";
}

void sdb::target::resolve_dynamic_linker_rendezvous() {
    if (dynamic_linker_rendezvous_address_.addr()) return;

    auto dynamic_section = main_elf_->get_section(".dynamic");
    auto dynamic_start = file_addr{ *main_elf_, dynamic_section.value()->sh_addr };
    auto dynamic_size = dynamic_section.value()->sh_size;
    auto dynamic_bytes = process_->read_memory(
        dynamic_start.to_virt_addr(), dynamic_size);

    std::vector<Elf64_Dyn> dynamic_entries(
        dynamic_size / sizeof(Elf64_Dyn));
    std::copy(dynamic_bytes.begin(), dynamic_bytes.end(),
        reinterpret_cast<std::byte*>(dynamic_entries.data()));

    for (auto entry : dynamic_entries) {
        if (entry.d_tag == DT_DEBUG) {
            dynamic_linker_rendezvous_address_ = sdb::virt_addr{ entry.d_un.d_ptr };
            reload_dynamic_libraries();

            auto debug_info = read_dynamic_linker_rendezvous();
            auto debug_state_addr = sdb::virt_addr{ debug_info->r_brk };
            auto& debug_state_bp = create_address_breakpoint(
                debug_state_addr, false, true);
            debug_state_bp.install_hit_handler([&] {
                reload_dynamic_libraries();
                return true;
                });
            debug_state_bp.enable();
        }
    }
}

std::vector<sdb::line_table::iterator> sdb::target::get_line_entries_by_line(
    std::filesystem::path path, std::size_t line) const {
    std::vector<sdb::line_table::iterator> entries;
    elves_.for_each([&](auto& elf) {
        for (auto& cu : elf.get_dwarf().compile_units()) {
            auto new_entries = cu->lines().get_entries_by_line(path, line);
            entries.insert(entries.end(), new_entries.begin(), new_entries.end());
        }
        });
    return entries;
}

std::optional<r_debug>
sdb::target::read_dynamic_linker_rendezvous() const {
    if (dynamic_linker_rendezvous_address_.addr()) {
        return process_->read_memory_as<r_debug>(
            dynamic_linker_rendezvous_address_);
    }
    return std::nullopt;
}

void sdb::target::reload_dynamic_libraries() {
    auto debug = read_dynamic_linker_rendezvous();
    if (!debug) return;

    auto entry_ptr = debug->r_map;
    while (entry_ptr != nullptr) {
        auto entry_addr = virt_addr(
            reinterpret_cast<std::uint64_t>(entry_ptr));
        auto entry = process_->read_memory_as<link_map>(entry_addr);
        entry_ptr = entry.l_next;
        auto name_addr = virt_addr(
            reinterpret_cast<std::uint64_t>(entry.l_name));
        auto name_bytes = process_->read_memory(name_addr, 4096);
        auto name = std::filesystem::path{
            reinterpret_cast<char*>(name_bytes.data()) };
        if (name.empty()) continue;
        const elf* found = nullptr;
        const auto vdso_name = "linux-vdso.so.1";
        if (name == vdso_name) {
            found = elves_.get_elf_by_filename(name.c_str());
        }
        else {
            found = elves_.get_elf_by_path(name);
        }
        if (!found) {
            if (name == vdso_name) {
                name = dump_vdso(*process_, virt_addr{ entry.l_addr });

            }
            auto new_elf = std::make_unique<elf>(name);
            new_elf->notify_loaded(virt_addr{ entry.l_addr });
            elves_.push(std::move(new_elf));
        }
    }
    breakpoints_.for_each([&](auto& bp) {
        bp.resolve();
        });
}

void sdb::target::notify_thread_lifecycle_event(
    const stop_reason& reason) {
    auto tid = reason.tid;
    if (reason.reason == process_state::stopped) {
        auto& state = process_->thread_states()[tid];
        threads_.emplace(
            tid, thread{ &state, stack{this, tid} });
    }
    else {
        threads_.erase(tid);
    }
}

std::vector<std::byte> sdb::target::read_location_data(
    const dwarf_expression::result& loc, std::size_t size,
    std::optional<pid_t> otid) const {
    auto tid = otid.value_or(process_->current_thread());
    if (auto simple_loc = std::get_if<sdb::dwarf_expression::simple_location>(&loc)) {
        if (auto reg_loc = std::get_if<sdb::dwarf_expression::register_result>(simple_loc)) {
            auto reg_info = register_info_by_dwarf(reg_loc->reg_num);
            auto reg_value = threads_.at(tid).frames.current_frame().regs.read(reg_info);
            auto get_bytes = [](auto value) {
                std::vector<std::byte> bytes(sizeof(value));
                auto begin = reinterpret_cast<const std::byte*>(&value);
                std::copy(begin, begin + sizeof(value), bytes.data());
                return bytes;
                };
            return std::visit(get_bytes, reg_value);
        }
        else if (
            auto addr_res = std::get_if<sdb::dwarf_expression::address_result>(simple_loc)) {
            return process_->read_memory(addr_res->address, size);
        }
        else if (auto data_res = std::get_if<sdb::dwarf_expression::data_result>(simple_loc)) {
            return { data_res->data.begin(), data_res->data.end() };
        }
        else if (
            auto literal_res = std::get_if<sdb::dwarf_expression::literal_result>(simple_loc)) {
            auto begin = reinterpret_cast<const std::byte*>(&literal_res->value);
            return { begin, begin + size };
        }
    }
    else if (auto pieces_res = std::get_if<sdb::dwarf_expression::pieces_result>(&loc)) {
        std::vector<std::byte> data(size);
        std::size_t offset = 0;
        for (auto& piece : pieces_res->pieces) {
            auto byte_size = (piece.bit_size + 7) / 8;
            auto piece_data = read_location_data(piece.location, byte_size, otid);
            if (offset % 8 == 0 and piece.offset == 0 and piece.bit_size % 8 == 0) {
                std::copy(piece_data.begin(), piece_data.end(), data.begin() + offset / 8);
                offset += piece.bit_size;
            }
            else {
                auto dest = reinterpret_cast<std::uint8_t*>(data.data());
                auto src = reinterpret_cast<const std::uint8_t*>(piece_data.data());
                memcpy_bits(dest, 0, src, piece.offset, piece.bit_size);
            }
        }

        return data;
    }
    sdb::error::send("Invalid location type");
}

std::optional<sdb::die> sdb::target::find_variable(
    std::string name, sdb::file_addr pc) const {
    auto& dwarf = pc.elf_file()->get_dwarf();
    auto local = dwarf.find_local_variable(name, pc);
    if (local) return local;

    std::optional<die> global = std::nullopt;
    elves_.for_each([&](auto& elf) {
        auto& dwarf = elf.get_dwarf();
        auto found = dwarf.find_global_variable(name);
        if (found) {
            global = *found;
        }
    });
    return global;
}

namespace {
    sdb::typed_data get_initial_variable_data(
        const sdb::target& target, std::string name, sdb::file_addr pc) {
        auto var = target.find_variable(name, pc);
        if (!var) {
            sdb::error::send("Variable not found");
        }
        auto var_type = var.value()[DW_AT_type].as_type();

        auto loc = var.value()[DW_AT_location].as_evaluated_location(
            target.get_process(), target.get_stack().current_frame().regs);
        auto data_vec = target.read_location_data(loc, var_type.byte_size());

        std::optional<sdb::virt_addr> address;
        if (auto single_loc = std::get_if<sdb::dwarf_expression::simple_location>(&loc)) {
            if (auto addr_res = std::get_if<sdb::dwarf_expression::address_result>(single_loc)) {
                address = addr_res->address;
            }
        }
        return { std::move(data_vec), var_type, address };
    }
}

sdb::typed_data sdb::target::resolve_indirect_name(
    std::string name, sdb::file_addr pc) const {
    auto op_pos = name.find_first_of(".-[");

    auto var_name = name.substr(0, op_pos);
    auto& dwarf = pc.elf_file()->get_dwarf();

    auto data = get_initial_variable_data(*this, var_name, pc);

    while (op_pos != std::string::npos) {
        if (name[op_pos] == '-') {
            if (name[op_pos + 1] != '>') {
                sdb::error::send("Invalid operator");
            }
            data = data.deref_pointer(get_process());
            op_pos++;
        }
        if (name[op_pos] == '.' or name[op_pos] == '>') {
            auto member_name_start = op_pos + 1;
            op_pos = name.find_first_of(".-[", member_name_start);
            auto member_name = name.substr(
                member_name_start, op_pos - member_name_start);
            data = data.read_member(get_process(), member_name);
            name = name.substr(member_name_start);
        }
         else if (name[op_pos] == '[') {
            auto int_end = name.find(']', op_pos);
            auto index_str = name.substr(op_pos + 1, int_end - op_pos - 1);
            char* end;
            auto index = to_integral<std::size_t>(index_str);
            if (!index) {
                sdb::error::send("Invalid index");
            }
            data = data.index(get_process(), *index);
            name = name.substr(int_end + 1);
        }
        op_pos = name.find_first_of(".-[");
    }

    return data;
}