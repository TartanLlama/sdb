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
        stop_reason reason(tid, process_state::stopped, SIGTRAP, trap_type::single_step);
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
        if (name[0] == '$') {
            auto index = sdb::to_integral<std::size_t>(name.substr(1));
            if (!index) {
                sdb::error::send("Invalid expression result index");
            }
            return target.get_expression_result(*index);
        }
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

    sdb::typed_data parse_argument(
        sdb::target& target, pid_t tid, std::string_view arg) {
        if (arg.empty()) {
            sdb::error::send("Empty argument");
        }
        if (arg.size() > 2 and arg[0] == '"' and arg[arg.size() - 1] == '"') {
            auto ptr = target.inferior_malloc(arg.size() - 1);
            std::string arg_str{ arg.substr(1, arg.size() - 2) };
            auto data_ptr = reinterpret_cast<const std::byte*>(arg_str.data());
            sdb::span<const std::byte> data = {
                data_ptr, arg_str.size() + 1 };
            target.get_process().write_memory(ptr, data);
            return { sdb::to_byte_vec(ptr), sdb::builtin_type::string };
        }
        else if (arg == "true" or arg == "false") {
            auto value = arg == "true";
            return { sdb::to_byte_vec(value), sdb::builtin_type::boolean };
        }
        else if (arg[0] == '\'') {
            if (arg.size() != 3 or arg[2] != '\'') {
                sdb::error::send("Invalid character literal");
            }
            return { sdb::to_byte_vec(arg[1]), sdb::builtin_type::character };
        }
        else if (arg[0] == '-' or std::isdigit(arg[0])) {
            if (arg.find(".") != std::string::npos) {
                auto value = sdb::to_float<double>(arg);
                if (!value) {
                    sdb::error::send("Invalid floating point literal");
                }
                return { sdb::to_byte_vec(*value), sdb::builtin_type::floating_point };
            }
            else {
                auto value = sdb::to_integral<std::int64_t>(arg);
                if (!value) {
                    sdb::error::send("Invalid integer literal");
                }
                return { sdb::to_byte_vec(*value), sdb::builtin_type::integer };
            }
        }
        else {
            auto pc = target.get_pc_file_address(tid);
            auto res = target.resolve_indirect_name(std::string(arg), pc);
            if (!res.funcs.empty()) {
                sdb::error::send("Nested function calls not supported");
            }
            return *res.variable;
        }
    }

    std::vector<sdb::typed_data> collect_arguments(
        sdb::target& target, pid_t tid, std::string_view arg_string,
        const std::vector<sdb::die>& funcs,
        std::optional<sdb::typed_data> object) {
        std::vector<sdb::typed_data> args;
        auto& proc = target.get_process();

        if (object) {
            std::vector<std::byte> data;
            if (object->address()) {
                data = sdb::to_byte_vec(*object->address());
            }
            else {
                auto& regs = proc.get_registers(tid);
                auto rsp = regs.read_by_id_as<std::uint64_t>(sdb::register_id::rsp);
                rsp -= object->value_type().byte_size();
                proc.write_memory(sdb::virt_addr{ rsp }, object->data());
                regs.write_by_id(sdb::register_id::rsp, rsp, true);
                data = sdb::to_byte_vec(rsp);
            }
            auto obj_ptr_die = funcs[0][DW_AT_object_pointer].as_reference();
            auto this_type = obj_ptr_die[DW_AT_type].as_type();
            args.push_back({ std::move(data), this_type });
        }

        auto args_start = 1;
        auto args_end = arg_string.find(')');

        while (args_start < args_end) {
            auto comma_pos = arg_string.find(',', args_start);
            if (comma_pos == std::string::npos) {
                comma_pos = args_end;
            }
            auto arg_expr = arg_string.substr(args_start, comma_pos - args_start);
            args.push_back(parse_argument(target, tid, arg_expr));
            args_start = comma_pos + 1;
        }
        return args;
    }

    sdb::die resolve_overload(
        const std::vector<sdb::die>& funcs,
        const std::vector<sdb::typed_data>& args) {
        std::optional<sdb::die> matching_func;
        for (auto& func : funcs) {
            bool matches = true;
            auto arg_it = args.begin();
            auto params = func.parameter_types();

            if (args.size() == params.size()) {
                for (auto param_it = params.begin();
                    arg_it != args.end();
                    ++param_it, ++arg_it) {
                    if (*param_it != arg_it->value_type()) {
                        matches = false;
                        break;
                    }
                }
            }
            else {
                matches = false;
            }

            if (matches) {
                if (matching_func) sdb::error::send("Ambiguous function call");
                matching_func = func;
            }
        }
        if (!matching_func) sdb::error::send("No matching function");
        return *matching_func;
    }



    void setup_arguments(
        sdb::target& target, sdb::die func,
        std::vector<sdb::typed_data> args,
        sdb::registers& regs,
        std::optional<sdb::virt_addr> return_slot) {
        std::array<sdb::register_id, 6> int_regs = {
            sdb::register_id::rdi,
            sdb::register_id::rsi,
            sdb::register_id::rdx,
            sdb::register_id::rcx,
            sdb::register_id::r8,
            sdb::register_id::r9
        };

        std::array<sdb::register_id, 8> sse_regs = {
            sdb::register_id::xmm0,
            sdb::register_id::xmm1,
            sdb::register_id::xmm2,
            sdb::register_id::xmm3,
            sdb::register_id::xmm4,
            sdb::register_id::xmm5,
            sdb::register_id::xmm6,
            sdb::register_id::xmm7
        };

        auto current_int_reg = 0;
        auto current_sse_reg = 0;
        struct stack_arg {
            sdb::typed_data data;
            std::size_t size;
        };
        auto stack_args = std::vector<stack_arg>{};
        auto rsp = regs.read_by_id_as<std::uint64_t>(sdb::register_id::rsp);

        auto round_up_to_eightbyte = [](std::size_t size) {
            return (size + 7) & ~7;
            };

        if (func.contains(DW_AT_type)) {
            auto ret_type = func[DW_AT_type].as_type();
            auto ret_class = ret_type.get_parameter_classes()[0];
            if (ret_class == sdb::parameter_class::memory) {
                current_int_reg++;
                regs.write_by_id(int_regs[0], return_slot->addr(), true);
            }
        }

        auto params = func.parameter_types();
        for (auto i = 0; i < params.size(); ++i) {
            auto& param = params[i];
            auto param_classes = param.get_parameter_classes();

            if (param.is_reference_type()) {
                if (args[i].address()) {
                    args[i] = sdb::typed_data{
                        sdb::to_byte_vec(*args[i].address()),
                        sdb::builtin_type::integer };
                }
                else {
                    rsp -= args[i].value_type().byte_size();
                    rsp &= ~(args[i].value_type().alignment() - 1);
                    target.get_process().write_memory(
                        sdb::virt_addr{ rsp }, args[i].data());
                    args[i] = sdb::typed_data{
                        sdb::to_byte_vec(rsp),
                        sdb::builtin_type::integer };
                }
            }
        }

        for (auto i = 0; i < params.size(); ++i) {
            auto& arg = args[i];
            auto& param = params[i];
            auto param_classes = params[i].get_parameter_classes();
            auto param_size = param.byte_size();

            auto required_int_regs = std::count(
                param_classes.begin(), param_classes.end(),
                sdb::parameter_class::integer);
            auto required_sse_regs = std::count(
                param_classes.begin(), param_classes.end(),
                sdb::parameter_class::sse);

            if (current_int_reg + required_int_regs > int_regs.size() or
                current_sse_reg + required_sse_regs > sse_regs.size() or
                (required_int_regs == 0 and required_sse_regs == 0)) {
                auto size = round_up_to_eightbyte(param_size);
                stack_args.push_back({ args[i], size });
            }
            else {
                for (auto i = 0; i < param_size; i += 8) {
                    sdb::register_id reg;
                    switch (param_classes[i / 8]) {
                    case sdb::parameter_class::integer:
                        reg = int_regs[current_int_reg++];
                        break;
                    case sdb::parameter_class::sse:
                        reg = sse_regs[current_sse_reg++];
                        break;
                    case sdb::parameter_class::no_class:
                        break;
                    default:
                        sdb::error::send("Unsupported parameter class");
                    }

                    sdb::byte64 data;
                    std::copy(
                        arg.data().begin() + i,
                        arg.data().begin() + i + 8,
                        data.begin());
                    regs.write_by_id(reg, data, true);
                }
            }
        }
        for (auto& [_, size] : stack_args) {
            rsp -= size;
        }
        rsp &= ~0xf;

        auto start_pos = rsp;
        for (auto& [arg, size] : stack_args) {
            target.get_process().write_memory(
                sdb::virt_addr{ start_pos }, arg.data());
            start_pos += size;
        }
        regs.write_by_id(sdb::register_id::rax, current_sse_reg, true);
        regs.write_by_id(sdb::register_id::rsp, rsp, true);
    }

    sdb::typed_data read_return_value(
        sdb::target& target, sdb::die func,
        sdb::virt_addr return_slot, sdb::registers& regs) {
        auto ret_type = func[DW_AT_type].as_type();
        auto ret_classes = ret_type.get_parameter_classes();

        bool used_int = false;
        bool used_sse = false;

        if (ret_classes[0] == sdb::parameter_class::memory) {
            auto value = target.get_process().read_memory(
                return_slot, ret_type.byte_size());
            return { sdb::typed_data{
                std::move(value), func[DW_AT_type].as_type(), return_slot } };
        }

        if (ret_classes[0] == sdb::parameter_class::x87) {
            auto data = regs.read_by_id_as<long double>(sdb::register_id::st0);
            auto value = sdb::to_byte_vec(data);
            target.get_process().write_memory(return_slot, value);
            return { sdb::typed_data{
                std::move(value), func[DW_AT_type].as_type(), return_slot } };
        }

        std::vector<std::byte> value;
        for (auto ret_class : ret_classes) {
            if (ret_class == sdb::parameter_class::integer) {
                auto reg = used_int ? sdb::register_id::rdx : sdb::register_id::rax;
                used_int = true;
                auto data = regs.read_by_id_as<std::uint64_t>(reg);
                auto new_value = sdb::to_byte_vec(data);
                value.insert(value.end(), new_value.begin(), new_value.end());
            }
            else if (ret_class == sdb::parameter_class::sse) {
                auto reg = used_sse ? sdb::register_id::xmm1 : sdb::register_id::xmm0;
                used_sse = true;
                auto data = regs.read_by_id_as<sdb::byte128>(reg);
                value = { data.begin(), data.end() };
                target.get_process().write_memory(return_slot, value);
            }
            else if (ret_class != sdb::parameter_class::no_class) {
                sdb::error::send("Unsupported return type");
            }
        }

        target.get_process().write_memory(return_slot, value);
        return { sdb::typed_data{
            std::move(value), func[DW_AT_type].as_type(), return_slot } };
    }


    std::optional<sdb::typed_data> inferior_call_from_dwarf(
        sdb::target& target, sdb::die func,
        const std::vector<sdb::typed_data>& args,
        sdb::virt_addr return_addr, pid_t tid) {
        auto& regs = target.get_process().get_registers(tid);
        auto saved_regs = regs;

        sdb::virt_addr call_addr;
        if (func.contains(DW_AT_low_pc) or func.contains(DW_AT_ranges)) {
            call_addr = func.low_pc().to_virt_addr();
        }
        else {
            auto def = func.cu()->dwarf_info()->get_member_function_definition(func);
            if (!def) {
                sdb::error::send("No function definition found");
            }
            call_addr = def->low_pc().to_virt_addr();
        }

        std::optional<sdb::virt_addr> return_slot;
        if (func.contains(DW_AT_type)) {
            auto ret_type = func[DW_AT_type].as_type();
            return_slot = target.inferior_malloc(ret_type.byte_size());
        }

        setup_arguments(target, func, args, regs, return_slot);
        auto new_regs = target.get_process().inferior_call(
            call_addr, return_addr, saved_regs, tid);

        if (func.contains(DW_AT_type)) {
            return read_return_value(
                target, func, *return_slot, new_regs);
        }
        return std::nullopt;
    }
}

sdb::target::resolve_indirect_name_result
sdb::target::resolve_indirect_name(
    std::string name, sdb::file_addr pc) const {
    auto op_pos = name.find_first_of(".-[(");

    if (name[op_pos] == '(') {
        auto func_name = name.substr(0, op_pos);
        auto funcs = find_functions(func_name);
        return { std::nullopt, std::move(funcs.dwarf_functions) };
    }

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
            op_pos = name.find_first_of(".-[(,", member_name_start);
            auto member_name = name.substr(member_name_start, op_pos - member_name_start);
            if (name[op_pos] == '(') {
                std::vector<die> funcs;
                auto stripped_value_type = data.value_type().strip_cvref_typedef();
                for (auto& child : stripped_value_type.get_die().children()) {
                    if (child.abbrev_entry()->tag == DW_TAG_subprogram and
                        child.contains(DW_AT_object_pointer) and
                        child.name() == member_name) {
                        funcs.push_back(child);
                    }
                }
                if (funcs.empty()) {
                    sdb::error::send("No such member function");
                }
                return { std::move(data), std::move(funcs) };
            }
            data = data.read_member(get_process(), member_name);
            name = name.substr(member_name_start);
        }
        else if (name[op_pos] == '[') {
            auto int_end = name.find(']', op_pos);
            auto index_str = name.substr(op_pos + 1, int_end - op_pos - 1);
            auto index = to_integral<std::size_t>(index_str);
            if (!index) {
                sdb::error::send("Invalid index");
            }
            data = data.index(get_process(), *index);
            name = name.substr(int_end + 1);
        }
        op_pos = name.find_first_of(".-[(");
    }

    return { std::move(data), {} };
}

sdb::virt_addr sdb::target::inferior_malloc(std::size_t size) {
    auto saved_regs = process_->get_registers();

    auto malloc_funcs = find_functions("malloc").elf_functions;
    auto malloc_func = std::find_if(
        malloc_funcs.begin(), malloc_funcs.end(), [](auto& sym) {
            return sym.second->st_value != 0;
        });
    if (malloc_func == malloc_funcs.end()) {
        error::send("malloc not found");
    }

    file_addr malloc_addr{
        *malloc_func->first, malloc_func->second->st_value };
    auto call_addr = malloc_addr.to_virt_addr();

    auto entry_point = virt_addr{ process_->get_auxv()[AT_ENTRY] };
    breakpoints_.get_by_address(entry_point).install_hit_handler([&] {
        return false;
        });

    process_->get_registers().write_by_id(register_id::rdi, size, true);

    auto new_regs = process_->inferior_call(
        call_addr, entry_point, saved_regs);
    auto result = new_regs.read_by_id_as<std::uint64_t>(register_id::rax);

    return virt_addr{ result };
}

std::optional<sdb::target::evaluate_expression_result>
sdb::target::evaluate_expression(
    std::string_view expr, std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto pc = get_pc_file_address(tid);

    auto paren_pos = expr.find('(');
    if (paren_pos == std::string::npos) {
        sdb::error::send("Invalid expression");
    }

    std::string name{ expr.substr(0, paren_pos + 1) };
    auto [variable, funcs] = resolve_indirect_name(name, pc);
    if (funcs.empty()) {
        sdb::error::send("Invalid expression");
    }

    auto entry_point = virt_addr{ process_->get_auxv()[AT_ENTRY] };
    breakpoints_.get_by_address(entry_point).install_hit_handler([&] {
        return false;
        });

    auto arg_string = expr.substr(paren_pos);
    auto args = collect_arguments(
        *this, tid, arg_string, funcs, variable);
    auto func = resolve_overload(funcs, args);
    auto ret = inferior_call_from_dwarf(
        *this, func, args, entry_point, tid);
    if (ret) {
        expression_results_.push_back(*ret);
        return evaluate_expression_result{
            std::move(*ret), expression_results_.size() - 1
        };
    }
    return std::nullopt;
}

const sdb::typed_data& sdb::target::get_expression_result(
    std::size_t i) const {
    auto& res = expression_results_[i];
    auto new_data = process_->read_memory(
        *res.address(), res.value_type().byte_size());
    res = typed_data{
        std::move(new_data), res.value_type(), res.address() };
    return res;
}