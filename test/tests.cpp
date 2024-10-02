#include <catch2/catch_test_macros.hpp>
#include <libsdb/process.hpp>
#include <libsdb/error.hpp>
#include <libsdb/pipe.hpp>
#include <libsdb/bit.hpp>
#include <sys/types.h>
#include <signal.h>
#include <fstream>
#include <elf.h>
#include <regex>
#include <libsdb/target.hpp>

using namespace sdb;
namespace {
    bool process_exists(pid_t pid) {
        auto ret = kill(pid, 0);
        return ret != -1 and errno != ESRCH;
    }

    char get_process_status(pid_t pid) {
        std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
        std::string data;
        std::getline(stat, data);
        auto index_of_last_parenthesis = data.rfind(')');
        auto index_of_status_indicator = index_of_last_parenthesis + 2;
        return data[index_of_status_indicator];
    }

    std::int64_t get_entry_point(std::filesystem::path path) {
        std::ifstream elf_file(path);

        Elf64_Ehdr header;
        elf_file.read(reinterpret_cast<char*>(&header), sizeof(header));
        return header.e_entry;
    }

    virt_addr get_load_address(pid_t pid, std::int64_t offset) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::regex map_regex(R"((\w+)-\w+ ..(.). (\w+))");

        std::string data;
        while (std::getline(maps, data)) {
            std::smatch groups;
            std::regex_search(data, groups, map_regex);

            if (groups[2] == 'x') {
                auto low_range = std::stol(groups[1], nullptr, 16);
                auto file_offset = std::stol(groups[3], nullptr, 16);
                return virt_addr(offset - file_offset + low_range);
            }
        }
        sdb::error::send("Could not find load address");
    }
}

TEST_CASE("process::launch success", "[process]") {
    auto proc = process::launch("yes");
    REQUIRE(process_exists(proc->pid()));
}

TEST_CASE("process::launch no such program", "[process]") {
    REQUIRE_THROWS_AS(process::launch("you_do_not_have_to_be_good"), error);
}

TEST_CASE("process::attach success", "[process]") {
    auto target = process::launch("targets/run_endlessly", false);
    auto proc = process::attach(target->pid());
    REQUIRE(get_process_status(target->pid()) == 't');
}

TEST_CASE("process::attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(process::attach(0), error);
}

TEST_CASE("process::resume success", "[process]") {
    {
        auto proc = process::launch("targets/run_endlessly");
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' or status == 'S';
        REQUIRE(success);
    }

    {
        auto target = process::launch("targets/run_endlessly", false);
        auto proc = process::attach(target->pid());
        proc->resume();
        auto status = get_process_status(proc->pid());
        auto success = status == 'R' or status == 'S';
        REQUIRE(success);
    }
}

TEST_CASE("process::resume already terminated", "[process]") {
    auto proc = process::launch("targets/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), error);
}


TEST_CASE("Write register works", "[register]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);

    auto proc = process::launch(
        "targets/reg_write", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    auto& regs = proc->get_registers();
    regs.write_by_id(register_id::rsi, 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    auto output = channel.read();
    REQUIRE(to_string_view(output) == "0xcafecafe");

    regs.write_by_id(register_id::mm0, 0xba5eba11);

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "0xba5eba11");

    regs.write_by_id(register_id::xmm0, 42.24);

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "42.24");

    regs.write_by_id(register_id::st0, 42.24l);
    regs.write_by_id(register_id::fsw,
        std::uint16_t{ 0b0011100000000000 });
    regs.write_by_id(register_id::ftw,
        std::uint16_t{ 0b0011111111111111 });

    proc->resume();
    proc->wait_on_signal();

    output = channel.read();
    REQUIRE(to_string_view(output) == "42.24");
}

TEST_CASE("Read register works", "[register]") {
    auto proc = process::launch("targets/reg_read");
    auto& regs = proc->get_registers();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint64_t>(register_id::r13) ==
        0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<std::uint8_t>(register_id::r13b) == 42);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte64>(register_id::mm0)
        == to_byte64(0xba5eba11ull));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<byte128>(register_id::xmm0) ==
        to_byte128(64.125));

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(regs.read_by_id_as<long double>(register_id::st0) ==
        64.125L);
}

TEST_CASE("Can create breakpoint site", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
    auto& site = proc->create_breakpoint_site(virt_addr{ 42 });
    REQUIRE(site.address().addr() == 42);
}

TEST_CASE("Breakpoint site ids increase", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");

    auto& s1 = proc->create_breakpoint_site(virt_addr{ 42 });
    REQUIRE(s1.address().addr() == 42);

    auto& s2 = proc->create_breakpoint_site(virt_addr{ 43 });
    REQUIRE(s2.id() == s1.id() + 1);

    auto& s3 = proc->create_breakpoint_site(virt_addr{ 44 });
    REQUIRE(s3.id() == s1.id() + 2);

    auto& s4 = proc->create_breakpoint_site(virt_addr{ 45 });
    REQUIRE(s4.id() == s1.id() + 3);
}

TEST_CASE("Can find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    proc->create_breakpoint_site(virt_addr{ 42 });
    proc->create_breakpoint_site(virt_addr{ 43 });
    proc->create_breakpoint_site(virt_addr{ 44 });
    proc->create_breakpoint_site(virt_addr{ 45 });

    auto& s1 = proc->breakpoint_sites().get_by_address(virt_addr{ 44 });
    REQUIRE(proc->breakpoint_sites().contains_address(virt_addr{ 44 }));
    REQUIRE(s1.address().addr() == 44);

    auto& cs1 = cproc->breakpoint_sites().get_by_address(virt_addr{ 44 });
    REQUIRE(cproc->breakpoint_sites().contains_address(virt_addr{ 44 }));
    REQUIRE(cs1.address().addr() == 44);

    auto& s2 = proc->breakpoint_sites().get_by_id(s1.id() + 1);
    REQUIRE(proc->breakpoint_sites().contains_id(s1.id() + 1));
    REQUIRE(s2.id() == s1.id() + 1);
    REQUIRE(s2.address().addr() == 45);

    auto& cs2 = proc->breakpoint_sites().get_by_id(cs1.id() + 1);
    REQUIRE(cproc->breakpoint_sites().contains_id(cs1.id() + 1));
    REQUIRE(cs2.id() == cs1.id() + 1);
    REQUIRE(cs2.address().addr() == 45);
}

TEST_CASE("Cannot find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    REQUIRE_THROWS_AS(
        proc->breakpoint_sites().get_by_address(virt_addr{ 44 }), error);
    REQUIRE_THROWS_AS(proc->breakpoint_sites().get_by_id(44), error);
    REQUIRE_THROWS_AS(
        cproc->breakpoint_sites().get_by_address(virt_addr{ 44 }), error);
    REQUIRE_THROWS_AS(cproc->breakpoint_sites().get_by_id(44), error);
}

TEST_CASE("Breakpoint site list size and emptiness", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    REQUIRE(proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 0);
    REQUIRE(cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 0);

    proc->create_breakpoint_site(virt_addr{ 42 });
    REQUIRE(!proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 1);
    REQUIRE(!cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 1);

    proc->create_breakpoint_site(virt_addr{ 43 });
    REQUIRE(!proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 2);
    REQUIRE(!cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 2);
}

TEST_CASE("Can iterate breakpoint sites", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
    const auto& cproc = proc;

    proc->create_breakpoint_site(virt_addr{ 42 });
    proc->create_breakpoint_site(virt_addr{ 43 });
    proc->create_breakpoint_site(virt_addr{ 44 });
    proc->create_breakpoint_site(virt_addr{ 45 });

    proc->breakpoint_sites().for_each(
        [addr = 42](auto& site) mutable {
            REQUIRE(site.address().addr() == addr++);
        });

    cproc->breakpoint_sites().for_each(
        [addr = 42](auto& site) mutable {
            REQUIRE(site.address().addr() == addr++);
        });
}

TEST_CASE("Breakpoint on address works", "[breakpoint]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);

    auto proc = process::launch("targets/hello_sdb", true, channel.get_write());
    channel.close_write();

    auto offset = get_entry_point("targets/hello_sdb");
    auto load_address = get_load_address(proc->pid(), offset);

    proc->create_breakpoint_site(load_address).enable();
    proc->resume();
    auto reason = proc->wait_on_signal();

    REQUIRE(reason.reason == process_state::stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(proc->get_pc() == load_address);

    proc->resume();
    reason = proc->wait_on_signal();

    REQUIRE(reason.reason == process_state::exited);
    REQUIRE(reason.info == 0);

    auto data = channel.read();
    REQUIRE(to_string_view(data) == "Hello, sdb!\n");
}

TEST_CASE("Can remove breakpoint sites", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");

    auto& site = proc->create_breakpoint_site(virt_addr{ 42 });
    proc->create_breakpoint_site(virt_addr{ 43 });
    REQUIRE(proc->breakpoint_sites().size() == 2);

    proc->breakpoint_sites().remove_by_id(site.id());
    proc->breakpoint_sites().remove_by_address(virt_addr{ 43 });
    REQUIRE(proc->breakpoint_sites().empty());
}

TEST_CASE("Reading and writing memory works", "[memory]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);
    auto proc = process::launch("targets/memory", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    auto a_pointer = from_bytes<std::uint64_t>(channel.read().data());
    auto data_vec = proc->read_memory(virt_addr{ a_pointer }, 8);
    auto data = from_bytes<std::uint64_t>(data_vec.data());
    REQUIRE(data == 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();

    auto b_pointer = from_bytes<std::uint64_t>(channel.read().data());
    proc->write_memory(
        virt_addr{ b_pointer }, { as_bytes("Hello, sdb!"), 12 });

    proc->resume();
    proc->wait_on_signal();

    auto read = channel.read();
    REQUIRE(to_string_view(read) == "Hello, sdb!");
}

TEST_CASE("Hardware breakpoint evades memory checksums",
    "[breakpoint]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);
    auto proc = process::launch(
        "targets/anti_debugger", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    auto func = virt_addr(
        from_bytes<std::uint64_t>(channel.read().data()));

    auto& soft = proc->create_breakpoint_site(func, false);
    soft.enable();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(to_string_view(channel.read()) ==
        "Putting pepperoni on pizza...\n");

    proc->breakpoint_sites().remove_by_id(soft.id());
    auto& hard = proc->create_breakpoint_site(func, true);
    hard.enable();

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(proc->get_pc() == func);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(to_string_view(channel.read()) ==
        "Putting pineapple on pizza...\n");
}

TEST_CASE("Watchpoint detects read", "[watchpoint]") {
    bool close_on_exec = false;
    sdb::pipe channel(close_on_exec);
    auto proc = process::launch("targets/anti_debugger", true, channel.get_write());
    channel.close_write();

    proc->resume();
    proc->wait_on_signal();

    auto func = virt_addr(
        from_bytes<std::uint64_t>(channel.read().data()));

    auto& watch = proc->create_watchpoint(func, sdb::stoppoint_mode::read_write, 1);
    watch.enable();

    proc->resume();
    proc->wait_on_signal();

    proc->step_instruction();
    auto& soft = proc->create_breakpoint_site(func, false);
    soft.enable();

    proc->resume();
    auto reason = proc->wait_on_signal();

    REQUIRE(reason.info == SIGTRAP);

    proc->resume();
    proc->wait_on_signal();

    REQUIRE(to_string_view(channel.read()) == "Putting pineapple on pizza...\n");
}

#include <libsdb/syscalls.hpp>
TEST_CASE("Syscall mapping works", "[syscall]") {
    REQUIRE(sdb::syscall_id_to_name(0) == "read");
    REQUIRE(sdb::syscall_name_to_id("read") == 0);
    REQUIRE(sdb::syscall_id_to_name(62) == "kill");
    REQUIRE(sdb::syscall_name_to_id("kill") == 62);
}

#include <fcntl.h>
TEST_CASE("Syscall catchpoints work", "[catchpoint]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto proc = process::launch("targets/anti_debugger", true, dev_null);

    auto write_syscall = sdb::syscall_name_to_id("write");
    auto policy = sdb::syscall_catch_policy::catch_some({ write_syscall });
    proc->set_syscall_catch_policy(policy);

    proc->resume();
    auto reason = proc->wait_on_signal();

    REQUIRE(reason.reason == sdb::process_state::stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(reason.trap_reason == sdb::trap_type::syscall);
    REQUIRE(reason.syscall_info->id == write_syscall);
    REQUIRE(reason.syscall_info->entry == true);

    proc->resume();
    reason = proc->wait_on_signal();

    REQUIRE(reason.reason == sdb::process_state::stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(reason.trap_reason == sdb::trap_type::syscall);
    REQUIRE(reason.syscall_info->id == write_syscall);
    REQUIRE(reason.syscall_info->entry == false);

    close(dev_null);
}

#include <libsdb/target.hpp>
TEST_CASE("ELF parser works", "[elf]") {
    auto path = "targets/hello_sdb";
    sdb::elf elf(path);
    auto entry = elf.get_header().e_entry;
    REQUIRE(entry == get_entry_point(path));
    auto sym = elf.get_symbol_at_address(file_addr{ elf, entry });
    auto name = elf.get_string(sym.value()->st_name);
    REQUIRE(name == "_start");
    auto syms = elf.get_symbols_by_name("_start");
    name = elf.get_string(syms.at(0)->st_name);
    REQUIRE(name == "_start");
    elf.notify_loaded(virt_addr{ 0xcafecafe });
    sym = elf.get_symbol_at_address(virt_addr{ 0xcafecafe + entry });
    name = elf.get_string(sym.value()->st_name);
    REQUIRE(name == "_start");
}

#include <libsdb/dwarf.hpp>
TEST_CASE("Correct DWARF language", "[dwarf]") {
    auto path = "targets/hello_sdb";
    sdb::elf elf(path);
    auto& compile_units = elf.get_dwarf().compile_units();
    REQUIRE(compile_units.size() == 1);

    auto& cu = compile_units[0];
    auto lang = cu->root()[DW_AT_language].as_int();
    REQUIRE(lang == DW_LANG_C_plus_plus);
}

TEST_CASE("Iterate DWARF", "[dwarf]") {
    auto path = "targets/hello_sdb";
    sdb::elf elf(path);
    auto& compile_units = elf.get_dwarf().compile_units();
    REQUIRE(compile_units.size() == 1);

    auto& cu = compile_units[0];
    std::size_t count = 0;
    for (auto& d : cu->root().children()) {
        auto a = d.abbrev_entry();
        REQUIRE(a->code != 0);
        ++count;
    }
    REQUIRE(count > 0);
}

TEST_CASE("Find main", "[dwarf]") {
    auto path = "targets/multi_cu";
    sdb::elf elf(path);
    sdb::dwarf dwarf(elf);

    bool found = false;
    for (auto& cu : dwarf.compile_units()) {
        for (auto& die : cu->root().children()) {
            if (die.abbrev_entry()->tag == DW_TAG_subprogram
                and die.contains(DW_AT_name)) {
                auto name = die[DW_AT_name].as_string();
                if (name == "main") {
                    found = true;
                }
            }
        }
    }

    REQUIRE(found);
}

TEST_CASE("Range list", "[dwarf]") {
    auto path = "targets/hello_sdb";
    sdb::elf elf(path);
    sdb::dwarf dwarf(elf);
    auto& cu = dwarf.compile_units()[0];

    std::vector<std::uint64_t> range_data{
    0x12341234, 0x12341236,
        ~0ULL, 0x32,
        0x12341234, 0x12341236,
        0x0, 0x0
    };

    auto bytes = reinterpret_cast<std::byte*>(range_data.data());
    sdb::range_list list(cu.get(), { bytes, bytes + range_data.size() }, file_addr{});

    auto it = list.begin();
    auto e1 = *it;
    REQUIRE(e1.low.addr() == 0x12341234);
    REQUIRE(e1.high.addr() == 0x12341236);
    REQUIRE(e1.contains(file_addr{ elf, 0x12341234 }));
    REQUIRE(e1.contains(file_addr{ elf, 0x12341235 }));
    REQUIRE(!e1.contains(file_addr{ elf, 0x12341236 }));

    ++it;
    auto e2 = *it;
    REQUIRE(e2.low.addr() == 0x12341266);
    REQUIRE(e2.high.addr() == 0x12341268);
    REQUIRE(e2.contains(file_addr{ elf, 0x12341266 }));
    REQUIRE(e2.contains(file_addr{ elf, 0x12341267 }));
    REQUIRE(!e2.contains(file_addr{ elf, 0x12341268 }));

    ++it;
    REQUIRE(it == list.end());

    REQUIRE(list.contains(file_addr{ elf, 0x12341234 }));
    REQUIRE(list.contains(file_addr{ elf, 0x12341235 }));
    REQUIRE(!list.contains(file_addr{ elf, 0x12341236 }));
    REQUIRE(list.contains(file_addr{ elf, 0x12341266 }));
    REQUIRE(list.contains(file_addr{ elf, 0x12341267 }));
    REQUIRE(!list.contains(file_addr{ elf, 0x12341268 }));
}

TEST_CASE("Line table", "[dwarf]") {
    auto path = "targets/hello_sdb";
    sdb::elf elf(path);
    sdb::dwarf dwarf(elf);

    REQUIRE(dwarf.compile_units().size() == 1);

    auto& cu = dwarf.compile_units()[0];
    auto it = cu->lines().begin();

    REQUIRE(it->line == 2);
    REQUIRE(it->file_entry->path.filename() == "hello_sdb.cpp");

    ++it;
    REQUIRE(it->line == 3);

    ++it;
    REQUIRE(it->line == 4);

    ++it;
    REQUIRE(it->end_sequence);
    ++it;
    REQUIRE(it == cu->lines().end());
}

TEST_CASE("Source-level breakpoints", "[breakpoint]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto target = target::launch("targets/overloaded", dev_null);
    auto& proc = target->get_process();

    target->create_line_breakpoint("overloaded.cpp", 17).enable();

    proc.resume();
    proc.wait_on_signal();

    auto entry = target->line_entry_at_pc();
    REQUIRE(entry->file_entry->path.filename() == "overloaded.cpp");
    REQUIRE(entry->line == 17);

    auto& bkpt = target->create_function_breakpoint("print_type");
    bkpt.enable();

    sdb::breakpoint_site* lowest_bkpt = nullptr;
    bkpt.breakpoint_sites().for_each([&lowest_bkpt](auto& site) {
        if (lowest_bkpt == nullptr or site.address().addr() < lowest_bkpt->address().addr()) {
            lowest_bkpt = &site;
        }
        });
    lowest_bkpt->disable();

    proc.resume();
    proc.wait_on_signal();

    REQUIRE(target->line_entry_at_pc()->line == 9);

    proc.resume();
    proc.wait_on_signal();

    REQUIRE(target->line_entry_at_pc()->line == 13);

    proc.resume();
    auto reason = proc.wait_on_signal();

    REQUIRE(reason.reason == sdb::process_state::exited);
    close(dev_null);
}

TEST_CASE("Source-level stepping", "[target]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto target = target::launch("targets/step", dev_null);
    auto& proc = target->get_process();

    target->create_function_breakpoint("main").enable();
    proc.resume();
    proc.wait_on_signal();

    auto pc = proc.get_pc();
    REQUIRE(target->function_name_at_address(pc) == "step`main");

    target->step_over();

    auto new_pc = proc.get_pc();
    REQUIRE(new_pc != pc);
    REQUIRE(target->function_name_at_address(pc) == "step`main");

    target->step_in();

    pc = proc.get_pc();
    REQUIRE(target->function_name_at_address(pc) == "step`find_happiness");
    REQUIRE(target->get_stack().inline_height() == 2);

    target->step_in();

    new_pc = proc.get_pc();
    REQUIRE(new_pc == pc);
    REQUIRE(target->get_stack().inline_height() == 1);

    target->step_out();

    new_pc = proc.get_pc();
    REQUIRE(new_pc != pc);
    REQUIRE(target->function_name_at_address(pc) == "step`find_happiness");

    target->step_out();

    pc = proc.get_pc();
    REQUIRE(target->function_name_at_address(pc) == "step`main");
    close(dev_null);
}

TEST_CASE("Stack unwinding", "[unwind]") {
    auto target = target::launch("targets/step");
    auto& proc = target->get_process();

    target->create_function_breakpoint("scratch_ears").enable();
    proc.resume();
    proc.wait_on_signal();
    target->step_in();
    target->step_in();

    std::vector<std::string_view> expected_names = {
        "scratch_ears",
        "pet_cat",
        "find_happiness",
        "main"
    };

    auto frames = target->get_stack().frames();
    for (auto i = 0; i < frames.size(); ++i) {
        REQUIRE(frames[i].func_die.name().value()
            == expected_names[i]);
    }
}

TEST_CASE("Shared library tracing works", "[dynlib]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto target = target::launch("targets/marshmallow", dev_null);
    auto& proc = target->get_process();

    target->create_function_breakpoint("libmeow_client_is_cute").enable();
    proc.resume();
    proc.wait_on_signal();

    REQUIRE(target->get_stack().frames().size() == 2);
    REQUIRE(target->get_stack().frames()[0].func_die.name().value() == "libmeow_client_is_cute");
    REQUIRE(target->get_stack().frames()[1].func_die.name().value() == "main");
    REQUIRE(target->get_pc_file_address().elf_file()->path().filename() == "libmeow.so");
    close(dev_null);
}

#include <set>
TEST_CASE("Multi-threading works", "[threads]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto target = target::launch("targets/multi_threaded", dev_null);
    auto& proc = target->get_process();

    target->create_function_breakpoint("say_hi").enable();

    std::set<pid_t> tids;

    stop_reason reason;
    do {
        proc.resume_all_threads();
        reason = proc.wait_on_signal();
        for (auto& [tid, thread] : proc.thread_states()) {
            if (thread.reason.reason == sdb::process_state::stopped and
                thread.reason.info == SIGTRAP and
                tid != proc.pid()) {
                tids.insert(tid);
            }
        }
    } while (tids.size() < 10);

    REQUIRE(tids.size() == 10);

    proc.resume_all_threads();
    reason = proc.wait_on_signal();
    REQUIRE(reason.reason == sdb::process_state::exited);
    close(dev_null);
}

TEST_CASE("Can read global integer variable", "[variable]") {
    auto target = target::launch("targets/global_variable");
    auto& proc = target->get_process();

    target->create_function_breakpoint("main").enable();
    proc.resume();
    proc.wait_on_signal();

    auto var_die = target->get_main_elf().get_dwarf().find_global_variable("g_int");
    auto var_loc = var_die.value()[DW_AT_location]
        .as_evaluated_location(proc, proc.get_registers(), false);
    auto res = target->read_location_data(var_loc, 8);
    auto val = from_bytes<std::uint64_t>(res.data());

    REQUIRE(val == 0);

    target->step_over();
    res = target->read_location_data(var_loc, 8);
    val = from_bytes<std::uint64_t>(res.data());

    REQUIRE(val == 1);

    target->step_over();
    res = target->read_location_data(var_loc, 8);
    val = from_bytes<std::uint64_t>(res.data());

    REQUIRE(val == 42);
}

TEST_CASE("DWARF expressions work", "[dwarf]") {
    std::vector<std::uint8_t> piece_data = {
        DW_OP_reg16, DW_OP_piece, 4, DW_OP_piece, 8, DW_OP_const4u,
        0xff, 0xff, 0xff, 0xff, DW_OP_bit_piece, 5, 12
    };

    auto target = target::launch("targets/step");
    auto& proc = target->get_process();

    sdb::span<const std::byte> data{
        reinterpret_cast<std::byte*>(piece_data.data()), piece_data.size() };
    auto expr = sdb::dwarf_expression(target->get_main_elf().get_dwarf(), data, false);
    auto res = expr.eval(proc, proc.get_registers());

    auto& pieces = std::get<sdb::dwarf_expression::pieces_result>(res).pieces;
    REQUIRE(pieces.size() == 3);
    REQUIRE(pieces[0].bit_size == 4 * 8);
    REQUIRE(pieces[1].bit_size == 8 * 8);
    REQUIRE(pieces[2].bit_size == 5);
    REQUIRE(std::get<dwarf_expression::register_result>(pieces[0].location).reg_num == 16);
    REQUIRE(std::get_if<dwarf_expression::empty_result>(&pieces[1].location) != nullptr);
    REQUIRE(std::get<dwarf_expression::address_result>(pieces[2].location)
        .address.addr() == 0xffffffff);
    REQUIRE(pieces[0].offset == 0);
    REQUIRE(pieces[1].offset == 0);
    REQUIRE(pieces[2].offset == 12);
}

#include <libsdb/type.hpp>
TEST_CASE("Global variables", "[variable]") {
    auto target = target::launch("targets/global_variable");
    auto& proc = target->get_process();

    target->create_function_breakpoint("main").enable();
    proc.resume();
    proc.wait_on_signal();

    auto name = target->resolve_indirect_name(
        "sy.pets[0].name", target->get_pc_file_address());
    auto name_vis = name.variable->visualize(target->get_process());
    REQUIRE(name_vis == "\"Marshmallow\"");

    auto cats = target->resolve_indirect_name(
        "cats[1].age", target->get_pc_file_address());
    auto cats_vis = cats.variable->visualize(target->get_process());
    REQUIRE(cats_vis == "8");
}

TEST_CASE("Local variables", "[variable]") {
    auto dev_null = open("/dev/null", O_WRONLY);
    auto target = target::launch("targets/blocks", dev_null);
    auto& proc = target->get_process();

    target->create_function_breakpoint("main").enable();
    proc.resume();
    proc.wait_on_signal();
    target->step_over();

    auto var_data = target->resolve_indirect_name("i", target->get_pc_file_address());
    REQUIRE(from_bytes<std::uint32_t>(var_data.variable->data_ptr()) == 1);

    target->step_over();
    target->step_over();

    var_data = target->resolve_indirect_name("i", target->get_pc_file_address());
    REQUIRE(from_bytes<std::uint32_t>(var_data.variable->data_ptr()) == 2);

    target->step_over();
    target->step_over();

    var_data = target->resolve_indirect_name("i", target->get_pc_file_address());
    REQUIRE(from_bytes<std::uint32_t>(var_data.variable->data_ptr()) == 3);
    close(dev_null);
}

TEST_CASE("Member pointers", "[variable]") {
    auto target = target::launch("targets/member_pointer");
    auto& proc = target->get_process();
    target->create_line_breakpoint("member_pointer.cpp", 10).enable();
    proc.resume();
    proc.wait_on_signal();

    auto data_ptr = target->resolve_indirect_name(
        "data_ptr", target->get_pc_file_address());
    auto data_vis = data_ptr.variable->visualize(proc);
    REQUIRE(data_vis == "0x0");

    auto func_ptr = target->resolve_indirect_name(
        "func_ptr", target->get_pc_file_address());
    auto func_vis = func_ptr.variable->visualize(proc);
    REQUIRE(func_vis != "0x0");
}