#include <iostream>
#include <unistd.h>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <libsdb/process.hpp>
#include <libsdb/error.hpp>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <charconv>
#include <libsdb/disassembler.hpp>
#include <libsdb/syscalls.hpp>
#include <libsdb/target.hpp>
#include <csignal>

namespace {
	sdb::process* g_sdb_process = nullptr;

	void handle_sigint(int) {
		kill(g_sdb_process->pid(), SIGSTOP);
	}

	std::unique_ptr<sdb::target> attach(int argc, const char** argv) {
		// Passing PID
		if (argc == 3 && argv[1] == std::string_view("-p")) {
			pid_t pid = std::atoi(argv[2]);
			return sdb::target::attach(pid);
		}
		// Passing program name
		else {
			auto program_path = argv[1];
			auto target = sdb::target::launch(program_path);
			fmt::print("Launched process with PID {}\n", target->get_process().pid());
			return target;
		}
	}

	void print_disassembly(sdb::process& process,
		sdb::virt_addr address, std::size_t n_instructions) {
		sdb::disassembler dis(process);
		auto instructions = dis.disassemble(n_instructions, address);
		for (auto& instr : instructions) {
			fmt::print("{:#018x}: {}\n", instr.address.addr(), instr.text);
		}
	}

	std::vector<std::string> split(std::string_view str, char delimiter) {
		std::vector<std::string> out{};
		std::stringstream ss{ std::string{str} };
		std::string item;

		while (std::getline(ss, item, delimiter)) {
			out.push_back(item);
		}

		return out;
	}

	bool is_prefix(std::string_view str, std::string_view of) {
		if (str.size() > of.size()) return false;
		return std::equal(str.begin(), str.end(), of.begin());
	}

	void resume(pid_t pid) {
		if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
			std::cerr << "Couldn't continue\n";
			std::exit(-1);
		}
	}

	void wait_on_signal(pid_t pid) {
		int wait_status;
		int options = 0;
		if (waitpid(pid, &wait_status, options) < 0) {
			std::perror("waitpid failed");
			std::exit(-1);
		}
	}

	void handle_command(
		pid_t pid, std::string_view line) {
		auto args = split(line, ' ');
		auto command = args[0];

		if (is_prefix(command, "continue")) {
			resume(pid);
			wait_on_signal(pid);
		}
		else {
			std::cerr << "Unknown command\n";
		}
	}

	std::string get_sigtrap_info(
		const sdb::process& process, sdb::stop_reason reason) {
		if (reason.trap_reason == sdb::trap_type::software_break) {
			auto& site = process.breakpoint_sites().get_by_address(process.get_pc());
			return fmt::format(" (breakpoint {})", site.id());
		}

		if (reason.trap_reason == sdb::trap_type::hardware_break) {
			auto id = process.get_current_hardware_stoppoint();

			if (id.index() == 0) {
				return fmt::format(" (breakpoint {})", std::get<0>(id));
			}

			std::string message;
			auto& point = process.watchpoints().get_by_id(std::get<1>(id));
			message += fmt::format(" (watchpoint {})", point.id());

			if (point.data() == point.previous_data()) {
				message += fmt::format("\nValue: {:#x}", point.data());
			}
			else {
				message += fmt::format("\nOld value: {:#x}\nNew value: {:#x}",
					point.previous_data(), point.data());
			}
			return message;
		}
		if (reason.trap_reason == sdb::trap_type::single_step) {
			return " (single step)";
		}
		if (reason.trap_reason == sdb::trap_type::syscall) {
			const auto& info = *reason.syscall_info;
			std::string message;
			if (info.entry) {
				message += "(syscall entry)\n";
				message += fmt::format("syscall: {}({:#x})",
					sdb::syscall_id_to_name(info.id),
					fmt::join(info.args, ","));
			}
			else {
				message += "(syscall exit)\n";
				message += fmt::format("syscall returned: {:#x}", info.ret);
			}
			return message;
		}

		return "";
	}

	std::string get_signal_stop_reason(
		const sdb::target& target, sdb::stop_reason reason) {
		auto& process = target.get_process();
		std::string message = fmt::format("stopped with signal {} at {:#x}",
			sigabbrev_np(reason.info), process.get_pc().addr());

		auto func = target.get_elf().get_symbol_containing_address(process.get_pc());
		if (func and ELF64_ST_TYPE(func.value()->st_info) == STT_FUNC) {
			message += fmt::format(" ({})", target.get_elf().get_string(func.value()->st_name));
		}

		if (reason.info == SIGTRAP) {
			message += get_sigtrap_info(process, reason);
		}

		return message;
	}

	void print_stop_reason(
		const sdb::target& target, sdb::stop_reason reason) {
		std::string message;
		switch (reason.reason) {
		case sdb::process_state::exited:
			message = fmt::format("exited with status {}",
				static_cast<int>(reason.info));
			break;
		case sdb::process_state::terminated:
			message = fmt::format("terminated with signal {}",
				sigabbrev_np(reason.info));
			break;
		case sdb::process_state::stopped:
			message = get_signal_stop_reason(target, reason);
			break;
		}

		fmt::print("Process {} {}\n", target.get_process().pid(), message);
	}

	void handle_stop(sdb::target& target, sdb::stop_reason reason) {
		print_stop_reason(target, reason);
		if (reason.reason == sdb::process_state::stopped) {
			print_disassembly(target.get_process(), target.get_process().get_pc(), 5);
		}
	}

	void print_help(const std::vector<std::string>& args) {
		if (args.size() == 1) {
			std::cerr << R"(Available commands:
    breakpoint  - Commands for operating on breakpoints
    catchpoint  - Commands for operating on catchpoints
    continue    - Resume the process
    disassemble - Disassemble machine code to assembly
    memory      - Commands for operating on memory
    register    - Commands for operating on registers
    step        - Step over a single instruction
    watchpoint  - Commands for operating on watchpoints
)";
		}
		else if (is_prefix(args[1], "memory")) {
			std::cerr << R"(Available commands:
    read <address>
    read <address> <number of bytes>
    write <address> <bytes>
)";
		}
		else if (is_prefix(args[1], "breakpoint")) {
			std::cerr << R"(Available commands:
    list
    delete <id>
    disable <id>
    enable <id>
    set <address>
    set <address> -h
)";
		}

		else if (is_prefix(args[1], "register")) {
			std::cerr << R"(Available commands:
    read
    read <register>
    read all
    write <register> <value>
)";
		}
		else if (is_prefix(args[1], "watchpoint")) {
			std::cerr << R"(Available commands:
    list
    delete <id>
    disable <id>
    enable <id>
    set <address> <write|rw|execute> <size>
)";
		}
		else if (is_prefix(args[1], "disassemble")) {
			std::cerr << R"(Available options:
    -c <number of instructions>
    -a <start address>
)";
		}
		else if (is_prefix(args[1], "catchpoint")) {
			std::cerr << R"(Available commands:
    syscall
    syscall none
    syscall <list of syscall IDs or names>
)";
		}
		else {
			std::cerr << "No help available on that\n";
		}
	}

	void handle_register_read(
		sdb::process& process,
		const std::vector<std::string>& args) {
		auto format = [](auto t) {
			if constexpr (std::is_floating_point_v<decltype(t)>) {
				return fmt::format("{}", t);
			}
			else if constexpr (std::is_integral_v<decltype(t)>) {
				return fmt::format("{:#0{}x}", t, sizeof(t) * 2 + 2);
			}
			else {
				return fmt::format("[{:#04x}]", fmt::join(t, ","));
			}
			};

		if (args.size() == 2 or
			(args.size() == 3 and args[2] == "all")) {
			for (auto& info : sdb::g_register_infos) {
				auto should_print = (args.size() == 3 or
					info.type == sdb::register_type::gpr)
					and info.name != "orig_rax";
				if (!should_print) continue;
				auto value = process.get_registers().read(info);
				fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
			}
		}
		else if (args.size() == 3) {
			try {
				auto info = sdb::register_info_by_name(args[2]);
				auto value = process.get_registers().read(info);
				fmt::print("{}:\t{}\n", info.name, std::visit(format, value));
			}
			catch (sdb::error& err) {
				std::cerr << "No such register\n";
				return;
			}
		}
		else {
			print_help({ "help", "register" });
		}
	}

	template <class I>
	std::optional<I> to_integral(std::string_view sv, int base = 10) {
		auto begin = sv.begin();
		if (base == 16 and sv.size() > 1 and
			begin[0] == '0' and begin[1] == 'x') {
			begin += 2;
		}

		I ret;
		auto result = std::from_chars(begin, sv.end(), ret, base);

		if (result.ptr != sv.end()) {
			return std::nullopt;
		}
		return ret;
	}

	template<>
	std::optional<std::byte> to_integral(std::string_view sv, int base) {
		auto uint8 = to_integral<std::uint8_t>(sv, base);
		if (uint8) return static_cast<std::byte>(*uint8);
		return std::nullopt;
	}

	template <std::size_t N>
	auto parse_vector(std::string_view text) {
		auto invalid = [] { sdb::error::send("Invalid format"); };

		std::array<std::byte, N> bytes;
		const char* c = text.data();

		if (*c++ != '[') invalid();
		for (auto i = 0; i < N - 1; ++i) {
			bytes[i] = to_integral<std::byte>({ c, 4 }, 16).value();
			c += 4;
			if (*c++ != ',') invalid();
		}

		bytes[N - 1] = to_integral<std::byte>({ c, 4 }, 16).value();
		c += 4;

		if (*c++ != ']') invalid();
		if (c != text.end()) invalid();

		return bytes;
	}


	template <class F>
	std::optional<F> to_float(std::string_view sv) {
		F ret;
		auto result = std::from_chars(sv.begin(), sv.end(), ret);

		if (result.ptr != sv.end()) {
			return std::nullopt;
		}
		return ret;
	}



	sdb::registers::value parse_register_value(
		sdb::register_info info, std::string_view text) {
		try {
			if (info.format ==
				sdb::register_format::uint) {
				switch (info.size) {
				case 1: return to_integral<std::uint8_t>(text, 16).value();
				case 2: return to_integral<std::uint16_t>(text, 16).value();
				case 4: return to_integral<std::uint32_t>(text, 16).value();
				case 8: return to_integral<std::uint64_t>(text, 16).value();
				}
			}
			else if (info.format ==
				sdb::register_format::double_float) {
				return to_float<double>(text).value();
			}
			else if (info.format ==
				sdb::register_format::long_double) {
				return to_float<long double>(text).value();
			}
			else if (info.format ==
				sdb::register_format::vector) {
				if (info.size == 8) {
					return parse_vector<8>(text);
				}
				else if (info.size == 16) {
					return parse_vector<16>(text);
				}
			}
		}
		catch (...) {}
		sdb::error::send("Invalid format");
	}

	void handle_register_write(
		sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() != 4) {
			print_help({ "help", "register" });
			return;
		}
		try {
			auto info = sdb::register_info_by_name(args[2]);
			auto value = parse_register_value(info, args[3]);
			process.get_registers().write(info, value);
		}
		catch (sdb::error& err) {
			std::cerr << err.what() << '\n';
			return;
		}
	}

	void handle_register_command(
		sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() < 2) {
			print_help({ "help", "register" });
			return;
		}

		if (is_prefix(args[1], "read")) {
			handle_register_read(process, args);
		}
		else if (is_prefix(args[1], "write")) {
			handle_register_write(process, args);
		}
		else {
			print_help({ "help", "register" });
		}
	}

	void handle_breakpoint_command(sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() < 2) {
			print_help({ "help", "breakpoint" });
			return;
		}

		auto command = args[1];

		if (is_prefix(command, "list")) {
			if (process.breakpoint_sites().empty()) {
				fmt::print("No breakpoints set\n");
			}
			else {
				fmt::print("Current breakpoints:\n");
				process.breakpoint_sites().for_each([](auto& site) {
					if (site.is_internal()) return;
					fmt::print("{}: address = {:#x}, {}\n",
						site.id(), site.address().addr(),
						site.is_enabled() ? "enabled" : "disabled");
					});
			}
			return;
		}

		if (args.size() < 3) {
			print_help({ "help", "breakpoint" });
			return;
		}

		if (is_prefix(command, "set")) {
			auto address = to_integral<std::uint64_t>(args[2], 16);

			if (!address) {
				fmt::print(stderr,
					"Breakpoint command expects address in "
					"hexadecimal, prefixed with '0x'\n");
				return;
			}

			bool hardware = false;
			if (args.size() == 4) {
				if (args[3] == "-h") hardware = true;
				else sdb::error::send("Invalid breakpoint command argument");
			}
			process.create_breakpoint_site(
				sdb::virt_addr{ *address }, hardware).enable();
			return;
		}

		auto id = to_integral<sdb::breakpoint_site::id_type>(args[2]);
		if (!id) {
			std::cerr << "Command expects breakpoint id";
			return;
		}

		if (is_prefix(command, "enable")) {
			process.breakpoint_sites().get_by_id(*id).enable();
		}
		else if (is_prefix(command, "disable")) {
			process.breakpoint_sites().get_by_id(*id).disable();
		}
		else if (is_prefix(command, "delete")) {
			process.breakpoint_sites().remove_by_id(*id);
		}
	}

	void handle_memory_read_command(
		sdb::process& process,
		const std::vector<std::string>& args) {
		auto address = to_integral<std::uint64_t>(args[2], 16);
		if (!address) sdb::error::send("Invalid address format");

		auto n_bytes = 32;
		if (args.size() == 4) {
			auto bytes_arg = to_integral<std::size_t>(args[3]);
			if (!bytes_arg) sdb::error::send("Invalid number of bytes");
			n_bytes = *bytes_arg;
		}

		auto data = process.read_memory(sdb::virt_addr{ *address }, n_bytes);

		for (std::size_t i = 0; i < data.size(); i += 16) {
			auto start = data.begin() + i;
			auto end = data.begin() + std::min(i + 16, data.size());
			fmt::print("{:#016x}: {:02x}\n",
				*address + i, fmt::join(start, end, " "));
		}
	}

	auto parse_vector(
		std::string_view text) {
		auto invalid = [] { sdb::error::send("Invalid format"); };

		std::vector<std::byte> bytes;
		const char* c = text.data();

		if (*c++ != '[') invalid();

		while (*c != ']') {
			bytes.push_back(to_integral<std::byte>({ c, 4 }, 16).value());
			c += 4;

			if (*c == ',') ++c;
			else if (*c != ']') invalid();
		}

		if (++c != text.end()) invalid();

		return bytes;
	}

	void handle_memory_write_command(
		sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() != 4) {
			print_help({ "help", "memory" });
			return;
		}

		auto address = to_integral<std::uint64_t>(args[2], 16);
		if (!address) sdb::error::send("Invalid address format");

		auto data = parse_vector(args[3]);
		process.write_memory(
			sdb::virt_addr{ *address }, { data.data(), data.size() });
	}

	void handle_memory_command(
		sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() < 3) {
			print_help({ "help", "memory" });
			return;
		}
		if (is_prefix(args[1], "read")) {
			handle_memory_read_command(process, args);
		}
		else if (is_prefix(args[1], "write")) {
			handle_memory_write_command(process, args);
		}
		else {
			print_help({ "help", "memory" });
		}
	}

	void handle_disassemble_command(
		sdb::process& process, const std::vector<std::string>& args) {
		auto address = process.get_pc();
		std::size_t n_instructions = 5;

		auto it = args.begin() + 1;
		while (it != args.end()) {
			if (*it == "-a" and it + 1 != args.end()) {
				++it;
				auto opt_addr = to_integral<std::uint64_t>(*it++, 16);
				if (!opt_addr) sdb::error::send("Invalid address format");
				address = sdb::virt_addr{ *opt_addr };
			}
			else if (*it == "-c" and it + 1 != args.end()) {
				++it;
				auto opt_n = to_integral<std::size_t>(*it++);
				if (!opt_n) sdb::error::send("Invalid instruction count");
				n_instructions = *opt_n;
			}
			else {
				print_help({ "help", "disassemble" });
				return;
			}
		}
		print_disassembly(process, address, n_instructions);
	}

	void handle_watchpoint_list(sdb::process& process,
		const std::vector<std::string>& args) {
		auto stoppoint_mode_to_string = [](auto mode) {
			switch (mode) {
			case sdb::stoppoint_mode::execute: return "execute";
			case sdb::stoppoint_mode::write: return "write";
			case sdb::stoppoint_mode::read_write: return "read_write";
			default: sdb::error::send("Invalid stoppoint mode");
			}
			};

		if (process.watchpoints().empty()) {
			fmt::print("No watchpoints set\n");
		}
		else {
			fmt::print("Current watchpoints:\n");
			process.watchpoints().for_each([&](auto& point) {
				fmt::print("{}: address = {:#x}, mode = {}, size = {}, {}\n",
					point.id(), point.address().addr(),
					stoppoint_mode_to_string(point.mode()), point.size(),
					point.is_enabled() ? "enabled" : "disabled");
				});
		}
	}

	void handle_watchpoint_set(sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() != 5) {
			print_help({ "help", "watchpoint" });
			return;
		}
		auto address = to_integral<std::uint64_t>(args[2], 16);
		auto mode_text = args[3];
		auto size = to_integral<std::size_t>(args[4]);

		if (!address or !size or
			!(mode_text == "write" or
				mode_text == "rw" or
				mode_text == "execute")) {
			print_help({ "help", "watchpoint" });
			return;
		}

		sdb::stoppoint_mode mode;
		if (mode_text == "write") mode = sdb::stoppoint_mode::write;
		else if (mode_text == "rw") mode = sdb::stoppoint_mode::read_write;
		else if (mode_text == "execute") mode = sdb::stoppoint_mode::execute;

		process.create_watchpoint(
			sdb::virt_addr{ *address }, mode, *size).enable();
	}

	void handle_watchpoint_command(sdb::process& process,
		const std::vector<std::string>& args) {
		if (args.size() < 2) {
			print_help({ "help", "watchpoint" });
			return;
		}

		auto command = args[1];

		if (is_prefix(command, "list")) {
			handle_watchpoint_list(process, args);
			return;
		}

		if (is_prefix(command, "set")) {
			handle_watchpoint_set(process, args);
			return;
		}

		if (args.size() < 3) {
			print_help({ "help", "watchpoint" });
			return;
		}

		auto id = to_integral<sdb::watchpoint::id_type>(args[2]);
		if (!id) {
			std::cerr << "Command expects watchpoint id";
			return;
		}

		if (is_prefix(command, "enable")) {
			process.watchpoints().get_by_id(*id).enable();
		}
		else if (is_prefix(command, "disable")) {
			process.watchpoints().get_by_id(*id).disable();
		}
		else if (is_prefix(command, "delete")) {
			process.watchpoints().remove_by_id(*id);
		}
	}

	void handle_syscall_catchpoint_command(
		sdb::process& process, const std::vector<std::string>& args) {
		sdb::syscall_catch_policy policy =
			sdb::syscall_catch_policy::catch_all();

		if (args.size() == 3 and args[2] == "none") {
			policy = sdb::syscall_catch_policy::catch_none();
		}
		else if (args.size() >= 3) {
			auto syscalls = split(args[2], ',');
			std::vector<int> to_catch;
			std::transform(begin(syscalls), end(syscalls),
				std::back_inserter(to_catch),
				[](auto& syscall) {
					return isdigit(syscall[0]) ?
						to_integral<int>(syscall).value() :
						sdb::syscall_name_to_id(syscall);
				});
			policy = sdb::syscall_catch_policy::catch_some(std::move(to_catch));
		}

		process.set_syscall_catch_policy(std::move(policy));
	}

	void handle_catchpoint_command(
		sdb::process& process, const std::vector<std::string>& args) {
		if (args.size() < 2) {
			print_help({ "help", "catchpoint" });
			return;
		}

		if (is_prefix(args[1], "syscall")) {
			handle_syscall_catchpoint_command(process, args);
		}
	}

	void handle_command(std::unique_ptr<sdb::target>& target,
		std::string_view line) {
		auto args = split(line, ' ');
		auto command = args[0];
		auto process = &target->get_process();

		if (is_prefix(command, "continue")) {
			process->resume();
			auto reason = process->wait_on_signal();
			handle_stop(*target, reason);
		}
		else if (is_prefix(command, "memory")) {
			handle_memory_command(*process, args);
		}
		else if (is_prefix(command, "register")) {
			handle_register_command(*process, args);
		}
		else if (is_prefix(command, "breakpoint")) {
			handle_breakpoint_command(*process, args);
		}
		else if (is_prefix(command, "watchpoint")) {
			handle_watchpoint_command(*process, args);
		}
		else if (is_prefix(command, "step")) {
			auto reason = process->step_instruction();
			handle_stop(*target, reason);
		}
		else if (is_prefix(command, "disassemble")) {
			handle_disassemble_command(*process, args);
		}
		else if (is_prefix(command, "catchpoint")) {
			handle_catchpoint_command(*process, args);
		}
		else if (is_prefix(command, "help")) {
			print_help(args);
		}
		else {
			std::cerr << "Unknown command\n";
		}


	}

	void main_loop(std::unique_ptr<sdb::target>& target) {
		char* line = nullptr;
		while ((line = readline("sdb> ")) != nullptr) {
			std::string line_str;

			if (line == std::string_view("")) {
				free(line);
				if (history_length > 0) {
					line_str = history_list()[history_length - 1]->line;
				}
			}
			else {
				line_str = line;
				add_history(line);
				free(line);
			}

			if (!line_str.empty()) {
				try {
					handle_command(target, line_str);
				}
				catch (const sdb::error& err) {
					std::cout << err.what() << '\n';
				}
			}
		}
	}
}

int main(int argc, const char** argv) {
	if (argc == 1) {
		std::cerr << "No arguments given\n";
		return -1;
	}

	try {
		auto target = attach(argc, argv);
		g_sdb_process = &target->get_process();
		signal(SIGINT, handle_sigint);
		main_loop(target);
	}
	catch (const sdb::error& err) {
		std::cout << err.what() << '\n';
	}
}