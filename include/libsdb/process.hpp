#ifndef SDB_PROCESS_HPP
#define SDB_PROCESS_HPP

#include <filesystem>
#include <memory>
#include <optional>
#include <sys/types.h>
#include <libsdb/registers.hpp>
#include <vector>
#include <libsdb/breakpoint_site.hpp>
#include <libsdb/stoppoint_collection.hpp>
#include <libsdb/bit.hpp>
#include <libsdb/watchpoint.hpp>
#include <unordered_map>
#include <csignal>
#include <functional>

namespace sdb {

	class syscall_catch_policy {
	public:
		enum mode {
			none, some, all
		};

		static syscall_catch_policy catch_all() {
			return { mode::all, {} };
		}

		static syscall_catch_policy catch_none() {
			return { mode::none, {} };
		}

		static syscall_catch_policy catch_some(std::vector<int> to_catch) {
			return { mode::some, std::move(to_catch) };
		}

		mode get_mode() const { return mode_; }
		const std::vector<int>& get_to_catch() const { return to_catch_; }

	private:
		syscall_catch_policy(mode mode, std::vector<int> to_catch) :
			mode_(mode), to_catch_(std::move(to_catch)) {}

		mode mode_ = mode::none;
		std::vector<int> to_catch_;
	};

	struct syscall_information {
		std::uint16_t id;
		bool entry;
		union {
			std::array<std::uint64_t, 6> args;
			std::int64_t ret;
		};
	};

	enum class process_state {
		stopped,
		running,
		exited,
		terminated
	};

	enum class trap_type {
		single_step, software_break,
		hardware_break, syscall, clone, unknown
	};

	struct stop_reason {
		stop_reason(pid_t tid, int wait_status);

		stop_reason(pid_t tid, process_state reason, std::uint8_t info,
			std::optional<trap_type> trap_reason = std::nullopt,
			std::optional<syscall_information> syscall_info = std::nullopt)
			: reason(reason)
			, info(info)
			, trap_reason(trap_reason)
			, syscall_info(syscall_info)
			, tid(tid)
		{}

		bool is_step() const {
			return reason == process_state::stopped
				and info == SIGTRAP
				and trap_reason == trap_type::single_step;
		}
		bool is_breakpoint() const {
			return reason == process_state::stopped
				and info == SIGTRAP
				and (trap_reason == trap_type::software_break
					or trap_reason == trap_type::hardware_break);
		}

		process_state reason;
		std::uint8_t info;
		std::optional<trap_type> trap_reason;
		std::optional<syscall_information> syscall_info;
		pid_t tid;
	};

	struct thread_state {
		pid_t tid;
		registers regs;
		stop_reason reason;
		process_state state = process_state::stopped;
		bool pending_sigstop = false;
	};

	class target;
	class process {
	public:
		~process();
		static std::unique_ptr<process> launch(std::filesystem::path path,
			bool debug = true,
			std::optional<int> stdout_replacement = std::nullopt);
		static std::unique_ptr<process> attach(pid_t pid);

		void resume(std::optional<pid_t> otid = std::nullopt);
		stop_reason wait_on_signal(pid_t to_await = -1);

		process() = delete;
		process(const process&) = delete;
		process& operator=(const process&) = delete;

		process_state state() const { return state_; }
		pid_t pid() const { return pid_; }

		registers& get_registers(std::optional<pid_t> otid = std::nullopt);
		const registers& get_registers(std::optional<pid_t> otid = std::nullopt) const;

		void write_user_area(std::size_t offset, std::uint64_t data, std::optional<pid_t> otid = std::nullopt);

		void write_fprs(const user_fpregs_struct& fprs, std::optional<pid_t> otid = std::nullopt);
		void write_gprs(const user_regs_struct& gprs, std::optional<pid_t> otid = std::nullopt);

		virt_addr get_pc(std::optional<pid_t> otid = std::nullopt) const;

		sdb::stop_reason step_instruction(std::optional<pid_t> otid = std::nullopt);

		breakpoint_site& create_breakpoint_site(
			virt_addr address,
			bool hardware = false,
			bool internal = false);

		stoppoint_collection<breakpoint_site>&
			breakpoint_sites() { return breakpoint_sites_; }

		const stoppoint_collection<breakpoint_site>&
			breakpoint_sites() const { return breakpoint_sites_; }

		void set_pc(std::optional<pid_t> otid = std::nullopt);

		std::vector<std::byte> read_memory(
			virt_addr address, std::size_t amount) const;
		std::vector<std::byte> read_memory_without_traps(
			virt_addr address, std::size_t amount) const;
		void write_memory(virt_addr address, span<const std::byte> data);

		template <class T>
		T read_memory_as(virt_addr address) const {
			auto data = read_memory(address, sizeof(T));
			return from_bytes<T>(data.data());
		}

		int set_hardware_breakpoint(
			breakpoint_site::id_type id, virt_addr address);
		void clear_hardware_stoppoint(int index);

		int set_watchpoint(
			watchpoint::id_type id, virt_addr address,
			stoppoint_mode mode, std::size_t size);

		watchpoint& create_watchpoint(
			virt_addr address, stoppoint_mode mode, std::size_t size);
		stoppoint_collection<watchpoint>& watchpoints() {
			return watchpoints_;
		}
		const stoppoint_collection<watchpoint>& watchpoints() const {
			return watchpoints_;
		}
		std::variant<breakpoint_site::id_type, watchpoint::id_type>
			get_current_hardware_stoppoint(std::optional<pid_t> otid = std::nullopt) const;

		void set_syscall_catch_policy(syscall_catch_policy info) {
			syscall_catch_policy_ = std::move(info);
		}

		std::unordered_map<int, std::uint64_t> get_auxv() const;

		void set_target(target* tgt) { target_ = tgt; }

		breakpoint_site& create_breakpoint_site(
			breakpoint* parent, breakpoint_site::id_type id, virt_addr address,
			bool hardware = false, bool internal = false);

		void set_current_thread(pid_t tid) { current_thread_ = tid; }
		pid_t current_thread() const { return current_thread_; }

		std::unordered_map<pid_t, thread_state>&
			thread_states() { return threads_; }

		const std::unordered_map<pid_t, thread_state>&
			thread_states() const { return threads_; }

		void stop_running_threads();
		void resume_all_threads();

		void cleanup_exited_threads(pid_t main_stop_tid);
		void report_thread_lifecycle_event(const stop_reason& reason);

		std::optional<stop_reason> handle_signal(
			stop_reason reason, bool is_main_stop);

		void install_thread_lifecycle_callback(
			std::function<void(const stop_reason&)> callback) {
			thread_lifecycle_callback_ = std::move(callback);
		}

	private:
		process(pid_t pid, bool terminate_on_end, bool is_attached)
			: pid_(pid)
			, terminate_on_end_(terminate_on_end)
			, is_attached_(is_attached)
			, current_thread_(pid) {
			populate_existing_threads();
		}

		void populate_existing_threads();

		void read_all_registers(pid_t tid);

		int set_hardware_stoppoint(
			virt_addr address, stoppoint_mode mode, std::size_t size);

		void augment_stop_reason(stop_reason& reason);
		bool should_resume_from_syscall(const stop_reason& reason);
		void swallow_pending_sigstop(pid_t tid);

		pid_t pid_ = 0;
		bool terminate_on_end_ = true;
		process_state state_ = process_state::stopped;
		bool is_attached_ = true;
		std::unique_ptr<registers> registers_;
		stoppoint_collection<breakpoint_site> breakpoint_sites_;
		stoppoint_collection<watchpoint> watchpoints_;
		syscall_catch_policy syscall_catch_policy_ =
			syscall_catch_policy::catch_none();
		bool expecting_syscall_exit_ = false;
		target* target_ = nullptr;
		std::unordered_map<pid_t, thread_state> threads_;
		pid_t current_thread_ = 0;
		std::function<void(const stop_reason&)> thread_lifecycle_callback_;
	};
}

#endif