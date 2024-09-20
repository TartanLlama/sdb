#include <libsdb/stack.hpp>
#include <libsdb/target.hpp>

std::vector<sdb::die>
sdb::stack::inline_stack_at_pc() const {
	auto pc = target_->get_pc_file_address();
	if (!pc.elf_file()) return {};
	return pc.elf_file()->get_dwarf().inline_stack_at_address(pc);
}

void sdb::stack::reset_inline_height() {
	auto stack = inline_stack_at_pc();

	inline_height_ = 0;
	auto pc = target_->get_pc_file_address();
	for (auto it = stack.rbegin();
		it != stack.rend() and it->low_pc() == pc;
		++it) {
		++inline_height_;
	}
}

sdb::span<const sdb::stack_frame>
sdb::stack::frames() const {
	return { frames_.data() + inline_height_,
			 frames_.size() - inline_height_ };
}

const sdb::registers& sdb::stack::regs() const {
	return frames_[current_frame_].regs;
}

sdb::virt_addr sdb::stack::get_pc() const {
	return virt_addr{
		regs().read_by_id_as<std::uint64_t>(sdb::register_id::rip)
	};
}

void sdb::stack::unwind() {
	reset_inline_height();
	current_frame_ = inline_height_;

	auto virt_pc = target_->get_process().get_pc();
	auto file_pc = target_->get_pc_file_address();
	auto& proc = target_->get_process();
	auto regs = proc.get_registers();

	frames_.clear();

	auto elf = file_pc.elf_file();
	if (!elf) return;

	while (virt_pc.addr() != 0 and elf) {
		auto& dwarf = elf->get_dwarf();
		auto inline_stack = dwarf.inline_stack_at_address(file_pc);
		if (inline_stack.empty()) return;

		if (inline_stack.size() > 1) {
			create_base_frame(regs, inline_stack, file_pc, true);
			create_inline_stack_frames(regs, inline_stack, file_pc);
		}
		else {
			create_base_frame(regs, inline_stack, file_pc, false);
		}
		regs = dwarf.cfi().unwind(proc, file_pc, frames_.back().regs);
		virt_pc = virt_addr{
			regs.read_by_id_as<std::uint64_t>(register_id::rip) - 1
		};
		file_pc = virt_pc.to_file_addr(target_->get_elves());
		elf = file_pc.elf_file();
	}
}


void sdb::stack::create_base_frame(
	const registers& regs,
	const std::vector<sdb::die> inline_stack,
	file_addr pc,
	bool inlined) {
	auto backtrace_pc = pc.to_virt_addr();
	auto line_entry = pc.elf_file()->get_dwarf().line_entry_at_address(pc);
	if (line_entry != line_table::iterator{})
		backtrace_pc = line_entry->address.to_virt_addr();

	frames_.push_back({ regs, backtrace_pc, inline_stack.back(), inlined });
	frames_.back().location = source_location{
		line_entry->file_entry, line_entry->line };
}

void sdb::stack::create_inline_stack_frames(
	const registers& regs,
	const std::vector<sdb::die> inline_stack,
	file_addr pc) {
	for (auto it = inline_stack.rbegin() + 1; it != inline_stack.rend(); ++it) {
		auto inlined_pc = std::prev(it)->low_pc().to_virt_addr();
		frames_.push_back(stack_frame{ regs, inlined_pc, *it });
		frames_.back().inlined = std::next(it) != inline_stack.rend();
		frames_.back().location = std::prev(it)->location();
	}
}