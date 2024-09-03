#include <libsdb/breakpoint.hpp>
#include <libsdb/target.hpp>

namespace {
	auto get_next_id() {
		static sdb::breakpoint::id_type id = 0;
		return ++id;
	}
}

sdb::breakpoint::breakpoint(
	target& tgt, bool is_hardware, bool is_internal)
	: target_{ &tgt }, is_hardware_{ is_hardware },
	is_internal_{ is_internal } {
	id_ = is_internal ? -1 : get_next_id();
}

void sdb::breakpoint::enable() {
	is_enabled_ = true;
	breakpoint_sites_.for_each([](auto& site) { site.enable(); });
}

void sdb::breakpoint::disable() {
	is_enabled_ = false;
	breakpoint_sites_.for_each([](auto& site) { site.disable(); });
}

void sdb::address_breakpoint::resolve() {
	if (breakpoint_sites_.empty()) {
		auto& new_site = target_->get_process()
			.create_breakpoint_site(
				this, next_site_id_++, address_, is_hardware_, is_internal_);
		breakpoint_sites_.push(&new_site);
		if (is_enabled_) new_site.enable();
	}
}

void sdb::function_breakpoint::resolve() {
	auto found_functions = target_->find_functions(function_name_);
	for (auto die : found_functions.dwarf_functions) {
		if (die.contains(DW_AT_low_pc) or die.contains(DW_AT_ranges)) {
			file_addr addr;
			if (die.abbrev_entry()->tag == DW_TAG_inlined_subroutine) {
				addr = die.low_pc();
			}
			else {
				auto function_line = die.cu()->lines()
					.get_entry_by_address(die.low_pc());
				++function_line;
				addr = function_line->address;
			}
			auto load_address = addr.to_virt_addr();
			if (!breakpoint_sites_.contains_address(load_address)) {
				auto& new_site = target_->get_process()
					.create_breakpoint_site(
						this, next_site_id_++, load_address, is_hardware_, is_internal_);

				breakpoint_sites_.push(&new_site);
				if (is_enabled_) new_site.enable();
			}
		}
	}
	for (auto sym : found_functions.elf_functions) {
		auto file_address = file_addr{ *sym.first, sym.second->st_value };
		auto load_address = file_address.to_virt_addr();
		if (!breakpoint_sites_.contains_address(load_address)) {
			auto& new_site = target_->get_process().create_breakpoint_site(
				this, next_site_id_++, load_address, is_hardware_, is_internal_);
			breakpoint_sites_.push(&new_site);
			if (is_enabled_) new_site.enable();
		}
	}
}

void sdb::line_breakpoint::resolve() {
	auto& dwarf = target_->get_elf().get_dwarf();
	for (auto& cu : dwarf.compile_units()) {
		auto entries = cu->lines().get_entries_by_line(file_, line_);
		for (auto entry : entries) {
			auto& dwarf = entry->address.elf_file()->get_dwarf();
			auto stack = dwarf.inline_stack_at_address(entry->address);
			auto no_inline_stack = stack.size() == 1;
			auto should_skip_prologue = no_inline_stack and
				(stack[0].contains(DW_AT_ranges) or stack[0].contains(DW_AT_low_pc)) and
				stack[0].low_pc() == entry->address;
			if (should_skip_prologue) {
				++entry;
			}
			auto load_address = entry->address.to_virt_addr();
			if (!breakpoint_sites_.contains_address(load_address)) {
				auto& new_site = target_->get_process()
					.create_breakpoint_site(
						this, next_site_id_++, load_address, is_hardware_, is_internal_);

				breakpoint_sites_.push(&new_site);
				if (is_enabled_) new_site.enable();
			}
		}
	}
}