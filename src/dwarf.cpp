#include <libsdb/dwarf.hpp>
#include <libsdb/types.hpp>
#include <libsdb/bit.hpp>
#include <string_view>
#include <algorithm>
#include <libsdb/elf.hpp>
#include <libsdb/error.hpp>

namespace {
	class cursor {
	public:
		explicit cursor(sdb::span<const std::byte> data)
			: data_(data), pos_(data.begin()) {}

		cursor& operator++() { ++pos_; return *this; }
		cursor& operator+=(std::size_t size) { pos_ += size; return *this; }

		const std::byte* position() const { return pos_; }

		bool finished() const {
			return pos_ >= data_.end();
		}

		template <class T>
		T fixed_int() {
			auto t = sdb::from_bytes<T>(pos_);
			pos_ += sizeof(T);
			return t;
		}

		std::uint8_t u8() { return fixed_int<std::uint8_t>(); }
		std::uint16_t u16() { return fixed_int<std::uint16_t>(); }
		std::uint32_t u32() { return fixed_int<std::uint32_t>(); }
		std::uint64_t u64() { return fixed_int<std::uint64_t>(); }
		std::int8_t s8() { return fixed_int<std::int8_t>(); }
		std::int16_t s16() { return fixed_int<std::int16_t>(); }
		std::int32_t s32() { return fixed_int<std::int32_t>(); }
		std::int64_t s64() { return fixed_int<std::int64_t>(); }

		std::string_view string() {
			auto null_terminator = std::find(pos_, data_.end(), std::byte{ 0 });
			std::string_view ret(reinterpret_cast<const char*>(pos_),
				null_terminator - pos_);
			pos_ = null_terminator + 1;
			return ret;
		}

		std::uint64_t uleb128() {
			std::uint64_t res = 0;
			int shift = 0;
			std::uint8_t byte = 0;
			do {
				byte = u8();
				auto masked = static_cast<uint64_t>(byte & 0x7f);
				res |= masked << shift;
				shift += 7;
			} while ((byte & 0x80) != 0);
			return res;
		}

		std::int64_t sleb128() {
			std::uint64_t res = 0;
			int shift = 0;
			std::uint8_t byte = 0;
			do {
				byte = u8();
				auto masked = static_cast<uint64_t>(byte & 0x7f);
				res |= masked << shift;
				shift += 7;
			} while ((byte & 0x80) != 0);

			if ((shift < sizeof(res) * 8) and (byte & 0x40)) {
				res |= (~static_cast<std::uint64_t>(0) << shift);
			}

			return res;
		}

		void skip_form(std::uint64_t form) {
			switch (form) {
			case DW_FORM_flag_present:
				break;

			case DW_FORM_data1:
			case DW_FORM_ref1:
			case DW_FORM_flag:
				pos_ += 1; break;

			case DW_FORM_data2:
			case DW_FORM_ref2:
				pos_ += 2; break;

			case DW_FORM_data4:
			case DW_FORM_ref4:
			case DW_FORM_ref_addr:
			case DW_FORM_sec_offset:
			case DW_FORM_strp:
				pos_ += 4; break;

			case DW_FORM_data8:
			case DW_FORM_addr:
				pos_ += 8; break;

			case DW_FORM_sdata:
				sleb128(); break;
			case DW_FORM_udata:
			case DW_FORM_ref_udata:
				uleb128(); break;

			case DW_FORM_block1:
				pos_ += u8();
				break;
			case DW_FORM_block2:
				pos_ += u16();
				break;
			case DW_FORM_block4:
				pos_ += u32();
				break;
			case DW_FORM_block:
			case DW_FORM_exprloc:
				pos_ += uleb128();
				break;

			case DW_FORM_string:
				while (!finished() && *pos_ != std::byte(0)) {
					++pos_;
				}
				++pos_;
				break;

			case DW_FORM_indirect:
				skip_form(uleb128());
				break;
			default: sdb::error::send("Unrecognized DWARF form");
			}
		}
	private:
		sdb::span<const std::byte> data_;
		const std::byte* pos_;
	};

	std::unordered_map<std::uint64_t, sdb::abbrev>
		parse_abbrev_table(const sdb::elf& obj, std::size_t offset) {
		cursor cur(obj.get_section_contents(".debug_abbrev"));
		cur += offset;

		std::unordered_map<std::uint64_t, sdb::abbrev> table;
		std::uint64_t code = 0;
		do {
			code = cur.uleb128();
			auto tag = cur.uleb128();
			auto has_children =
				static_cast<bool>(cur.u8());

			std::vector<sdb::attr_spec> attr_specs;
			std::uint64_t attr = 0;
			do {
				attr = cur.uleb128();
				auto form = cur.uleb128();
				if (attr != 0) {
					attr_specs.push_back(sdb::attr_spec{ attr, form });
				}
			} while (attr != 0);

			if (code != 0) {
				table.emplace(code,
					sdb::abbrev{ code, tag, has_children, std::move(attr_specs) });
			}
		} while (code != 0);

		return table;
	}

	std::unique_ptr<sdb::compile_unit> parse_compile_unit(
		sdb::dwarf& dwarf, const sdb::elf& obj, cursor cur) {
		auto start = cur.position();
		auto size = cur.u32();
		auto version = cur.u16();
		auto abbrev = cur.u32();
		auto address_size = cur.u8();

		if (size == 0xffffffff) {
			sdb::error::send("Only DWARF32 is supported");
		}
		if (version != 4) {
			sdb::error::send("Only DWARF version 4 is supported");
		}
		if (address_size != 8) {
			sdb::error::send("Invalid address size for DWARF");
		}

		size += sizeof(std::uint32_t);

		sdb::span<const std::byte> data = { start, size };
		return std::make_unique<sdb::compile_unit>(dwarf, data, abbrev);
	}

	std::vector<std::unique_ptr<sdb::compile_unit>> parse_compile_units(
		sdb::dwarf& dwarf, const sdb::elf& obj) {
		auto debug_info = obj.get_section_contents(".debug_info");
		cursor cur(debug_info);

		std::vector<std::unique_ptr<sdb::compile_unit>> units;
		while (!cur.finished()) {
			auto unit = parse_compile_unit(dwarf, obj, cur);
			cur += unit->data().size();
			units.push_back(std::move(unit));
		}

		return units;
	}

	sdb::die parse_die(const sdb::compile_unit& cu, cursor cur) {
		auto pos = cur.position();
		auto abbrev_code = cur.uleb128();

		if (abbrev_code == 0) {
			auto next = cur.position();
			return sdb::die{ next };
		}

		auto& abbrev_table = cu.abbrev_table();
		auto& abbrev = abbrev_table.at(abbrev_code);

		std::vector<const std::byte*> attr_locs;
		attr_locs.reserve(abbrev.attr_specs.size());
		for (auto& attr : abbrev.attr_specs) {
			attr_locs.push_back(cur.position());
			cur.skip_form(attr.form);
		}

		auto next = cur.position();
		return sdb::die(pos, &cu, &abbrev, std::move(attr_locs), next);
	}
}

const std::unordered_map<std::uint64_t, sdb::abbrev>&
sdb::dwarf::get_abbrev_table(std::size_t offset) {
	if (!abbrev_tables_.count(offset)) {
		abbrev_tables_.emplace(offset, parse_abbrev_table(*elf_, offset));
	}
	return abbrev_tables_.at(offset);
}

const std::unordered_map<std::uint64_t, sdb::abbrev>&
sdb::compile_unit::abbrev_table() const {
	return parent_->get_abbrev_table(abbrev_offset_);
}

sdb::dwarf::dwarf(const sdb::elf& parent) : elf_(&parent) {
	compile_units_ = parse_compile_units(*this, parent);
}

sdb::die sdb::compile_unit::root() const {
	std::size_t header_size = 11;
	cursor cur({ data_.begin() + header_size, data_.end() });
	return parse_die(*this, cur);
}

sdb::die::children_range::iterator::iterator(const sdb::die& d) {
	cursor next_cur({ d.next_, d.cu_->data().end() });
	die_ = parse_die(*d.cu_, next_cur);
}

bool sdb::die::children_range::iterator::operator==(const iterator& rhs) const {
	auto lhs_null = !die_.has_value() or !die_->abbrev_entry();
	auto rhs_null = !rhs.die_.has_value() or !rhs.die_->abbrev_entry();
	if (lhs_null and rhs_null) return true;
	if (lhs_null or rhs_null) return false;

	return die_->abbrev_ == rhs->abbrev_
		and die_->next() == rhs->next();
}

sdb::die::children_range::iterator&
sdb::die::children_range::iterator::operator++() {
	if (!die_.has_value() or !die_->abbrev_) return *this;

	if (!die_->abbrev_->has_children) {
		cursor next_cur({ die_->next_, die_->cu_->data().end() });
		die_ = parse_die(*die_->cu_, next_cur);
	}
	else {
		iterator sub_children(*die_);
		while (sub_children->abbrev_) ++sub_children;
		cursor next_cur({ sub_children->next_, die_->cu_->data().end() });
		die_ = parse_die(*die_->cu_, next_cur);
	}
	return *this;
}

sdb::die::children_range::iterator
sdb::die::children_range::iterator::operator++(int) {
	auto tmp = *this;
	++(*this);
	return tmp;
}

sdb::die::children_range sdb::die::children() const {
	return children_range(*this);
}

sdb::attr sdb::die::operator[](std::uint64_t attribute) const {
	auto& specs = abbrev_->attr_specs;
	for (std::size_t i = 0; i < specs.size(); ++i) {
		if (specs[i].attr == attribute) {
			return { cu_, specs[i].attr, specs[i].form, attr_locs_[i] };
		}
	}

	error::send("Attribute not found");
}

bool sdb::die::contains(std::uint64_t attribute) const {
	auto& specs = abbrev_->attr_specs;
	return std::find_if(begin(specs), end(specs),
		[=](auto spec) { return spec.attr == attribute; }) != end(specs);
}

sdb::file_addr sdb::attr::as_address() const {
	cursor cur({ location_, cu_->data().end() });
	if (form_ != DW_FORM_addr) error::send("Invalid address type");
	auto elf = cu_->dwarf_info()->elf_file();
	return file_addr{ *elf, cur.u64() };
}

std::uint32_t sdb::attr::as_section_offset() const {
	cursor cur({ location_, cu_->data().end() });
	if (form_ != DW_FORM_sec_offset) error::send("Invalid offset type");
	return cur.u32();
}

std::uint64_t sdb::attr::as_int() const {
	cursor cur({ location_, cu_->data().end() });
	switch (form_) {
	case DW_FORM_data1:
		return cur.u8();
	case DW_FORM_data2:
		return cur.u16();
	case DW_FORM_data4:
		return cur.u32();
	case DW_FORM_data8:
		return cur.u64();
	case DW_FORM_udata:
		return cur.uleb128();
	default:
		error::send("Invalid integer type");
	}
}

sdb::span<const std::byte> sdb::attr::as_block() const {
	std::size_t size;
	cursor cur({ location_, cu_->data().end() });
	switch (form_) {
	case DW_FORM_block1:
		size = cur.u8();
		break;
	case DW_FORM_block2:
		size = cur.u16();
		break;
	case DW_FORM_block4:
		size = cur.u32();
		break;
	case DW_FORM_block:
		size = cur.uleb128();
		break;
	default:
		error::send("Invalid block type");
	}
	return { cur.position(), size };
}

sdb::die sdb::attr::as_reference() const {
	cursor cur({ location_, cu_->data().end() });
	std::size_t offset;
	switch (form_) {
	case DW_FORM_ref1:
		offset = cur.u8(); break;
	case DW_FORM_ref2:
		offset = cur.u16(); break;
	case DW_FORM_ref4:
		offset = cur.u32(); break;
	case DW_FORM_ref8:
		offset = cur.u64(); break;
	case DW_FORM_ref_udata:
		offset = cur.uleb128(); break;
	case DW_FORM_ref_addr: {
		offset = cur.u32();
		auto section = cu_->dwarf_info()->elf_file()->get_section_contents(".debug_info");
		auto die_pos = section.begin() + offset;
		auto& cus = cu_->dwarf_info()->compile_units();
		auto cu_finder = [=](auto& cu) {
			return cu->data().begin() <= die_pos and cu->data().end() > die_pos;
			};
		auto cu_for_offset = std::find_if(begin(cus), end(cus), cu_finder);
		cursor ref_cur({ die_pos, cu_for_offset->get()->data().end() });
		return parse_die(**cu_for_offset, ref_cur);
	}
	default:
		error::send("Invalid reference type");
	}

	cursor ref_cur({ cu_->data().begin() + offset, cu_->data().end() });
	return parse_die(*cu_, ref_cur);
}

std::string_view sdb::attr::as_string() const {
	cursor cur({ location_, cu_->data().end() });
	switch (form_) {
	case DW_FORM_string:
		return cur.string();
	case DW_FORM_strp: {
		auto offset = cur.u32();
		auto stab = cu_->dwarf_info()->elf_file()->get_section_contents(".debug_str");
		cursor stab_cur({ stab.begin() + offset, stab.end() });
		return stab_cur.string();
	}
	default:
		error::send("Invalid string type");
	}
}

sdb::range_list::iterator::iterator(
	const compile_unit* cu,
	sdb::span<const std::byte> data,
	file_addr base_address)
	: cu_(cu), data_(data)
	, base_address_(base_address)
	, pos_(data.begin()) {
	++(*this);
}

sdb::range_list::iterator&
sdb::range_list::iterator::operator++() {
	auto elf = cu_->dwarf_info()->elf_file();
	constexpr auto base_address_flag = ~static_cast<std::uint64_t>(0);

	cursor cur({ pos_, data_.end() });
	while (true) {
		current_.low = file_addr{ *elf, cur.u64() };
		current_.high = file_addr{ *elf, cur.u64() };

		if (current_.low.addr() == base_address_flag) {
			base_address_ = current_.high;
		}
		else if (current_.low.addr() == 0 and current_.high.addr() == 0) {
			pos_ = nullptr;
			break;
		}
		else {
			pos_ = cur.position();
			current_.low += base_address_.addr();
			current_.high += base_address_.addr();
			break;
		}
	}

	return *this;
}

sdb::range_list::iterator
sdb::range_list::iterator::operator++(int) {
	auto tmp = *this;
	++(*this);
	return tmp;
}

sdb::range_list sdb::attr::as_range_list() const {
	auto section = cu_->dwarf_info()->elf_file()->get_section_contents(
		".debug_ranges");
	auto offset = as_section_offset();
	span<const std::byte> data(section.begin() + offset, section.end());

	auto root = cu_->root();
	file_addr base_address = root.contains(DW_AT_low_pc)
		? root[DW_AT_low_pc].as_address()
		: file_addr{};

	return { cu_, data, base_address };
}

sdb::range_list::iterator
sdb::range_list::begin() const {
	return { cu_, data_, base_address_ };
}

sdb::range_list::iterator
sdb::range_list::end() const {
	return {};
}

bool sdb::range_list::contains(file_addr address) const {
	return std::any_of(begin(), end(),
		[=](auto& e) { return e.contains(address); });
}

bool sdb::die::contains_address(file_addr address) const {
	if (address.elf_file() != this->cu_->dwarf_info()->elf_file()) {
		return false;
	}

	if (contains(DW_AT_ranges)) {
		return (*this)[DW_AT_ranges].as_range_list().contains(address);
	}
	else if (contains(DW_AT_low_pc)) {
		return low_pc() <= address and high_pc() > address;
	}
	return false;
}

sdb::file_addr sdb::die::low_pc() const {
	if (contains(DW_AT_ranges)) {
		auto first_entry = (*this)[DW_AT_ranges].as_range_list().begin();
		return first_entry->low;
	}
	else if (contains(DW_AT_low_pc)) {
		return (*this)[DW_AT_low_pc].as_address();
	}
	error::send("DIE does not have low PC");
}

sdb::file_addr sdb::die::high_pc() const {
	if (contains(DW_AT_ranges)) {
		auto ranges = (*this)[DW_AT_ranges].as_range_list();
		auto it = ranges.begin();
		while (std::next(it) != ranges.end()) ++it;
		return it->high;
	}
	else if (contains(DW_AT_high_pc)) {
		auto attr = (*this)[DW_AT_high_pc];
		file_addr addr;
		if (attr.form() == DW_FORM_addr) {
			return attr.as_address();
		}
		else {
			return low_pc() + attr.as_int();
		}
	}
	error::send("DIE does not have high PC");
}

const sdb::compile_unit*
sdb::dwarf::compile_unit_containing_address(file_addr address) const {
	for (auto& cu : compile_units_) {
		if (cu->root().contains_address(address)) {
			return cu.get();
		}
	}
	return nullptr;
}

std::optional<sdb::die>
sdb::dwarf::function_containing_address(file_addr address) const {
	index();
	for (auto& [name, entry] : function_index_) {
		cursor cur({ entry.pos, entry.cu->data().end() });
		auto d = parse_die(*entry.cu, cur);
		if (d.contains_address(address) and
			d.abbrev_entry()->tag == DW_TAG_subprogram) {
			return d;
		}
	}
	return std::nullopt;
}

std::vector<sdb::die> sdb::dwarf::find_functions(std::string name) const {
	index();

	std::vector<die> found;
	auto [begin, end] = function_index_.equal_range(name);
	std::transform(begin, end, std::back_inserter(found), [](auto& pair) {
		auto [name, entry] = pair;
		cursor cur({ entry.pos, entry.cu->data().end() });
		return parse_die(*entry.cu, cur);
		});
	return found;
}

void sdb::dwarf::index() const {
	if (!function_index_.empty()) return;
	for (auto& cu : compile_units_) {
		index_die(cu->root());
	}
}

std::optional<std::string_view> sdb::die::name() const {
	if (contains(DW_AT_name)) {
		return (*this)[DW_AT_name].as_string();
	}
	if (contains(DW_AT_specification)) {
		return (*this)[DW_AT_specification].as_reference().name();
	}
	if (contains(DW_AT_abstract_origin)) {
		return (*this)[DW_AT_abstract_origin].as_reference().name();
	}
	return std::nullopt;
}

void sdb::dwarf::index_die(const die& current) const {
	bool has_range = current.contains(DW_AT_low_pc) or current.contains(DW_AT_ranges);
	bool is_function = current.abbrev_entry()->tag == DW_TAG_subprogram or
		current.abbrev_entry()->tag == DW_TAG_inlined_subroutine;
	if (has_range and is_function) {
		if (auto name = current.name(); name) {
			index_entry entry{ current.cu(), current.position() };
			function_index_.emplace(*name, entry);
		}
	}
	for (auto child : current.children()) {
		index_die(child);
	}
}