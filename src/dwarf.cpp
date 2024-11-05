#include <libsdb/dwarf.hpp>
#include <libsdb/types.hpp>
#include <libsdb/bit.hpp>
#include <string_view>
#include <algorithm>
#include <libsdb/elf.hpp>
#include <libsdb/error.hpp>
#include <libsdb/process.hpp>
#include <variant>
#include <functional>
#include <libsdb/type.hpp>

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

    sdb::line_table::file parse_line_table_file(cursor& cur,
        std::filesystem::path compilation_dir,
        const std::vector<std::filesystem::path>& include_directories) {
        auto file = cur.string();
        auto dir_index = cur.uleb128();
        auto modification_time = cur.uleb128();
        auto file_length = cur.uleb128();

        std::filesystem::path path = file;
        if (file[0] != '/') {
            if (dir_index == 0) {
                path = compilation_dir / std::string(file);
            }
            else {
                path = include_directories[dir_index - 1] / std::string(file);
            }
        }
        return { path.string(), modification_time, file_length };
    }

    std::unique_ptr<sdb::line_table>
        parse_line_table(const sdb::compile_unit& cu) {
        auto section = cu.dwarf_info()->elf_file()->get_section_contents(".debug_line");
        if (!cu.root().contains(DW_AT_stmt_list)) return nullptr;
        auto offset = cu.root()[DW_AT_stmt_list].as_section_offset();
        cursor cur({ section.begin() + offset, section.end() });

        auto size = cur.u32();
        auto end = cur.position() + size;

        auto version = cur.u16();
        if (version != 4) sdb::error::send("Only DWARF 4 is supported");

        (void)cur.u32(); // Header length

        auto minimum_instruction_length = cur.u8();
        if (minimum_instruction_length != 1)
            sdb::error::send("Invalid minimum instruction length");

        auto maximum_operations_per_instruction = cur.u8();
        if (maximum_operations_per_instruction != 1)
            sdb::error::send("Invalid maximum operations per instruction");

        auto default_is_stmt = cur.u8();
        auto line_base = cur.s8();
        auto line_range = cur.u8();
        auto opcode_base = cur.u8();

        std::array<std::uint8_t, 12> expected_opcode_lengths{
            0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1
        };
        for (auto i = 0; i < opcode_base - 1; ++i) {
            if (cur.u8() != expected_opcode_lengths[i]) {
                sdb::error::send("Unexpected opcode length");
            }
        }

        std::vector<std::filesystem::path> include_directories;
        std::filesystem::path compilation_dir(cu.root()[DW_AT_comp_dir].as_string());
        for (auto dir = cur.string(); !dir.empty(); dir = cur.string()) {
            if (dir[0] == '/') {
                include_directories.push_back(std::string(dir));
            }
            else {
                include_directories.push_back(compilation_dir / std::string(dir));
            }
        }

        std::vector<sdb::line_table::file> file_names;
        while (*cur.position() != std::byte(0)) {
            file_names.push_back(
                parse_line_table_file(cur, compilation_dir, include_directories));
        }
        cur += 1;

        sdb::span<const std::byte> data{ cur.position(), end };
        return std::make_unique<sdb::line_table>(data, &cu,
            default_is_stmt,
            line_base, line_range, opcode_base,
            std::move(include_directories), std::move(file_names));
    }

    std::size_t eh_frame_pointer_encoding_size(std::uint8_t encoding) {
        switch (encoding & 0x7) {
        case DW_EH_PE_absptr: return 8;
        case DW_EH_PE_udata2: return 2;
        case DW_EH_PE_udata4: return 4;
        case DW_EH_PE_udata8: return 8;
        default: sdb::error::send("Invalid pointer encoding");
        }
    }


    std::uint64_t parse_eh_frame_pointer_with_base(
        cursor& cur, std::uint8_t encoding, std::uint64_t base) {
        switch (encoding & 0x0f) {
        case DW_EH_PE_absptr: return base + cur.u64();
        case DW_EH_PE_uleb128: return base + cur.uleb128();
        case DW_EH_PE_udata2: return base + cur.u16();
        case DW_EH_PE_udata4: return base + cur.u32();
        case DW_EH_PE_udata8: return base + cur.u64();
        case DW_EH_PE_sleb128: return base + cur.sleb128();
        case DW_EH_PE_sdata2: return base + cur.s16();
        case DW_EH_PE_sdata4: return base + cur.s32();
        case DW_EH_PE_sdata8: return base + cur.s64();
        default: sdb::error::send("Unknown eh_frame pointer encoding");
        }
    }
    std::uint64_t parse_eh_frame_pointer(
        const sdb::elf& elf,
        cursor& cur, std::uint8_t encoding,
        std::uint64_t pc, std::uint64_t text_section_start,
        std::uint64_t data_section_start, std::uint64_t func_start) {
        std::uint64_t base = 0;
        switch (encoding & 0x70) {
        case DW_EH_PE_absptr: break;
        case DW_EH_PE_pcrel:
            base = pc; break;
        case DW_EH_PE_textrel:
            base = text_section_start; break;
        case DW_EH_PE_datarel:
            base = data_section_start; break;
        case DW_EH_PE_funcrel:
            base = func_start; break;
        default: sdb::error::send("Unknown eh_frame pointer encoding");
        }

        return parse_eh_frame_pointer_with_base(cur, encoding, base);
    }
    sdb::call_frame_information::common_information_entry parse_cie(cursor cur) {
        auto start = cur.position();
        auto length = cur.u32() + 4;
        auto id = cur.u32();
        auto version = cur.u8();

        if (!(version == 1 or version == 3 or version == 4)) {
            sdb::error::send("Invalid CIE version");
        }

        auto augmentation = cur.string();

        if (!augmentation.empty() and augmentation[0] != 'z') {
            sdb::error::send("Invalid CIE augmentation");
        }

        if (version == 4) {
            auto address_size = cur.u8();
            auto segment_size = cur.u8();
            if (address_size != 8)
                sdb::error::send("Invalid address size");
            if (segment_size != 0)
                sdb::error::send("Invalid segment size");
        }

        auto code_alignment_factor = cur.uleb128();
        auto data_alignment_factor = cur.sleb128();
        auto return_address_register = version == 1 ? cur.u8() : cur.uleb128();

        std::uint8_t fde_pointer_encoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;
        for (auto c : augmentation) {
            switch (c) {
            case 'z': cur.uleb128(); break;
            case 'R': fde_pointer_encoding = cur.u8(); break;
            case 'L': cur.u8(); break;
            case 'P': {
                auto encoding = cur.u8();
                (void)parse_eh_frame_pointer_with_base(cur, encoding, 0);
                break;
            }
            default: sdb::error::send("Invalid CIE augmentation");
            }
        }

        sdb::span<const std::byte> instructions = { cur.position(), start + length };
        bool fde_has_augmentation = !augmentation.empty();
        return { length, code_alignment_factor, data_alignment_factor,
            fde_has_augmentation, fde_pointer_encoding, instructions };
    }

    sdb::call_frame_information::eh_hdr
        parse_eh_hdr(sdb::dwarf& dwarf) {
        auto elf = dwarf.elf_file();
        auto eh_hdr_start = *elf->get_section_start_address(".eh_frame_hdr");
        auto text_section_start = *elf->get_section_start_address(".text");

        auto eh_hdr_data = elf->get_section_contents(".eh_frame_hdr");
        cursor cur(eh_hdr_data);

        auto start = cur.position();
        auto version = cur.u8();
        auto eh_frame_ptr_enc = cur.u8();
        auto fde_count_enc = cur.u8();
        auto table_enc = cur.u8();

        (void)parse_eh_frame_pointer_with_base(cur, eh_frame_ptr_enc, 0);
        auto fde_count = parse_eh_frame_pointer_with_base(
            cur, fde_count_enc, 0);

        auto search_table = cur.position();
        return { start, search_table, fde_count, table_enc, nullptr };
    }


    sdb::call_frame_information::frame_description_entry
        parse_fde(const sdb::call_frame_information& cfi, cursor cur) {
        auto start = cur.position();
        auto length = cur.u32() + 4;

        auto elf = cfi.dwarf_info().elf_file();
        auto current_offset = elf->data_pointer_as_file_offset(cur.position());
        sdb::file_offset cie_offset{ *elf, current_offset.off() - cur.s32() };
        auto& cie = cfi.get_cie(cie_offset);

        current_offset = elf->data_pointer_as_file_offset(cur.position());
        auto text_section_start = elf->get_section_start_address(".text")
            .value_or(sdb::file_addr{});
        auto initial_location_addr = parse_eh_frame_pointer(
            *elf, cur, cie.fde_pointer_encoding, current_offset.off(),
            text_section_start.addr(), 0, 0);
        sdb::file_addr initial_location{ *elf, initial_location_addr };

        auto address_range = parse_eh_frame_pointer_with_base(
            cur, cie.fde_pointer_encoding, 0);

        if (cie.fde_has_augmentation) {
            auto augmentation_length = cur.uleb128();
            cur += augmentation_length;
        }
        sdb::span<const std::byte> instructions = { cur.position(), start + length };
        return { length, &cie, initial_location, address_range, instructions };
    }

    std::unique_ptr<sdb::call_frame_information>
        parse_call_frame_information(sdb::dwarf& dwarf) {
        auto eh_hdr = parse_eh_hdr(dwarf);
        return std::make_unique<sdb::call_frame_information>(
            &dwarf, eh_hdr);
    }
}

const std::byte*
sdb::call_frame_information::eh_hdr::operator[](file_addr address) const {
    auto elf = address.elf_file();
    auto text_section_start = *elf->get_section_start_address(".text");
    auto encoding_size = eh_frame_pointer_encoding_size(encoding);
    auto row_size = encoding_size * 2;

    std::size_t low = 0;
    std::size_t high = count - 1;
    while (low <= high) {
        std::size_t mid = (low + high) / 2;

        cursor cur({ search_table + mid * row_size,
                                   search_table + count * row_size });
        auto current_offset = elf->data_pointer_as_file_offset(cur.position());
        auto eh_hdr_offset = elf->data_pointer_as_file_offset(start);
        auto entry_address = parse_eh_frame_pointer(*elf, cur, encoding, current_offset.off(),
            text_section_start.addr(), eh_hdr_offset.off(), 0);

        if (entry_address < address.addr()) {
            low = mid + 1;
        }
        else if (entry_address > address.addr()) {
            if (mid == 0)
                sdb::error::send("Address not found in eh_hdr");
            high = mid - 1;
        }
        else {
            high = mid;
            break;
        }
    }

    cursor cur({ search_table + high * row_size + encoding_size,
         search_table + count * row_size });
    auto current_offset = elf->data_pointer_as_file_offset(cur.position());
    auto eh_hdr_offset = elf->data_pointer_as_file_offset(start);
    auto fde_offset_int = parse_eh_frame_pointer(
        *elf, cur, encoding, current_offset.off(),
        text_section_start.addr(), eh_hdr_offset.off(), 0);
    sdb::file_offset fde_offset{ *elf, fde_offset_int };
    return elf->file_offset_as_data_pointer(fde_offset);
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
    cfi_ = parse_call_frame_information(*this);
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

void sdb::dwarf::index_die(const die& current, bool in_function) const {
    bool has_range = current.contains(DW_AT_low_pc) or current.contains(DW_AT_ranges);
    bool is_function = current.abbrev_entry()->tag == DW_TAG_subprogram or
        current.abbrev_entry()->tag == DW_TAG_inlined_subroutine;
    if (has_range and is_function) {
        if (auto name = current.name(); name) {
            index_entry entry{ current.cu(), current.position() };
            function_index_.emplace(*name, entry);
        }
    }

    if (is_function) {
        if (current.contains(DW_AT_specification)) {
            index_entry entry{ current.cu(), current.position() };
            member_function_index_.insert(std::make_pair(
                current[DW_AT_specification].as_reference().position(), entry));
        }
        else if (current.contains(DW_AT_abstract_origin)) {
            index_entry entry{ current.cu(), current.position() };
            member_function_index_.insert(std::make_pair(
                current[DW_AT_abstract_origin].as_reference().position(), entry));
        }
    }

    auto has_location = current.contains(DW_AT_location);
    auto is_variable = current.abbrev_entry()->tag == DW_TAG_variable;
    if (has_location and is_variable and !in_function) {
        if (auto name = current.name()) {
            index_entry entry{ current.cu(), current.position() };
            global_variable_index_.emplace(*name, entry);
        }
    }

    if (is_function) in_function = true;
    for (auto child : current.children()) {
        index_die(child, in_function);
    }
}

sdb::compile_unit::compile_unit(
    dwarf& parent,
    span<const std::byte> data,
    std::size_t abbrev_offset)
    : parent_(&parent)
    , data_(data)
    , abbrev_offset_(abbrev_offset) {
    line_table_ = parse_line_table(*this);
}

sdb::line_table::iterator::iterator(const sdb::line_table* table)
    : table_(table), pos_(table->data_.begin()) {
    registers_.is_stmt = table->default_is_stmt_;
    ++(*this);
}

sdb::line_table::iterator
sdb::line_table::begin() const {
    return iterator(this);
}
sdb::line_table::iterator
sdb::line_table::end() const {
    return {};
}

sdb::line_table::iterator&
sdb::line_table::iterator::operator++() {
    if (pos_ == table_->data_.end()) {
        pos_ = nullptr;
        return *this;
    }

    bool emitted = false;
    do {
        emitted = execute_instruction();
    } while (!emitted);

    current_.file_entry = &table_->file_names_[current_.file_index - 1];
    return *this;
}

sdb::line_table::iterator
sdb::line_table::iterator::operator++(int) {
    auto tmp = *this;
    ++(*this);
    return tmp;
}

bool sdb::line_table::iterator::execute_instruction() {
    auto elf = table_->cu_->dwarf_info()->elf_file();
    cursor cur({ pos_, table_->data_.end() });
    auto opcode = cur.u8();
    bool emitted = false;

    if (opcode > 0 and opcode < table_->opcode_base_) {
        switch (opcode) {
        case DW_LNS_copy:
            current_ = registers_;
            registers_.basic_block_start = false;
            registers_.prologue_end = false;
            registers_.epilogue_begin = false;
            registers_.discriminator = 0;
            emitted = true;
            break;
        case DW_LNS_advance_pc:
            registers_.address += cur.uleb128();
            break;
        case DW_LNS_advance_line:
            registers_.line += cur.sleb128();
            break;
        case DW_LNS_set_file:
            registers_.file_index = cur.uleb128();
            break;
        case DW_LNS_set_column:
            registers_.column = cur.uleb128();
            break;
        case DW_LNS_negate_stmt:
            registers_.is_stmt = !registers_.is_stmt;
            break;
        case DW_LNS_set_basic_block:
            registers_.basic_block_start = true;
            break;
        case DW_LNS_const_add_pc:
            registers_.address +=
                (255 - table_->opcode_base_) / table_->line_range_;
            break;
        case DW_LNS_fixed_advance_pc:
            registers_.address += cur.u16();
            break;
        case DW_LNS_set_prologue_end:
            registers_.prologue_end = true;
            break;
        case DW_LNS_set_epilogue_begin:
            registers_.epilogue_begin = true;
            break;
        case DW_LNS_set_isa:
            break;
        default:
            error::send("Unexpected standard opcode");
        }
    }
    else if (opcode == 0) {
        auto length = cur.uleb128();
        auto extended_opcode = cur.u8();

        switch (extended_opcode) {
        case DW_LNE_end_sequence:
            registers_.end_sequence = true;
            current_ = registers_;
            registers_ = entry{};
            registers_.is_stmt = table_->default_is_stmt_;
            emitted = true;
            break;
        case DW_LNE_set_address:
            registers_.address = file_addr(
                *elf, cur.u64());
            break;
        case DW_LNE_define_file: {
            auto compilation_dir =
                table_->cu_->root()[DW_AT_comp_dir].as_string();
            auto file = parse_line_table_file(
                cur, std::string(compilation_dir), table_->include_directories_);
            table_->file_names_.push_back(file);
            break;
        }
        case DW_LNE_set_discriminator:
            registers_.discriminator = cur.uleb128();
            break;
        default:
            error::send("Unexpected extended opcode");
        }
    }
    else {
        auto adjusted_opcode = opcode - table_->opcode_base_;
        registers_.address += adjusted_opcode / table_->line_range_;
        registers_.line +=
            table_->line_base_ + (adjusted_opcode % table_->line_range_);
        current_ = registers_;
        registers_.basic_block_start = false;
        registers_.prologue_end = false;
        registers_.epilogue_begin = false;
        registers_.discriminator = 0;
        emitted = true;
    }

    pos_ = cur.position();
    return emitted;
}

sdb::line_table::iterator
sdb::line_table::get_entry_by_address(file_addr address) const {
    auto prev = begin();
    if (prev == end()) return prev;

    auto it = prev;
    for (++it; it != end(); prev = it++) {
        if (prev->address <= address and
            it->address > address and
            !prev->end_sequence) {
            return prev;
        }
    }
    return end();
}

namespace {
    bool path_ends_in(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
        auto lhs_size = std::distance(lhs.begin(), lhs.end());
        auto rhs_size = std::distance(rhs.begin(), rhs.end());
        if (rhs_size > lhs_size) return false;
        auto start = std::next(lhs.begin(), lhs_size - rhs_size);
        return std::equal(start, lhs.end(), rhs.begin());
    }
}

std::vector<sdb::line_table::iterator>
sdb::line_table::get_entries_by_line(
    std::filesystem::path path, std::size_t line) const {
    std::vector<iterator> entries;

    for (auto it = begin(); it != end(); ++it) {
        auto& entry_path = it->file_entry->path;
        if (it->line == line) {
            if ((path.is_absolute() and entry_path == path) or
                (path.is_relative() and path_ends_in(entry_path, path))) {
                entries.push_back(it);
            }
        }
    }

    return entries;
}

sdb::source_location
sdb::die::location() const {
    return { &file(), line() };
}

const sdb::line_table::file&
sdb::die::file() const {
    std::uint64_t idx;
    if (abbrev_->tag == DW_TAG_inlined_subroutine) {
        idx = (*this)[DW_AT_call_file].as_int();
    }
    else {
        idx = (*this)[DW_AT_decl_file].as_int();
    }
    return this->cu_->lines().file_names()[idx - 1];
}

std::uint64_t sdb::die::line() const {
    if (abbrev_->tag == DW_TAG_inlined_subroutine) {
        return (*this)[DW_AT_call_line].as_int();
    }
    return (*this)[DW_AT_decl_line].as_int();
}

std::vector<sdb::die> sdb::dwarf::inline_stack_at_address(file_addr address) const {
    auto func = function_containing_address(address);
    std::vector<sdb::die> stack;
    if (func) {
        stack.push_back(*func);
        while (true) {
            const auto& children = stack.back().children();
            auto found = std::find_if(children.begin(), children.end(),
                [=](auto& child) {
                    return child.abbrev_entry()->tag == DW_TAG_inlined_subroutine and
                        child.contains_address(address);
                });
            if (found == children.end()) {
                break;
            }
            else {
                stack.push_back(*found);
            }
        }
    }
    return stack;
}

const sdb::call_frame_information::common_information_entry&
sdb::call_frame_information::get_cie(file_offset at) const {
    auto offset = at.off();
    if (cie_map_.count(offset)) {
        return cie_map_.at(offset);
    }

    auto section = at.elf_file()->get_section_contents(".eh_frame");
    cursor cur({ at.elf_file()->file_offset_as_data_pointer(at), section.end() });
    auto cie = parse_cie(cur);
    cie_map_.emplace(offset, cie);
    return cie_map_.at(offset);
}

namespace {
    struct undefined_rule {};
    struct same_rule {};
    struct offset_rule {
        std::int64_t offset;
    };
    struct val_offset_rule {
        std::int64_t offset;
    };
    struct register_rule {
        std::uint32_t reg;
    };
    struct expr_rule {
        sdb::dwarf_expression expr;
    };
    struct val_expr_rule {
        sdb::dwarf_expression expr;
    };
    struct cfa_register_rule {
        std::uint32_t reg;
        std::int64_t offset;
    };
    struct cfa_expr_rule {
        sdb::dwarf_expression expr;
    };

    struct unwind_context {
        cursor cur{ {nullptr, nullptr} };
        sdb::file_addr location;
        using cfa_rule_type = std::variant<cfa_register_rule, cfa_expr_rule>;
        cfa_rule_type cfa_rule;
        using rule = std::variant<
            undefined_rule, same_rule, offset_rule,
            val_offset_rule, register_rule,
            expr_rule, val_expr_rule>;
        using ruleset = std::unordered_map<std::uint32_t, rule>;
        ruleset cie_register_rules;
        ruleset register_rules;
        std::vector<std::pair<ruleset, cfa_rule_type>> rule_stack;
    };

    void execute_cfi_instruction(
        const sdb::elf& elf,
        const sdb::call_frame_information::frame_description_entry& fde,
        unwind_context& ctx, sdb::file_addr pc) {
        auto& cie = *fde.cie;
        auto& cur = ctx.cur;

        auto text_section_start = *elf.get_section_start_address(".text");
        auto plt_start = elf.get_section_start_address(".got.plt")
            .value_or(sdb::file_addr{});

        auto opcode = cur.u8();
        auto primary_opcode = opcode & 0xc0;
        auto extended_opcode = opcode & 0x3f;
        if (primary_opcode) {
            switch (primary_opcode) {
            case DW_CFA_advance_loc:
                ctx.location += extended_opcode * cie.code_alignment_factor;
                break;
            case DW_CFA_offset: {
                auto offset =
                    static_cast<std::int64_t>(cur.uleb128()) * cie.data_alignment_factor;
                ctx.register_rules.emplace(extended_opcode, offset_rule{ offset });
                break;
            }
            case DW_CFA_restore:
                ctx.register_rules.emplace(
                    extended_opcode, ctx.cie_register_rules.at(extended_opcode));
                break;
            }
        }
        else if (extended_opcode) {
            switch (extended_opcode) {
            case DW_CFA_set_loc: {
                auto current_offset = elf.data_pointer_as_file_offset(cur.position());
                auto loc = parse_eh_frame_pointer(
                    elf, cur, cie.fde_pointer_encoding,
                    current_offset.off(), text_section_start.addr(),
                    plt_start.addr(), fde.initial_location.addr());
                ctx.location = sdb::file_addr{ elf, loc };
                break;
            }
            case DW_CFA_advance_loc1:
                ctx.location += cur.u8() * cie.code_alignment_factor;
                break;
            case DW_CFA_advance_loc2:
                ctx.location += cur.u16() * cie.code_alignment_factor;
                break;
            case DW_CFA_advance_loc4:
                ctx.location += cur.u32() * cie.code_alignment_factor;
                break;
            case DW_CFA_def_cfa:
                ctx.cfa_rule = cfa_register_rule{
                  static_cast<std::uint32_t>(cur.uleb128()),
                  static_cast<std::uint32_t>(cur.uleb128())
                };
                break;
            case DW_CFA_def_cfa_sf:
                ctx.cfa_rule = cfa_register_rule{
                    static_cast<std::uint32_t>(cur.uleb128()),
                    cur.sleb128() * cie.data_alignment_factor
                };
                break;
            case DW_CFA_def_cfa_register:
                std::get<cfa_register_rule>(ctx.cfa_rule).reg = cur.uleb128();
                break;
            case DW_CFA_def_cfa_offset:
                std::get<cfa_register_rule>(ctx.cfa_rule).offset = cur.uleb128();
                break;
            case DW_CFA_def_cfa_offset_sf:
                std::get<cfa_register_rule>(ctx.cfa_rule).offset =
                    cur.sleb128() * cie.data_alignment_factor;
                break;
            case DW_CFA_def_cfa_expression: {
                auto length = cur.uleb128();
                auto expr = sdb::dwarf_expression{
                    elf, { cur.position(), cur.position() + length }, true };
                ctx.cfa_rule = cfa_expr_rule{ expr };
                break;
            }
            case DW_CFA_expression: {
                auto reg = cur.uleb128();
                auto length = cur.uleb128();
                auto expr = sdb::dwarf_expression{
                    elf, { cur.position(), cur.position() + length }, true };
                ctx.register_rules.emplace(reg, expr_rule{ expr });
                break;
            }
            case DW_CFA_val_expression: {
                auto reg = cur.uleb128();
                auto length = cur.uleb128();
                auto expr = sdb::dwarf_expression{
                    elf, { cur.position(), cur.position() + length }, true };
                ctx.register_rules.emplace(reg, val_expr_rule{ expr });
                break;
            }
            case DW_CFA_undefined:
                ctx.register_rules.emplace(cur.uleb128(), undefined_rule{});
                break;
            case DW_CFA_same_value:
                ctx.register_rules.emplace(cur.uleb128(), same_rule{});
                break;
            case DW_CFA_offset_extended: {
                auto reg = cur.uleb128();
                auto offset = static_cast<std::int64_t>(
                    cur.uleb128()) * cie.data_alignment_factor;
                ctx.register_rules.emplace(reg, offset_rule{ offset });
                break;
            }
            case DW_CFA_offset_extended_sf: {
                auto reg = cur.uleb128();
                auto offset = cur.sleb128() * cie.data_alignment_factor;
                ctx.register_rules.emplace(reg, offset_rule{ offset });
                break;
            }
            case DW_CFA_val_offset: {
                auto reg = cur.uleb128();
                auto offset = static_cast<std::int64_t>(
                    cur.uleb128()) * cie.data_alignment_factor;
                ctx.register_rules.emplace(reg, val_offset_rule{ offset });
                break;
            }
            case DW_CFA_val_offset_sf: {
                auto reg = cur.uleb128();
                auto offset = cur.sleb128() * cie.data_alignment_factor;
                ctx.register_rules.emplace(reg, val_offset_rule{ offset });
                break;
            }
            case DW_CFA_register: {
                auto reg = cur.uleb128();
                ctx.register_rules.emplace(
                    reg, register_rule{ static_cast<std::uint32_t>(cur.uleb128()) });
                break;
            }
            case DW_CFA_restore_extended: {
                auto reg = cur.uleb128();
                ctx.register_rules.emplace(reg, ctx.cie_register_rules.at(reg));
                break;
            }
            case DW_CFA_remember_state:
                ctx.rule_stack.push_back({ ctx.register_rules, ctx.cfa_rule });
                break;
            case DW_CFA_restore_state:
                ctx.register_rules = ctx.rule_stack.back().first;
                ctx.cfa_rule = ctx.rule_stack.back().second;
                ctx.rule_stack.pop_back();
                break;
            }
        }
    }

    sdb::registers execute_unwind_rules(
        unwind_context& ctx, sdb::registers& old_regs,
        const sdb::process& proc) {
        auto unwound_regs = old_regs;

        auto dwexp_addr_result = [&](const auto& res) {
            auto& loc = std::get<sdb::dwarf_expression::simple_location>(res);
            auto& addr_res = std::get<sdb::dwarf_expression::address_result>(loc);
            return sdb::virt_addr{ addr_res.address.addr() };
            };

        std::uint64_t cfa;
        if (auto reg_rule = std::get_if<cfa_register_rule>(&ctx.cfa_rule)) {
            auto reg_info = sdb::register_info_by_dwarf(reg_rule->reg);
            cfa = std::get<std::uint64_t>(old_regs.read(reg_info)) +
                reg_rule->offset;
        }
        else if (auto expr = std::get_if<cfa_expr_rule>(&ctx.cfa_rule)) {
            auto res = expr->expr.eval(proc, old_regs);
            cfa = dwexp_addr_result(res).addr();
        }
        old_regs.set_cfa(sdb::virt_addr{ cfa });
        unwound_regs.write_by_id(sdb::register_id::rsp, { cfa }, false);

        for (auto [reg, rule] : ctx.register_rules) {
            auto reg_info = sdb::register_info_by_dwarf(reg);

            if (auto undef = std::get_if<undefined_rule>(&rule)) {
                unwound_regs.undefine(reg_info.id);
            }
            else if (auto same = std::get_if<same_rule>(&rule)) {
                // Do nothing
            }
            else if (auto reg = std::get_if<register_rule>(&rule)) {
                auto other_reg = sdb::register_info_by_dwarf(reg->reg);
                unwound_regs.write(reg_info, old_regs.read(other_reg), false);
            }
            else if (auto offset = std::get_if<offset_rule>(&rule)) {
                auto addr = sdb::virt_addr{ cfa + offset->offset };
                auto value = sdb::from_bytes<std::uint64_t>(
                    proc.read_memory(addr, 8).data());
                unwound_regs.write(reg_info, { value }, false);
            }
            else if (auto val_offset = std::get_if<val_offset_rule>(&rule)) {
                auto addr = cfa + val_offset->offset;
                unwound_regs.write(reg_info, { addr }, false);
            }
            else if (auto expr = std::get_if<expr_rule>(&rule)) {
                auto res = expr->expr.eval(proc, old_regs);
                auto addr = dwexp_addr_result(res);
                auto value = proc.read_memory_as<std::uint64_t>(addr);
                unwound_regs.write(reg_info, { value }, false);
            }
            else if (auto val_expr = std::get_if<val_expr_rule>(&rule)) {
                auto res = val_expr->expr.eval(proc, old_regs);
                auto addr = dwexp_addr_result(res);
                unwound_regs.write(reg_info, { addr.addr() }, false);
            }
        }
        return unwound_regs;
    }
}

sdb::registers sdb::call_frame_information::unwind(
    const sdb::process& proc, file_addr pc, registers& regs) const {
    auto fde_start = eh_hdr_[pc];
    auto eh_frame_end = dwarf_->elf_file()->get_section_contents(".eh_frame").end();

    cursor cur({ fde_start, eh_frame_end });
    auto fde = parse_fde(*this, cur);
    if (pc < fde.initial_location
        or pc >= fde.initial_location + fde.address_range) {
        sdb::error::send("No unwind information at PC");
    }

    unwind_context ctx{};
    ctx.cur = cursor(fde.cie->instructions);

    while (!ctx.cur.finished()) {
        execute_cfi_instruction(*dwarf_->elf_file(), fde, ctx, pc);
    }

    ctx.cie_register_rules = ctx.register_rules;
    ctx.cur = cursor(fde.instructions);
    ctx.location = fde.initial_location;

    while (!ctx.cur.finished() and ctx.location <= pc) {
        execute_cfi_instruction(*dwarf_->elf_file(), fde, ctx, pc);
    }

    return execute_unwind_rules(ctx, regs, proc);
}

namespace {
    sdb::virt_addr read_frame_base_result(
        const sdb::dwarf_expression::result& loc,
        const sdb::registers& regs) {
        auto simple_loc = std::get_if<sdb::dwarf_expression::simple_location>(&loc);
        if (!simple_loc) sdb::error::send("Unsupported frame base location");
        if (auto addr_res = std::get_if<sdb::dwarf_expression::address_result>(simple_loc)) {
            return addr_res->address;
        }
        sdb::error::send("Unsupported frame base location");
    }
}

sdb::dwarf_expression::result
sdb::dwarf_expression::eval(
    const sdb::process& proc, const registers& regs, bool push_cfa) const {
    cursor cur({ expr_data_.begin(), expr_data_.end() });

    std::vector<std::uint64_t> stack;
    if (push_cfa) stack.push_back(regs.cfa().addr());

    std::optional<simple_location> most_recent_location;
    std::vector<pieces_result::piece> pieces;

    bool result_is_address = true;

    auto binop = [&](auto op) {
        auto rhs = stack.back();
        stack.pop_back();
        auto lhs = stack.back();
        stack.pop_back();
        stack.push_back(op(lhs, rhs));
        };

    auto relop = [&](auto op) {
        auto rhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        auto lhs = static_cast<std::int64_t>(stack.back());
        stack.pop_back();
        stack.push_back(op(lhs, rhs) ? 1 : 0);
        };

    auto virt_pc = virt_addr{
        regs.read_by_id_as<std::uint64_t>(register_id::rip)
    };
    auto pc = virt_pc.to_file_addr(*parent_->elf_file());
    auto func = parent_->function_containing_address(pc);

    auto get_current_location = [&]() {
        simple_location loc;
        if (stack.empty()) {
            loc = most_recent_location.value_or(empty_result{});
            most_recent_location.reset();
        }
        else if (result_is_address) {
            loc = address_result{ virt_addr{stack.back()} };
            stack.pop_back();
        }
        else {
            loc = literal_result{ stack.back() };
            stack.pop_back();
            result_is_address = true;
        }
        return loc;
        };

    while (!cur.finished()) {
        auto opcode = cur.u8();

        if (opcode >= DW_OP_lit0 and opcode <= DW_OP_lit31) {
            stack.push_back(opcode - DW_OP_lit0);
        }
        else if (opcode >= DW_OP_breg0 and opcode <= DW_OP_breg31) {
            auto reg = opcode - DW_OP_breg0;
            auto reg_val = regs.read(sdb::register_info_by_dwarf(reg));
            auto offset = cur.sleb128();
            stack.push_back(std::get<std::uint64_t>(reg_val) + offset);
        }
        else if (opcode >= DW_OP_reg0 and opcode <= DW_OP_reg31) {
            auto reg = opcode - DW_OP_reg0;
            if (in_frame_info_) {
                auto reg_val = regs.read(sdb::register_info_by_dwarf(reg));
                stack.push_back(std::get<std::uint64_t>(reg_val));
            }
            else {
                most_recent_location = register_result{
                    static_cast<std::uint64_t>(reg)
                };
            }
        }

        switch (opcode) {
        case DW_OP_addr: {
            auto addr = file_addr{
                *parent_->elf_file(), cur.u64()
            };
            stack.push_back(addr.to_virt_addr().addr());
            break;
        }
        case DW_OP_const1u:
            stack.push_back(cur.u8());
            break;
        case DW_OP_const1s:
            stack.push_back(cur.s8());
            break;
        case DW_OP_const2u:
            stack.push_back(cur.u16());
            break;
        case DW_OP_const2s:
            stack.push_back(cur.s16());
            break;
        case DW_OP_const4u:
            stack.push_back(cur.u32());
            break;
        case DW_OP_const4s:
            stack.push_back(cur.s32());
            break;
        case DW_OP_const8u:
            stack.push_back(cur.u64());
            break;
        case DW_OP_const8s:
            stack.push_back(cur.s64());
            break;
        case DW_OP_constu:
            stack.push_back(cur.uleb128());
            break;
        case DW_OP_consts:
            stack.push_back(cur.sleb128());
            break;

        case DW_OP_bregx: {
            auto reg_val = regs.read(
                sdb::register_info_by_dwarf(cur.uleb128()));
            stack.push_back(
                std::get<std::uint64_t>(reg_val) + cur.sleb128());
            break;
        }
        case DW_OP_fbreg: {
            auto offset = cur.sleb128();
            auto fb_loc = func.value()[DW_AT_frame_base].as_evaluated_location(proc, regs, true);
            auto fb_addr = read_frame_base_result(fb_loc, regs);
            stack.push_back(fb_addr.addr() + offset);
            break;
        }

        case DW_OP_dup:
            stack.push_back(stack.back());
            break;
        case DW_OP_drop:
            stack.pop_back();
            break;
        case DW_OP_pick:
            stack.push_back(
                stack.rbegin()[cur.u8()]);
            break;
        case DW_OP_over:
            stack.push_back(stack.rbegin()[1]);
            break;
        case DW_OP_swap:
            std::swap(stack.rbegin()[0], stack.rbegin()[1]);
            break;
        case DW_OP_rot:
            std::rotate(stack.rbegin(), stack.rbegin() + 1, stack.rbegin() + 3);
            break;
        case DW_OP_deref: {
            auto addr = virt_addr{ stack.back() };
            stack.back() = proc.read_memory_as<std::uint64_t>(addr);
            break;
        }
        case DW_OP_deref_size: {
            auto addr = virt_addr{ stack.back() };
            auto size_to_read = cur.u8();
            auto mem = proc.read_memory(addr, size_to_read);
            std::uint64_t res = 0;
            std::copy(mem.data(), mem.data() + mem.size(),
                reinterpret_cast<std::byte*>(&res));
            stack.back() = res;
            break;
        }
        case DW_OP_xderef:
            sdb::error::send("DW_OP_xderef not supported");
        case DW_OP_xderef_size:
            sdb::error::send("DW_OP_xderef_size not supported");
        case DW_OP_push_object_address:
            sdb::error::send("Unsupported opcode DW_OP_push_object_address");
        case DW_OP_form_tls_address:
            sdb::error::send("Unsupported opcode DW_OP_form_tls_address");
        case DW_OP_call_frame_cfa:
            stack.push_back(regs.cfa().addr());
            break;

        case DW_OP_minus:
            binop(std::minus{});
            break;
        case DW_OP_mod:
            binop(std::modulus{});
            break;
        case DW_OP_mul:
            binop(std::multiplies{});
            break;
        case DW_OP_and:
            binop(std::bit_and{});
            break;
        case DW_OP_or:
            binop(std::bit_or{});
            break;
        case DW_OP_plus:
            binop(std::plus{});
            break;
        case DW_OP_shl:
            binop([](auto lhs, auto rhs) { return lhs << rhs; });
            break;
        case DW_OP_shr:
            binop([](auto lhs, auto rhs) { return lhs >> rhs; });
            break;
        case DW_OP_shra:
            binop([](auto lhs, auto rhs) {
                return static_cast<std::int64_t>(lhs) >> rhs; });
            break;
        case DW_OP_xor:
            binop(std::bit_xor{});
            break;
        case DW_OP_div: {
            auto rhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            auto lhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            stack.push_back(static_cast<std::uint64_t>(lhs / rhs));
            break;
        }
        case DW_OP_abs: {
            auto sval = static_cast<std::int64_t>(stack.back());
            sval = std::abs(sval);
            stack.back() = static_cast<std::uint64_t>(sval);
            break;
        }
        case DW_OP_neg: {
            auto neg = -static_cast<std::int64_t>(stack.back());
            stack.back() = static_cast<std::uint64_t>(neg);
            break;
        }
        case DW_OP_plus_uconst:
            stack.back() += cur.uleb128();
            break;
        case DW_OP_not:
            stack.back() = ~stack.back();
            break;

        case DW_OP_le:
            relop(std::less_equal{});
            break;
        case DW_OP_ge:
            relop(std::greater_equal{});
            break;
        case DW_OP_eq:
            relop(std::equal_to{});
            break;
        case DW_OP_lt:
            relop(std::less{});
            break;
        case DW_OP_gt:
            relop(std::greater{});
            break;
        case DW_OP_ne:
            relop(std::not_equal_to{});
            break;
        case DW_OP_skip:
            cur += cur.s16();
            break;
        case DW_OP_bra:
            if (stack.back() != 0) {
                cur += cur.s16();
            }
            stack.pop_back();
            break;
        case DW_OP_call2:
            sdb::error::send("Unsupported opcode DW_OP_call2");
        case DW_OP_call4:
            sdb::error::send("Unsupported opcode DW_OP_call4");
        case DW_OP_call_ref:
            sdb::error::send("Unsupported opcode DW_OP_call_ref");
        case DW_OP_regx:
            if (in_frame_info_) {
                auto reg_val = regs.read(
                    sdb::register_info_by_dwarf(cur.uleb128()));
                stack.push_back(
                    std::get<std::uint64_t>(reg_val));
            }
            else {
                most_recent_location = register_result{
                    cur.uleb128() };
            }
            break;

        case DW_OP_implicit_value: {
            auto length = cur.uleb128();
            most_recent_location = data_result{
                span<const std::byte>{cur.position(), length} };
            break;
        }
        case DW_OP_stack_value:
            result_is_address = false;
            break;
        case DW_OP_nop:
            break;

        case DW_OP_piece: {
            auto byte_size = cur.uleb128();
            simple_location loc = get_current_location();
            pieces.push_back(pieces_result::piece{ loc, byte_size * 8 });
            break;
        }
        case DW_OP_bit_piece: {
            auto bit_size = cur.uleb128();
            auto offset = cur.uleb128();
            simple_location loc = get_current_location();
            pieces.push_back(pieces_result::piece{ loc, bit_size, offset });
            break;
        }
        }
    }
    if (!pieces.empty()) {
        return pieces_result{ pieces };
    }

    return get_current_location();
}

sdb::dwarf_expression::result
sdb::location_list::eval(
    const sdb::process& proc, const registers& regs) const {
    auto virt_pc = virt_addr{
        regs.read_by_id_as<std::uint64_t>(register_id::rip)
    };
    auto pc = virt_pc.to_file_addr(*parent_->elf_file());
    auto func = parent_->function_containing_address(pc);

    cursor cur({ expr_data_.begin(), expr_data_.end() });
    constexpr auto base_address_flag = ~static_cast<std::uint64_t>(0);
    auto base_address = cu_->root()[DW_AT_low_pc].as_address().addr();

    auto first = cur.u64();
    auto second = cur.u64();
    while (!(first == 0 and second == 0)) {
        if (first == base_address_flag) {
            base_address = second;
        }
        else {
            auto length = cur.u16();
            if (pc.addr() >= base_address + first and 
                pc.addr() < base_address + second) {
                dwarf_expression expr(*parent_, { cur.position(), cur.position() + length }, in_frame_info_);
                return expr.eval(proc, regs);
            }
            else {
                cur += length;
            }
        }
        first = cur.u64();
        second = cur.u64();
    }

    return dwarf_expression::empty_result{};
}

sdb::dwarf_expression sdb::attr::as_expression(bool in_frame_info) const {
    cursor cur({ location_, cu_->data().end() });
    auto length = cur.uleb128();
    span<const std::byte> data{ cur.position(), length };
    return dwarf_expression{ *cu_->dwarf_info(), data, in_frame_info };
}

sdb::location_list sdb::attr::as_location_list(bool in_frame_info) const {
    auto section = cu_->dwarf_info()->elf_file()->get_section_contents(
        ".debug_loc");

    cursor cur({ location_, cu_->data().end() });
    auto offset = cur.u32();

    span<const std::byte> data(section.begin() + offset, section.end());
    return location_list{ *cu_->dwarf_info(), *cu_, data, in_frame_info };
}

sdb::dwarf_expression::result
sdb::attr::as_evaluated_location(
    const sdb::process& proc, const registers& regs, bool in_frame_info) const {
    if (form_ == DW_FORM_exprloc) {
        auto expr = as_expression(in_frame_info);
        return expr.eval(proc, regs);
    }
    else if (form_ == DW_FORM_sec_offset) {
        auto loc_list = as_location_list(in_frame_info);
        return loc_list.eval(proc, regs);
    }
    else {
        error::send("Invalid location type");
    }
}

std::optional<sdb::die> sdb::dwarf::find_global_variable(std::string name) const {
    index();
    auto it = global_variable_index_.find(name);
    if (it != global_variable_index_.end()) {
        cursor cur({ it->second.pos, it->second.cu->data().end() });
        return parse_die(*it->second.cu, cur);
    }
    return std::nullopt;
}

sdb::type sdb::attr::as_type() const {
    return sdb::type{ as_reference() };
}

std::optional<sdb::die::bitfield_information> sdb::die::get_bitfield_information(
    std::uint64_t class_byte_size) const {
    if (!contains(DW_AT_bit_offset) and !contains(DW_AT_data_bit_offset)) {
        return std::nullopt;
    }
    auto bit_size = (*this)[DW_AT_bit_size].as_int();
    auto storage_byte_size = contains(DW_AT_byte_size) ?
        (*this)[DW_AT_byte_size].as_int() :
        class_byte_size;
    auto storage_bit_size = storage_byte_size * 8;
    std::uint8_t bit_offset = 0;
    if (contains(DW_AT_bit_offset)) {
        auto offset_field = (*this)[DW_AT_bit_offset].as_int();
        bit_offset = storage_bit_size - offset_field - bit_size;
    }
    if (contains(DW_AT_data_bit_offset)) {
        bit_offset = (*this)[DW_AT_data_bit_offset].as_int() % 8;
    }
    return bitfield_information{ bit_size, storage_byte_size, bit_offset };
}

namespace {
    void scopes_at_address_in_die(
        const sdb::die& die, sdb::file_addr address,
        std::vector<sdb::die>& scopes) {
        for (auto& c : die.children()) {
            if (c.contains_address(address)) {
                scopes_at_address_in_die(c, address, scopes);
                scopes.push_back(c);
            }
        }
    }
}

std::vector<sdb::die> sdb::dwarf::scopes_at_address(file_addr address) const {
    auto func = function_containing_address(address);
    if (!func) return {};

    std::vector<sdb::die> scopes;
    scopes_at_address_in_die(*func, address, scopes);
    scopes.push_back(*func);
    return scopes;
}

std::optional<sdb::die> sdb::dwarf::find_local_variable(
    std::string name, file_addr pc) const {
    auto scopes = scopes_at_address(pc);
    for (auto& scope : scopes) {
        for (auto& child : scope.children()) {
            auto tag = child.abbrev_entry()->tag;
            if ((tag == DW_TAG_variable or
                tag == DW_TAG_formal_parameter) and
                child.name() == name) {
                return child;
            }
        }
    }
    return std::nullopt;
}

std::vector<sdb::type> sdb::die::parameter_types() const {
    std::vector<type> ret;
    if (!abbrev_->tag == DW_TAG_subprogram) return ret;
    for (auto& c : children()) {
        if (c.abbrev_entry()->tag == DW_TAG_formal_parameter) {
            ret.push_back(c[DW_AT_type].as_type());
        }
    }
    return ret;
}

std::optional<sdb::die>
sdb::dwarf::get_member_function_definition(
    const sdb::die& declaration) const {
    index();
    auto it = member_function_index_.find(declaration.position());
    if (it != member_function_index_.end()) {
        cursor cur({ it->second.pos, it->second.cu->data().end() });
        auto die = parse_die(*it->second.cu, cur);
        if (die.contains(DW_AT_low_pc) or die.contains(DW_AT_ranges)) {
            return die;
        }
        return get_member_function_definition(die);
    }
    return std::nullopt;
}