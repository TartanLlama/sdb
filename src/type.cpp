#include <libsdb/type.hpp>
#include <fmt/format.h>
#include <libsdb/process.hpp>
#include <numeric>

std::size_t sdb::type::byte_size() const {
    if (!byte_size_.has_value())
        byte_size_ = compute_byte_size();
    return *byte_size_;
}

std::size_t sdb::type::compute_byte_size() const {
    if (!is_from_dwarf()) {
        switch (get_builtin_type()) {
        case builtin_type::boolean: return 1;
        case builtin_type::character: return 1;
        case builtin_type::integer: return 8;
        case builtin_type::floating_point: return 8;
        case builtin_type::string: return 8;
        }
    }

    auto& die_ = std::get<sdb::die>(info_);
    auto tag = die_.abbrev_entry()->tag;

    if (tag == DW_TAG_pointer_type) {
        return 8;
    }
    if (tag == DW_TAG_ptr_to_member_type) {
        auto member_type = die_[DW_AT_type].as_type();
        if (member_type.get_die().abbrev_entry()->tag == DW_TAG_subroutine_type) {
            return 16;
        }
        return 8;
    }
    if (tag == DW_TAG_array_type) {
        auto value_size = die_[DW_AT_type].as_type().byte_size();
        for (auto& child : die_.children()) {
            if (child.abbrev_entry()->tag == DW_TAG_subrange_type) {
                value_size *= child[DW_AT_upper_bound].as_int() + 1;
            }
        }
        return value_size;
    }
    if (die_.contains(DW_AT_byte_size)) {
        return die_[DW_AT_byte_size].as_int();
    }
    if (die_.contains(DW_AT_type)) {
        return die_[DW_AT_type].as_type().byte_size();
    }

    return 0;
}

bool sdb::type::is_char_type() const {
    auto stripped = strip_cv_typedef().get_die();
    if (!stripped.contains(DW_AT_encoding)) return false;
    auto encoding = stripped[DW_AT_encoding].as_int();
    return stripped.abbrev_entry()->tag == DW_TAG_base_type and
        encoding == DW_ATE_signed_char or
        encoding == DW_ATE_unsigned_char;
}


namespace {
    std::string visualize_member_pointer_type(const sdb::typed_data& data) {
        return fmt::format("0x{:x}",
            sdb::from_bytes<std::uintptr_t>(data.data_ptr()));
    }

    std::string visualize_pointer_type(
        const sdb::process& proc, const sdb::typed_data& data) {
        auto ptr = sdb::from_bytes<std::uint64_t>(data.data_ptr());
        if (ptr == 0) return "0x0";
        if (data.value_type().get_die()[DW_AT_type].as_type().is_char_type()) {
            return fmt::format("\"{}\"", proc.read_string(sdb::virt_addr{ ptr }));
        }
        return fmt::format("0x{:x}", ptr);
    }

    std::string visualize_class_type(
        const sdb::process& proc, const sdb::typed_data& data, int depth) {
        std::string ret = "{\n";
        for (auto& child : data.value_type().get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member and
                child.contains(DW_AT_data_member_location) or
                child.contains(DW_AT_data_bit_offset)) {
                auto indent = std::string(depth + 1, '\t');
                auto byte_offset = child.contains(DW_AT_data_member_location) ?
                    child[DW_AT_data_member_location].as_int() :
                    child[DW_AT_data_bit_offset].as_int() / 8;
                auto pos = data.data_ptr() + byte_offset;
                auto subtype = child[DW_AT_type].as_type();
                std::vector<std::byte> member_data{
                    pos, pos + subtype.byte_size() };
                auto data = sdb::typed_data{ member_data, subtype }
                .fixup_bitfield(proc, child);
                auto member_str = data.visualize(proc, depth);
                auto name = child.name().value_or("<unnamed>");
                ret += fmt::format("{}{}: {}\n", indent, name, member_str);
            }
        }
        auto indent = std::string(depth, '\t');
        ret += indent + "}";
        return ret;
    }

    std::string visualize_subrange(
        const sdb::process& proc, const sdb::type& value_type,
        sdb::span<const std::byte> data, std::vector<std::size_t> dimensions) {
        if (dimensions.empty()) {
            std::vector<std::byte> data_vec{ data.begin(), data.end() };
            return sdb::typed_data{ std::move(data_vec), value_type }.visualize(proc);
        }

        std::string ret = "[";
        auto size = dimensions.back();
        dimensions.pop_back();
        auto sub_size = std::accumulate(
            dimensions.begin(), dimensions.end(),
            value_type.byte_size(), std::multiplies<>());
        for (std::size_t i = 0; i < size; ++i) {
            sdb::span<const std::byte> subdata{ data.begin() + i * sub_size, data.end() };
            ret += visualize_subrange(proc, value_type, subdata, dimensions);

            if (i != size - 1) {
                ret += ", ";
            }
        }
        return ret + "]";
    }

    std::string visualize_array_type(
        const sdb::process& proc, const sdb::typed_data& data) {
        std::vector<std::size_t> dimensions;
        for (auto& child : data.value_type().get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_subrange_type) {
                dimensions.push_back(child[DW_AT_upper_bound].as_int() + 1);
            }
        }
        std::reverse(dimensions.begin(), dimensions.end());
        auto value_type = data.value_type().get_die()[DW_AT_type].as_type();
        return visualize_subrange(proc, value_type, data.data(), dimensions);
    }

    std::string visualize_base_type(const sdb::typed_data& data) {
        auto& type = data.value_type();
        auto die = type.get_die();
        auto ptr = data.data_ptr();

        switch (die[DW_AT_encoding].as_int()) {
        case DW_ATE_boolean:
            return sdb::from_bytes<bool>(ptr) ? "true" : "false";
        case DW_ATE_float:
            if (die.name() == "float")
                return fmt::format("{}", sdb::from_bytes<float>(ptr));
            if (die.name() == "double")
                return fmt::format("{}", sdb::from_bytes<double>(ptr));
            if (die.name() == "long double")
                return fmt::format("{}", sdb::from_bytes<long double>(ptr));
            sdb::error::send("Unsupported floating point type");
        case DW_ATE_signed:
            switch (type.byte_size()) {
            case 1: return fmt::format("{}", sdb::from_bytes<std::int8_t>(ptr));
            case 2: return fmt::format("{}", sdb::from_bytes<std::int16_t>(ptr));
            case 4: return fmt::format("{}", sdb::from_bytes<std::int32_t>(ptr));
            case 8: return fmt::format("{}", sdb::from_bytes<std::int64_t>(ptr));
            default: sdb::error::send("Unsupported signed integer size");
            }
        case DW_ATE_unsigned:
            switch (type.byte_size()) {
            case 1: return fmt::format("{}", sdb::from_bytes<std::uint8_t>(ptr));
            case 2: return fmt::format("{}", sdb::from_bytes<std::uint16_t>(ptr));
            case 4: return fmt::format("{}", sdb::from_bytes<std::uint32_t>(ptr));
            case 8: return fmt::format("{}", sdb::from_bytes<std::uint64_t>(ptr));
            default: sdb::error::send("Unsupported unsigned integer size");
            }
        case DW_ATE_signed_char:
            return fmt::format("{}", sdb::from_bytes<signed char>(ptr));
        case DW_ATE_unsigned_char:
            return fmt::format("{}", sdb::from_bytes<unsigned char>(ptr));
        case DW_ATE_UTF:
            sdb::error::send("DW_ATE_UTF is not implemented");
        default:
            sdb::error::send("Unsupported encoding");
        }
    }
}

std::string sdb::typed_data::visualize(
    const sdb::process& proc, int depth) const {
    auto die = type_.get_die();
    switch (die.abbrev_entry()->tag) {
    case DW_TAG_base_type:
        return visualize_base_type(*this);
    case DW_TAG_pointer_type:
        return visualize_pointer_type(proc, *this);
    case DW_TAG_ptr_to_member_type:
        return visualize_member_pointer_type(*this);
    case DW_TAG_array_type:
        return visualize_array_type(proc, *this);
    case DW_TAG_class_type:
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
        return visualize_class_type(proc, *this, depth);
    case DW_TAG_enumeration_type:
    case DW_TAG_typedef:
    case DW_TAG_const_type:
    case DW_TAG_volatile_type:
        return sdb::typed_data{ data_, die[DW_AT_type].as_type() }
        .visualize(proc);
    default: sdb::error::send("Unsupported type");
    }
}


sdb::typed_data sdb::typed_data::fixup_bitfield(
    const sdb::process& proc,
    const sdb::die& member_die) const {
    auto stripped = type_.strip_cv_typedef();
    auto bitfield_info = member_die.get_bitfield_information(stripped.byte_size());
    if (bitfield_info) {
        auto [bit_size, storage_byte_size, bit_offset] = *bitfield_info;

        std::vector<std::byte> fixed_data;
        fixed_data.resize(storage_byte_size);

        auto dest = reinterpret_cast<std::uint8_t*>(fixed_data.data());
        auto src = reinterpret_cast<const std::uint8_t*>(data_.data());
        memcpy_bits(dest, 0, src, bit_offset, bit_size);

        return { fixed_data, type_ };
    }
    return *this;
}

sdb::typed_data sdb::typed_data::deref_pointer(
    const sdb::process& proc) const {
    auto stripped_type_die = type_.strip_cv_typedef().get_die();
    auto tag = stripped_type_die.abbrev_entry()->tag;
    if (tag != DW_TAG_pointer_type) {
        sdb::error::send("Not a pointer type");
    }
    sdb::virt_addr address{ sdb::from_bytes<std::uint64_t>(data_.data()) };
    auto value_type = stripped_type_die[DW_AT_type].as_type();
    auto data_vec = proc.read_memory(
        address, value_type.byte_size());
    return { std::move(data_vec), value_type, address };
}

sdb::typed_data sdb::typed_data::read_member(
    const sdb::process& proc, std::string_view member_name) const {
    auto die = type_.get_die();
    auto children = die.children();
    auto it = std::find_if(children.begin(), children.end(),
        [&](auto& child) { return child.name().value_or("") == member_name; });
    if (it == children.end()) {
        sdb::error::send("No such member");
    }
    auto var = *it;
    auto value_type = var[DW_AT_type].as_type();

    auto byte_offset = var.contains(DW_AT_data_member_location) ?
        var[DW_AT_data_member_location].as_int() :
        var[DW_AT_data_bit_offset].as_int() / 8;
    auto data_start = data_.begin() + byte_offset;
    std::vector<std::byte> member_data{ data_start, data_start + value_type.byte_size() };

    auto data = address_ ?
        typed_data{ std::move(member_data), value_type, *address_ + byte_offset } :
        typed_data{ std::move(member_data), value_type };
    return data.fixup_bitfield(proc, var);
}

sdb::typed_data sdb::typed_data::index(
    const sdb::process& proc, std::size_t index) const {
    auto parent_type = type_.strip_cv_typedef().get_die();
    auto tag = parent_type.abbrev_entry()->tag;
    if (tag != DW_TAG_array_type and tag != DW_TAG_pointer_type) {
        sdb::error::send("Not an array or pointer type");
    }
    auto value_type = parent_type[DW_AT_type].as_type();
    auto element_size = value_type.byte_size();
    auto offset = index * element_size;
    if (tag == DW_TAG_pointer_type) {
        sdb::virt_addr address{ sdb::from_bytes<std::uint64_t>(data_.data()) };
        address += offset;
        auto data_vec = proc.read_memory(
            address, element_size);
        return { std::move(data_vec), value_type, address };
    }
    else {
        std::vector<std::byte> data_vec{
            data_.begin() + offset,
            data_.begin() + offset + element_size };
        if (address_) {
            return { std::move(data_vec), value_type, *address_ + offset };
        }
        return { std::move(data_vec), value_type };
    }
}

bool sdb::type::operator==(const type& rhs) const {
    if (!is_from_dwarf() and !rhs.is_from_dwarf()) {
        return get_builtin_type() == rhs.get_builtin_type();
    }
    const sdb::type* from_dwarf = nullptr;
    const sdb::type* builtin = nullptr;
    if (!is_from_dwarf()) {
        from_dwarf = &rhs;
        builtin = this;
    }
    else if (!rhs.is_from_dwarf()) {
        from_dwarf = this;
        builtin = &rhs;
    }
    if (from_dwarf and builtin) {
        auto die = from_dwarf->strip_cvref_typedef().get_die();
        auto tag = die.abbrev_entry()->tag;
        if (tag == DW_TAG_base_type) {
            switch (die[DW_AT_encoding].as_int()) {
            case DW_ATE_boolean:
                return builtin->get_builtin_type() == builtin_type::boolean;
            case DW_ATE_float:
                return builtin->get_builtin_type() == builtin_type::floating_point;
            case DW_ATE_signed:
            case DW_ATE_unsigned:
                return builtin->get_builtin_type() == builtin_type::integer;
            case DW_ATE_signed_char:
            case DW_ATE_unsigned_char:
                return builtin->get_builtin_type() == builtin_type::character;
            default:
                return false;
            }
        }
        if (tag == DW_TAG_pointer_type) {
            return die[DW_AT_type].as_type().is_char_type() and
                builtin->get_builtin_type() == builtin_type::string;
        }
        return false;
    }
    auto lhs_stripped = strip_all();
    auto rhs_stripped = rhs.strip_all();

    auto lhs_name = lhs_stripped.get_die().name();
    auto rhs_name = rhs_stripped.get_die().name();
    if (lhs_name and rhs_name and *lhs_name == *rhs_name)
        return true;

    return false;
}

namespace {
    sdb::parameter_class merge_parameter_classes(
        sdb::parameter_class lhs, sdb::parameter_class rhs) {
        using namespace sdb;
        if (lhs == rhs) return lhs;

        if (lhs == parameter_class::no_class) return rhs;
        if (rhs == parameter_class::no_class) return lhs;

        if (lhs == parameter_class::memory or
            rhs == parameter_class::memory) {
            return parameter_class::memory;
        }

        if (lhs == parameter_class::integer or
            rhs == parameter_class::integer) {
            return parameter_class::integer;
        }

        if (lhs == parameter_class::x87 or
            rhs == parameter_class::x87 or
            lhs == parameter_class::x87up or
            rhs == parameter_class::x87up or
            lhs == parameter_class::complex_x87 or
            rhs == parameter_class::complex_x87) {
            return parameter_class::memory;
        }

        return parameter_class::sse;
    }

    void classify_class_field(
        const sdb::type& type,
        const sdb::die& field,
        std::array<sdb::parameter_class, 2>& classes,
        int bit_offset) {
        auto bitfield_info = field.get_bitfield_information(type.byte_size());
        auto field_type = field[DW_AT_type].as_type();

        auto bit_size = bitfield_info ?
            bitfield_info->bit_size :
            field_type.byte_size() * 8;
        auto current_bit_offset = bitfield_info ?
            bitfield_info->bit_offset + bit_offset :
            field[DW_AT_data_member_location].as_int() * 8 + bit_offset;
        auto eightbyte_index = current_bit_offset / 64;

        if (field_type.is_class_type()) {
            for (auto child : field_type.get_die().children()) {
                if (child.abbrev_entry()->tag == DW_TAG_member and
                    child.contains(DW_AT_data_member_location) or
                    child.contains(DW_AT_data_bit_offset)) {
                    classify_class_field(type, child, classes, current_bit_offset);
                }
            }
        }
        else {
            auto field_classes = field_type.get_parameter_classes();
            classes[eightbyte_index] = merge_parameter_classes(
                classes[eightbyte_index], field_classes[0]);
            if (eightbyte_index == 0) {
                classes[1] = merge_parameter_classes(classes[1], field_classes[1]);
            }
        }
    }

    std::array<sdb::parameter_class, 2> classify_class_type(
        const sdb::type& type) {
        if (type.is_non_trivial_for_calls()) {
            sdb::error::send("NTFPOC types are not supported");
        }

        if (type.byte_size() > 16 or
            type.has_unaligned_fields()) {
            return {
                sdb::parameter_class::memory,
                sdb::parameter_class::memory
            };
        }

        std::array<sdb::parameter_class, 2> classes = {
            sdb::parameter_class::no_class,
            sdb::parameter_class::no_class
        };

        if (type.get_die().abbrev_entry()->tag == DW_TAG_array_type) {
            auto value_type = type.get_die()[DW_AT_type].as_type();
            classes = value_type.get_parameter_classes();
            if (type.byte_size() > 8 and classes[1] == sdb::parameter_class::no_class) {
                classes[1] = classes[0];
            }
        }
        else {
            for (auto child : type.get_die().children()) {
                if (child.abbrev_entry()->tag == DW_TAG_member and
                    child.contains(DW_AT_data_member_location) or
                    child.contains(DW_AT_data_bit_offset)) {
                    classify_class_field(type, child, classes, 0);
                }
            }
        }

        if (classes[0] == sdb::parameter_class::memory or
            classes[1] == sdb::parameter_class::memory) {
            classes[0] = classes[1] = sdb::parameter_class::memory;
        }
        else if (classes[1] == sdb::parameter_class::x87up and
            classes[0] != sdb::parameter_class::x87) {
            classes[0] = classes[1] = sdb::parameter_class::memory;
        }

        return classes;
    }

    bool is_destructor(const sdb::die& func) {
        auto name = func.name();
        return name and
            name.value().size() > 1 and
            name.value()[0] == '~';
    }

    bool is_copy_or_move_constructor(
        const sdb::type& class_type, const sdb::die& func) {
        auto class_name = class_type.get_die().name();
        if (class_name != func.name()) return false;

        int i = 0;
        for (auto child : func.children()) {
            if (child.abbrev_entry()->tag == DW_TAG_formal_parameter) {
                if (i == 0) {
                    auto type = child[DW_AT_type].as_type();
                    if (type.get_die().abbrev_entry()->tag != DW_TAG_pointer_type)
                        return false;
                    if (type.get_die()[DW_AT_type].as_type().strip_cv_typedef() != class_type)
                        return false;
                }
                else if (i == 1) {
                    auto type = child[DW_AT_type].as_type();
                    auto tag = type.get_die().abbrev_entry()->tag;
                    if (tag != DW_TAG_reference_type and
                        tag != DW_TAG_rvalue_reference_type)
                        return false;
                    auto ref = type.get_die()[DW_AT_type].as_type().strip_cv_typedef();
                    if (ref != class_type)
                        return false;
                }
                else {
                    return false;
                }
            }
            ++i;
        }
        return i == 2;
    }
}

std::size_t sdb::type::alignment() const {
    if (!is_from_dwarf()) {
        return byte_size();
    }
    if (is_class_type()) {
        std::size_t max_alignment = 0;
        for (auto child : get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member and
                child.contains(DW_AT_data_member_location) or
                child.contains(DW_AT_data_bit_offset)) {
                auto member_type = child[DW_AT_type].as_type();
                if (member_type.alignment() > max_alignment) {
                    max_alignment = member_type.alignment();
                }
            }
        }
        return max_alignment;
    }
    if (get_die().abbrev_entry()->tag == DW_TAG_array_type) {
        return get_die()[DW_AT_type].as_type().alignment();
    }
    return byte_size();
}

bool sdb::type::has_unaligned_fields() const {
    if (!is_from_dwarf()) {
        return false;
    }
    if (is_class_type()) {
        for (auto child : get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member and
                child.contains(DW_AT_data_member_location)) {
                auto member_type = child[DW_AT_type].as_type();
                if (child[DW_AT_data_member_location].as_int() %
                    member_type.alignment() != 0) {
                    return true;
                }
                if (member_type.has_unaligned_fields()) {
                    return true;
                }
            }
        }
    }
    return false;
}

std::array<sdb::parameter_class, 2> sdb::type::get_parameter_classes() const {
    std::array<parameter_class, 2> classes = {
        parameter_class::no_class, parameter_class::no_class };

    if (!is_from_dwarf()) {
        switch (get_builtin_type()) {
        case builtin_type::boolean: classes[0] = parameter_class::integer; break;
        case builtin_type::character: classes[0] = parameter_class::integer; break;
        case builtin_type::integer: classes[0] = parameter_class::integer; break;
        case builtin_type::floating_point: classes[0] = parameter_class::sse; break;
        case builtin_type::string: classes[0] = parameter_class::integer; break;
        }
        return classes;
    }

    auto stripped = strip_cv_typedef();
    auto die = stripped.get_die();
    auto tag = die.abbrev_entry()->tag;
    if (tag == DW_TAG_base_type and stripped.byte_size() <= 8) {
        switch (die[DW_AT_encoding].as_int()) {
        case DW_ATE_boolean: classes[0] = parameter_class::integer; break;
        case DW_ATE_float: classes[0] = parameter_class::sse; break;
        case DW_ATE_signed: classes[0] = parameter_class::integer; break;
        case DW_ATE_signed_char: classes[0] = parameter_class::integer; break;
        case DW_ATE_unsigned: classes[0] = parameter_class::integer; break;
        case DW_ATE_unsigned_char: classes[0] = parameter_class::integer; break;
        default: sdb::error::send("Unimplemented base type encoding");
        }
    }
    else if (tag == DW_TAG_pointer_type or
        tag == DW_TAG_reference_type or
        tag == DW_TAG_rvalue_reference_type) {
        classes[0] = parameter_class::integer;
    }
    else if (tag == DW_TAG_base_type and
        die[DW_AT_encoding].as_int() == DW_ATE_float and
        stripped.byte_size() == 16) {
        classes[0] = parameter_class::x87;
        classes[1] = parameter_class::x87up;
    }
    else if (tag == DW_TAG_class_type or
        tag == DW_TAG_structure_type or
        tag == DW_TAG_union_type or
        tag == DW_TAG_array_type) {
        classes = classify_class_type(*this);
    }
    return classes;
}

bool sdb::type::is_class_type() const {
    if (!is_from_dwarf()) return false;
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;
    return tag == DW_TAG_class_type or
        tag == DW_TAG_structure_type or
        tag == DW_TAG_union_type;
}

bool sdb::type::is_reference_type() const {
    if (!is_from_dwarf()) return false;
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;
    return tag == DW_TAG_reference_type or
        tag == DW_TAG_rvalue_reference_type;
}

bool sdb::type::is_non_trivial_for_calls() const {
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;
    if (tag == DW_TAG_class_type or
        tag == DW_TAG_structure_type or
        tag == DW_TAG_union_type) {
        for (auto& child : stripped.children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member and
                child.contains(DW_AT_data_member_location) or
                child.contains(DW_AT_data_bit_offset)) {
                if (child[DW_AT_type].as_type().is_non_trivial_for_calls()) {
                    return true;
                }
            }
            if (child.abbrev_entry()->tag == DW_TAG_inheritance) {
                if (child[DW_AT_type].as_type().is_non_trivial_for_calls()) {
                    return true;
                }
            }
            if (child.contains(DW_AT_virtuality) and
                child[DW_AT_virtuality].as_int() != DW_VIRTUALITY_none) {
                return true;
            }
            if (child.abbrev_entry()->tag == DW_TAG_subprogram) {
                if (is_copy_or_move_constructor(*this, child)) {
                    if (!child.contains(DW_AT_defaulted) or
                        !child[DW_AT_defaulted].as_int() != DW_DEFAULTED_in_class) {
                        return true;
                    }
                }
                else if (is_destructor(child)) {
                    if (!child.contains(DW_AT_defaulted) or
                        !child[DW_AT_defaulted].as_int() != DW_DEFAULTED_in_class) {
                        return true;
                    }
                }
            }
        }
    }
    if (tag == DW_TAG_array_type) {
        return stripped[DW_AT_type].as_type().is_non_trivial_for_calls();
    }
    return false;
}