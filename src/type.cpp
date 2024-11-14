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
                auto member_str = data.visualize(proc, depth + 1);
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