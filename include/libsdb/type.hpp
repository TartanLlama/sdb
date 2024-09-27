#ifndef SDB_TYPE_HPP
#define SDB_TYPE_HPP

#include <string_view>
#include <optional>
#include <libsdb/dwarf.hpp>
#include <vector>

namespace sdb {
    class type {
    public:
        type(die die)
            : die_(std::move(die)) {}

        die get_die() const { return die_; }

        std::size_t byte_size() const;

        bool is_char_type() const;

        template<int... Tags>
        type strip() const {
            auto ret = *this;
            auto tag = ret.get_die().abbrev_entry()->tag;
            while (((tag == Tags) or ...)) {
                ret = ret.get_die()[DW_AT_type].as_type().get_die();
                tag = ret.get_die().abbrev_entry()->tag;
            }
            return ret;
        }

        type strip_cv_typedef() const {
            return strip<DW_TAG_const_type,
                DW_TAG_volatile_type,
                DW_TAG_typedef>();
        }
        type strip_cvref_typedef() const {
            return strip<DW_TAG_const_type,
                DW_TAG_volatile_type,
                DW_TAG_typedef,
                DW_TAG_reference_type,
                DW_TAG_rvalue_reference_type>();
        }
        type strip_all() const {
            return strip<DW_TAG_const_type,
                DW_TAG_volatile_type,
                DW_TAG_typedef,
                DW_TAG_reference_type,
                DW_TAG_rvalue_reference_type, 
                DW_TAG_pointer_type>();
        }

    private:
        std::size_t compute_byte_size() const;

        die die_;
        mutable std::optional<std::size_t> byte_size_;
    };

    class process;
    class typed_data {
    public:
        typed_data(std::vector<std::byte> data, type value_type,
            std::optional<virt_addr> address = std::nullopt)
            : data_(std::move(data)), type_(value_type), address_(address) {}

        const std::vector<std::byte>& data() const { return data_; }
        const std::byte* data_ptr() const { return data_.data(); }
        const type& value_type() const { return type_; }
        std::optional<virt_addr> address() const { return address_; }

        typed_data fixup_bitfield(
            const sdb::process& proc, const sdb::die& member_die) const;
        std::string visualize(const sdb::process& proc, int depth = 0) const;

        typed_data deref_pointer(
            const sdb::process& proc) const;
        typed_data read_member(
            const sdb::process& proc,
            std::string_view member_name) const;
        typed_data index(
            const sdb::process& proc,
            std::size_t index) const;

    private:
        std::vector<std::byte> data_;
        type type_;
        std::optional<virt_addr> address_;
    };
}

#endif