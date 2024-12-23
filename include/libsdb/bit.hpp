#ifndef SDB_BIT_HPP
#define SDB_BIT_HPP

#include <cstring>
#include <libsdb/types.hpp>
#include <vector>
#include <string_view>

namespace sdb {
    template <class To>
    To from_bytes(const std::byte* bytes) {
        To ret;
        std::memcpy(&ret, bytes, sizeof(To));
        return ret;
    }

    template <class From>
    std::byte* as_bytes(From& from) {
        return reinterpret_cast<std::byte*>(&from);
    }

    template <class From>
    const std::byte* as_bytes(const From& from) {
        return reinterpret_cast<const std::byte*>(&from);
    }

    template <class From>
    byte128 to_byte128(From src) {
        byte128 ret{};
        std::memcpy(&ret, &src, sizeof(From));
        return ret;
    }

    template <class From>
    byte64 to_byte64(From src) {
        byte64 ret{};
        std::memcpy(&ret, &src, sizeof(From));
        return ret;
    }

    inline std::string_view to_string_view(
        const std::byte* data, std::size_t size) {
        return { reinterpret_cast<const char*>(data), size };
    }

    inline std::string_view to_string_view(
        const std::vector<std::byte>& data) {
        return to_string_view(data.data(), data.size());
    }

    inline void memcpy_bits(std::uint8_t* dest, std::uint32_t dest_bit,
        const std::uint8_t* src, std::uint32_t src_bit,
        std::uint32_t n_bits) {
        for (; n_bits; --n_bits, ++src_bit, ++dest_bit) {
            std::uint8_t dest_mask = 1 << (dest_bit % 8);
            dest[dest_bit / 8] &= ~dest_mask;

            auto src_mask = 1 << (src_bit % 8);
            auto corresponding_src_bit_set = src[src_bit / 8] & src_mask;
            if (corresponding_src_bit_set) {
                dest[dest_bit / 8] |= dest_mask;
            }
        }
    }

    template <class From>
    sdb::span<const std::byte> to_byte_span(const From& from) {
        return { as_bytes(from), sizeof(From) };
    }

    template <class From>
    std::vector<std::byte> to_byte_vec(const From& from) {
        std::vector<std::byte> ret(sizeof(From));
        std::memcpy(ret.data(), as_bytes(from), sizeof(From));
        return ret;
    }
}

#endif