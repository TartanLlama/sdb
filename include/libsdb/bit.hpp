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
}

#endif