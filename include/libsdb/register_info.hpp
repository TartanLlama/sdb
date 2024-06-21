#ifndef SDB_REGISTER_INFO_HPP
#define SDB_REGISTER_INFO_HPP

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <sys/user.h>
#include <algorithm>
#include <libsdb/error.hpp>

namespace sdb {
    enum class register_id {
#define DEFINE_REGISTER(name,dwarf_id,size,offset,type,format) name
#include <libsdb/detail/registers.inc>
#undef DEFINE_REGISTER
    };

    enum class register_type {
        gpr, sub_gpr, fpr, dr
    };

    enum class register_format {
        uint, double_float, long_double, vector
    };

    struct register_info {
        register_id id;
        std::string_view name;
        std::int32_t dwarf_id;
        std::size_t size;
        std::size_t offset;
        register_type type;
        register_format format;
    };

    inline constexpr const register_info g_register_infos[] = {
        #define DEFINE_REGISTER(name,dwarf_id,size,offset,type,format) \
            { register_id::name, #name, dwarf_id, size, offset, type, format }
        #include <libsdb/detail/registers.inc>
        #undef DEFINE_REGISTER
    };

    template <class F>
    const register_info& register_info_by(F f) {
        auto it = std::find_if(
            std::begin(g_register_infos),
            std::end(g_register_infos), f);

        if (it == std::end(g_register_infos))
            error::send("Can't find register info");

        return *it;
    }
    inline const register_info& register_info_by_id(register_id id) {
        return register_info_by([id](auto& i) { return i.id == id; });
    }
    inline const register_info& register_info_by_name(std::string_view name) {
        return register_info_by([name](auto& i) { return i.name == name; });
    }
    inline const register_info& register_info_by_dwarf(std::int32_t dwarf_id) {
        return register_info_by([dwarf_id](auto& i) { return i.dwarf_id == dwarf_id; });
    }
}
#endif