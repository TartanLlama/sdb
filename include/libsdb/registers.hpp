#ifndef SDB_REGISTERS_HPP
#define SDB_REGISTERS_HPP

#include <sys/user.h>
#include <libsdb/register_info.hpp>
#include <variant>
#include <libsdb/types.hpp>

namespace sdb {
    class process;
    class registers {
    public:
        registers() = default;
        registers(const registers&) = default;
        registers& operator=(const registers&) = default;

        using value = std::variant<
            std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t,
            std::int8_t, std::int16_t, std::int32_t, std::int64_t,
            float, double, long double,
            byte64, byte128>;
        value read(const register_info& info) const;       
        void write(const register_info& info, value val, bool commit = true);

        template <class T>
        T read_by_id_as(register_id id) const {
            return std::get<T>(read(register_info_by_id(id)));
        }
        void write_by_id(register_id id, value val, bool commit = true) {
            write(register_info_by_id(id), val, commit);
        }
        bool is_undefined(register_id id) const;
        void undefine(register_id id);

        virt_addr cfa() const { return cfa_; }
        void set_cfa(virt_addr addr) { cfa_ = addr; }
        void flush();

    private:
        friend process;
        registers(process& proc) : proc_(&proc) {}

        user data_;
        process* proc_;
        std::vector<std::size_t> undefined_;
        virt_addr cfa_;
    };
}

#endif