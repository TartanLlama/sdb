#ifndef SDB_SYSCALLS_HPP
#define SDB_SYSCALLS_HPP

#include <string_view>

namespace sdb {
    std::string_view syscall_id_to_name(int id);
    int syscall_name_to_id(std::string_view name);
}

#endif