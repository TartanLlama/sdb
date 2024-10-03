# Early Access Upgrade Guide

If you purchased the Early Access version of Building a Debugger and you want to go straight into the chapters that weren't included in that version, this guide shows you all the code modifications that you'll need to make. If you notice something that is not in this guide, please [file an issue](https://github.com/TartanLlama/sdb/issues).

## Chapter 3 - Attaching to a Process

- Add `[[nodiscard]]` to `sdb::error::send` and `send_errno` in *sdb/include/libsdb/error.hpp*

## Chapter 4 - Pipes, procfs, and Automated Testing

- Use `-1` as a null indicator in `sdb::pipe::close_read` and `close_write` in *sdb/src/pipe.cpp*:

```diff
void sdb::pipe::close_read() {
-   if (fds_[read_fd]) {
+   if (fds_[read_fd] != -1) {
        close(fds_[read_fd]);
+       fds_[read_fd] = -1;
    }
}
void sdb::pipe::close_write() {
-    if (fds_[write_fd]) {
+    if (fds_[write_fd] != -1) {
        close(fds_[write_fd]);
+       fds_[write_fd] = -1;
    }
}
```

- Fix off-by-one error in `sdb::process::launch` in *sdb/src/process.cpp*:

```diff
- error::send(std::string(chars, chars + data.size() + 1));
+ error::send(std::string(chars, chars + data.size()));
```

- Remove broken test case in *sdb/test/tests.cpp*:

```diff
TEST_CASE("process::resume already terminated", "[process]") {
-   {
        auto proc = process::launch("targets/end_immediately");
        proc->resume();
        proc->wait_on_signal();
        REQUIRE_THROWS_AS(proc->resume(), error);
-   }

-   {
-       auto target = process::launch("targets/end_immediately", false);
-       auto proc = process::attach(target->pid());
-       proc->resume();
-       proc->wait_on_signal();
-       REQUIRE_THROWS_AS(proc->resume(), error);
-   }
}
```

## Chapter 5 - Registers

- Correct the superregister for `dil` in *sdb/include/libsdb/detail/registers.inc*:

```diff
- DEFINE_GPR_8L(sil, rsi), DEFINE_GPR_8L(dil, rsi),
+ DEFINE_GPR_8L(sil, rsi), DEFINE_GPR_8L(dil, rdi),
```
- Correct parameter name for `sdb::process::write_gprs`:

```diff
-  void write_gprs(const user_regs_struct& fprs);
+  void write_gprs(const user_regs_struct& gprs);
```

- Don't fill leftover bytes in `widen` in *sdb/src/registers.cpp*, as this is done in the implementation of `to_byte128`:

```diff
- auto ret = to_byte128(t);
- std::fill(as_bytes(ret) + sizeof(T),
-     as_bytes(ret) + info.size + 1, std::byte(0));
- return ret;
+ return to_byte128(t);
```

- Add `default` case to switch in `sdb::registers::read` in *sdb/src/registers.cpp*:

```diff
    if (info.format == register_format::uint) {
        switch (info.size) {
        case 1: return from_bytes<std::uint8_t>(bytes + info.offset);
        case 2: return from_bytes<std::uint16_t>(bytes + info.offset);
        case 4: return from_bytes<std::uint32_t>(bytes + info.offset);
        case 8: return from_bytes<std::uint64_t>(bytes + info.offset);
+       default: sdb::error::send("Unexpected register size");
        }
    }
```

- Use `info.size` instead of `sizeof(v)` in `sdb::registers::write` in *sdb/src/registers.cpp*:

```diff
- std::copy(val_bytes, val_bytes + info.size, bytes + info.offset);
+ std::copy(val_bytes, val_bytes + sizeof(v), bytes + info.offset);
```

## Chapter 6 - Testing Registers with x64 Assembly

- In `sdb::process::launch` in *sdb/src/process.cpp*, do not call `close(STDOUT_FILENO)`, as this is already handled by `dup2`:
```diff
- close(STDOUT_FILENO);
  if (dup2(*stdout_replacement, STDOUT_FILENO) < 0) {
      exit_with_perror(channel, "stdout replacement failed");
  }
```
- Move definitions of `to_integral`, `to_float`, and `parse_vector` from *sdb/tools/sdb.cpp* into new *sdb/include/libsdb/parse.hpp* header, including the specialization of `to_integral<std::byte>` **and mark it as `inline`**:
```cpp
#ifndef SDB_PARSE_HPP
#define SDB_PARSE_HPP

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <array>

namespace sdb {
    template <class I>
    std::optional<I> to_integral(std::string_view sv, int base = 10) {
        --snip--
    }

    template<>
    //NOTE THE INLINE HERE
    inline std::optional<std::byte> to_integral(std::string_view sv, int base) {
        --snip--
    }

    template <std::size_t N>
    auto parse_vector(std::string_view text) {
        --snip--
    }


    template <class F>
    std::optional<F> to_float(std::string_view sv) {
        --snip--
    }
}

#endif
```

- Prefix calls to the above functions in *sdb/tools/sdb.cpp* with `sdb::`.
- Change header includes in *sdb/tools/sdb.cpp*:
```diff
- #include <charconv>
+ #include <fmt/ranges.h>
+ #include <libsdb/parse.hpp>
```
- Change `lea` in *sdb/test/targets/reg_write.s* to `leaq`:
```diff
- lea      hex_format(%rip), %rdi
+ leaq     hex_format(%rip), %rdi
```

## Chapter 7 - Software Breakpoints

- Add `sdb::` to calls to `to_integral` in *sdb/tools/sdb.cpp*
- Use parentheses instead of braces in `get_load_address` in *sdb/test/tests.cpp*, and throw an exception at the end of the function: 
```diff
    virt_addr get_load_address(pid_t pid, std::int64_t offset) {
        --snip--
-               return virt_addr{ offset - file_offset + low_range };
+               return virt_addr(offset - file_offset + low_range);
            }
        }
+       sdb::error::send("Could not find load address");
    }
```
- Correct `get_entry_point` in *sdb/test/tests.cpp* to compute the file offset rather than file address:
```diff
-   std::int64_t get_entry_point(std::filesystem::path path) {
+   std::int64_t get_entry_point_offset(std::filesystem::path path) {
        std::ifstream elf_file(path);

        Elf64_Ehdr header;
        elf_file.read(reinterpret_cast<char*>(&header), sizeof(header));
-       return header.e_entry;
+
+       auto entry_file_address = header.e_entry;
+
+       auto command = std::string("readelf -S ") + path.string() + " | grep .text";
+       auto pipe = popen(command.c_str(), "r");
+       std::string data;
+       data.resize(1024);
+       std::fgets(data.data(), data.size(), pipe);
+       pclose(pipe);
+
+       std::regex text_regex(R"(PROGBITS\s+(\w{16})\s+(\w{8}))");
+       std::smatch groups;
+       std::regex_search(data, groups, text_regex);
+
+       auto address = std::stol(groups[1], nullptr, 16);
+       auto offset = std::stol(groups[2], nullptr, 16);
+       auto load_bias = address - offset;
+
+       return header.e_entry - load_bias;
    }
```
- Update the call to `get_entry_point` in *sdb/test/tests.cpp* to call `get_entry_point_offset`:
```diff
-    auto offset = get_entry_point("targets/hello_sdb");
+    auto offset = get_entry_point_offset("targets/hello_sdb");
```
## Chapter 8 - Memory and Disassembly

- Put `span` in *sdb/include/libsdb/types.hpp* in the `sdb` namespace
- New definition of `sdb::process::read_memory` in *sdb/src/process.cpp* that can handle partial reads:
```cpp
std::vector<std::byte>
sdb::process::read_memory(
      virt_addr address, std::size_t amount) const {
    std::vector<std::byte> ret(amount);

    iovec local_desc{ ret.data(), ret.size() };
    std::vector<iovec> remote_descs;
    while (amount > 0) {
        auto up_to_next_page = 0x1000 - (address.addr() & 0xfff);
        auto chunk_size = std::min(amount, up_to_next_page);
        remote_descs.push_back({ reinterpret_cast<void*>(address.addr()), chunk_size });
        amount -= chunk_size;
        address += chunk_size;
    }

    if (process_vm_readv(pid_, &local_desc, /*liovcnt=*/1,
        remote_descs.data(), /*riovcnt=*/remote_descs.size(), /*flags=*/0) < 0) {
        error::send_errno("Could not read process memory");
    }
    return ret;
}
```
- Add `sdb::` to all calls to `to_integral` and `parse_vector` in *sdb/tools/sdb.cpp*
- Move definition of `parse_vector(std::string_view text)` into *sdb/include/libsdb/parse.hpp* and add the `inline` specifier
- Add `#include <unistd.h>` to *sdb/src/process.cpp*
- Correct assignment to `*address` in `sdb::disassembler::disassemble` in *sdb/src/disassembler.cpp*:
```diff
- *address = process->get_pc();
+ address.emplace(process_->get_pc());
```
- In `sdb::process::read_memory_without_traps` in *sdb/src/process.cpp*, do not attempt to remove traps for breakpoints that are disabled:
```diff
std::vector<std::byte>
sdb::process::read_memory_without_traps(
     virt_addr address, std::size_t amount) const {
    --snip--
    for (auto site : sites) {
+       if (!site->is_enabled()) continue;
        auto offset = site->address() - address.addr();
        memory[offset.addr()] = site->saved_data_;
    }
    --snip--
}
```

## Chapter 9 - Hardware Breakpoints and Watchpoints

- Make `sdb::process::read_memory_without_traps` in *sdb/src/process.cpp* ignore hardware breakpoints:
```diff
std::vector<std::byte>
sdb::process::read_memory_without_traps(
      virt_addr address, std::size_t amount) const {
    ___--snip--___
    for (auto site : sites) {
-       if (!site->is_enabled()) continue;
+       if (!site->is_enabled() or site->is_hardware()) continue;
        --snip--
    }
    --snip--
}
```
- Add `default` case to the `switch` statement in `encode_hardware_stoppoint_mode` in *sdb/src/process.cpp*:
```diff
+ default: sdb::error::send("Invalid stoppoint mode");
```
- Add `sdb::` to calls to `to_integral` in *sdb/tools/sdb.cpp*
- Add `default` case to the `switch` statement in `handle_breakpoint_list` in *sdb/tools/sdb.cpp*:
```diff
+ default: sdb::error::send("Invalid stoppoint mode");
```
- Remove additional call to `process->wait_on_signal` from the "Watchpoint detects read" test in *sdb/test/tests.cpp*:
```diff
    proc->resume();
-   proc->wait_on_signal();
    auto reason = proc->wait_on_signal();
```

## Chapter 10 - Signals and Syscalls

- Add `#include <csignal>` to *sdb/tools/sdb.cpp*
- Change the type of `syscall_information::id` in *sdb/include/libsdb/process.hpp*:
```diff
    struct syscall_information {
-       std::uint8_t id;
+       std::uint16_t id; 
        bool entry; 
        union { 
            std::array<std::uint64_t, 6> args;
            std::int64_t ret;
        };
    };
```
- Initialize `reason.trap_reason` to `sdb::trap_reason::unknown` in `sdb::process::augment_stop_reason` in *sdb/src/process.cpp*:
```diff
    expecting_syscall_exit_ = false;

+   reason.trap_reason = trap_type::unknown;
    if (reason.info == SIGTRAP) {
```
- Initialize `message` in `get_sigtrap_info` in *sdb/src/process.cpp* to `" "`:
```diff
- std::string message;
+ std::string message = " ";
```
- In the "Syscall catchpoints work" test in *sdb/test/tests.cpp*, `#include <fcntl.h>` and redirect `stdout` to `/dev/null`:
```diff
+ #include <fcntl.h>
  TEST_CASE("Syscall catchpoints work", "[catchpoint]") {
+     auto dev_null = open("/dev/null", O_WRONLY);
+     auto proc = process::launch("targets/anti_debugger", true, dev_null);
-     auto proc = process::launch("targets/anti_debugger");
      --snip--
+     close(dev_null);
}
```
- Add a space to the start of the `(breakpoint {})` message in `get_sigtrap_info` in *sdb/tools/sdb.cpp*:
```diff
- return fmt::format("(breakpoint {})", site.id());
+ return fmt::format(" (breakpoint {})", site.id());
```
