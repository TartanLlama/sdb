# Early Access Upgrade Guide

## Chapter 3

- Add `[[nodiscard]]` to `sdb::error::send` and `send_errno` in *sdb/include/libsdb/error.hpp*

## Chapter 4


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

- Fix off-by-one error in `sdb::process::launch` in *sdb/src/process.cpp:

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

## Chapter 5

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

## Chapter 6

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
- leaq     hex_format(%rip), %rdi
+ leaq     hex_format(%rip), %rdi
```

## Chapter 7

- Use parentheses instead of braces in `get_load_address` in *sdb/test/tests.cpp*, and throw an exception at the end of the function: 
```diff
    virt_addr get_load_address(pid_t pid, std::int64_t offset) {
        --snip--
-               return virt_addr{ offset - file_offset + low_range };
+               return virt_addr(offset - file_offset + low_range);
            }
        }
+		sdb::error::send("Could not find load address");
    }
- 
