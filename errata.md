# Errata

## Chapter 6: Testing Registers with x64 Assembly

### p120 - Missing include for *sdb/error.hpp*

`parse_vector` in *sdb/include/libsdb/parse.hpp* uses `sdb::error` but includes neither the required header nor any header that includes it.

```diff
  #include <array>
  #include <cstddef>
+ #include <libsdb/error.hpp>
```
## Chapter 7: Software Breakpoints

### p141-142 - All `cproc` initializations are wrong

The initializations of `cproc` in *sdb/test/tests.cpp* initialize `const` references to `std::unique_ptr`, but `std::unique_ptr` doesn't maintain `const` through dereferences, so uses of this operate on non-`const` `sdb::process` objects. These changes fix this, capturing instead `const sdb::process*` pointers:

```diff
TEST_CASE("Can find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
-   const auto& cproc = proc;
+   const auto* cproc = proc.get();
```

```diff
TEST_CASE("Cannot find breakpoint site", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
-   const auto& cproc = proc;
+   const auto* cproc = proc.get();
```

```diff
TEST_CASE("Breakpoint site list size and emptiness", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
-   const auto& cproc = proc;
+   const auto* cproc = proc.get();
```

```diff
TEST_CASE("Can iterate breakpoint sites", "[breakpoint]") {
    auto proc = process::launch("targets/run_endlessly");
-   const auto& cproc = proc;
+   const auto* cproc = proc.get();
```

### p143 - Inverted boolean

There is an inverted boolean in the text. The code is correct, however.

```diff
  We then create a couple of breakpoint sites and ensure that the size increments as expected and that empty now returns
- true.
+ false.
```

## Chapter 9: Hardware Breakpoints and Watchpoints

### p194 - Wrong binary representation of Enable flag in Debug Control Register

The example says `we want to set a read/write stop point of size 8 on debug register 2`, but
the reported `Enable flag` shows the wrong bits set.

```diff
- Enable flag:    00000000 00000000 00000000 01000000
+ Enable flag:    00000000 00000000 00000000 00010000
```

### p205 - Off-by-one error in alignment text

The text incorrectly describes aligning addresses. The code is correct, however.

```diff
If the size of the breakpoint is 8, the least significant
- 4
+ 3
bits of the address must be 0 for the address to be aligned. Because address & (8 - 1) is
- address & 0b1111,
+ address & 0b111,
we ensure that this calculation results in 0.
```

## Chapter 12: Debug Information

### p335 - Strict DWARF needed

The "Correct DWARF Language" test checks against `DW_LANG_C_plus_plus`. However, Clang may output DWARF 5 attributes such as `DW_LANG_C_plus_plus_14` even in DWARF 4 mode, unless `-gdwarf-strict` is passed. The code should either pass this flag, or test against the `DW_LANG_C_plus_plus_XXX` values [specified here](https://dwarfstd.org/languages.html).
