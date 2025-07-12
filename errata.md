# Errata

## Chapter 7: Software Breakpoints

### All `cproc` initializations are wrong

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

## Chapter 9: Hardware Breakpoints and Watchpoints

### Off-by-one error in alignment text

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
