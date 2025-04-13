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
