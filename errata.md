# Errata

## Chapter 19: Dwarf Expressions

**Page 580**: The calls to `expr->expr.eval` for `expr_rule` and `val_expr` rule should pass `true` as the last argument to push the CFA to the stack before evaluating the expression.

```diff
            else if (auto expr = std::get_if<expr_rule>(&rule)) {
-               auto res = expr->expr.eval(proc, old_regs);
+               auto res = expr->expr.eval(proc, old_regs, true);
                auto addr = dwexp_addr_result(res);
                auto value = proc.read_memory_as<std::uint64_t>(addr);
                unwound_regs.write(reg_info, { value }, false);
            }
            else if (auto val_expr = std::get_if<val_expr_rule>(&rule)) {
-               auto res = val_expr->expr.eval(proc, old_regs);
+               auto res = val_expr->expr.eval(proc, old_regs, true);
                auto addr = dwexp_addr_result(res);
                unwound_regs.write(reg_info, { addr.addr() }, false);
            }
