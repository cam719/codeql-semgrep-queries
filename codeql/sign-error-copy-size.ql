/**
 * @name Arithmetic sign error in copy/move size
 * @description memmove/memcpy size uses addition where subtraction is likely
 *              intended (e.g., end - base + consumed instead of end - base - consumed).
 *              CVE-2026-7270 pattern: wrong operator in memmove size caused
 *              2*consume bytes of OOB write in FreeBSD kernel exec path.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @id custom/sign-error-copy-size
 */

import cpp

from FunctionCall call, Expr sizeArg, AddExpr add, SubExpr sub
where
  (
    call.getTarget().hasGlobalName("memmove") or
    call.getTarget().hasGlobalName("memcpy") or
    call.getTarget().hasGlobalName("bcopy")
  ) and
  sizeArg = call.getArgument(2) and
  add = sizeArg and
  (
    sub = add.getLeftOperand() or
    sub = add.getRightOperand()
  ) and
  (
    sub.getLeftOperand().getType() instanceof PointerType or
    sub.getLeftOperand().getType().hasName("size_t") or
    sub.getLeftOperand().getType().hasName("ssize_t") or
    sub.getLeftOperand().getType().hasName("ptrdiff_t")
  )
select call,
  "Copy size is (ptr_diff) + offset at $@. Verify sign: should + be - ? " +
  "Pattern matches CVE-2026-7270 (memmove OOB via wrong operator).",
  sizeArg, "size expression"
