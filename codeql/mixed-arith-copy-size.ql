/**
 * @name Mixed addition/subtraction in copy size argument
 * @description Copy size expression contains both + and - on variables,
 *              requiring manual verification of each operator's sign.
 *              Broader variant of the CVE-2026-7270 pattern.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @id custom/mixed-arith-copy-size
 */

import cpp

from FunctionCall call, Expr sizeArg
where
  (
    call.getTarget().hasGlobalName("memmove") or
    call.getTarget().hasGlobalName("memcpy") or
    call.getTarget().hasGlobalName("bcopy") or
    call.getTarget().hasGlobalName("wmemmove") or
    call.getTarget().hasGlobalName("wmemcpy")
  ) and
  sizeArg = call.getArgument(2) and
  exists(SubExpr sub | sub.getParent*() = sizeArg) and
  exists(AddExpr add | add.getParent*() = sizeArg) and
  exists(VariableAccess va | va.getParent*() = sizeArg)
select call,
  "Copy size at $@ mixes + and - operators on variables. " +
  "Review each operator: wrong sign causes OOB by 2x operand.",
  sizeArg, "size expression"
