/**
 * @name Unbounded memcpy from parsed token
 * @description memcpy with length derived from pointer arithmetic or parsed field without max check
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @id custom/unbounded-memcpy-token
 */

import cpp

from FunctionCall memcpyCall, Expr lenArg
where
  memcpyCall.getTarget().hasName("memcpy") and
  lenArg = memcpyCall.getArgument(2) and
  (
    // Length from struct field access (e.g., token.len[N])
    exists(ArrayExpr ae | ae = lenArg and ae.getArrayBase().(DotFieldAccess).getTarget().hasName("len"))
    or
    // Length from subtraction (pointer arithmetic)
    lenArg instanceof SubExpr
  ) and
  not exists(IfStmt guard |
    guard.getThen().getAChild*() = memcpyCall and
    guard.getCondition().toString().matches("%>%")
  )
select memcpyCall, "memcpy with potentially unbounded length from parsed data at " + memcpyCall.getLocation().toString()
