/**
 * @name Unbounded hex decode into fixed buffer
 * @description Function call decodes hex data with length from strlen into fixed-size buffer
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @id custom/unbounded-hex-decode
 */

import cpp

from FunctionCall hexCall, FunctionCall strlenCall
where
  hexCall.getTarget().hasName("hex_to_binary") and
  strlenCall.getTarget().hasName("strlen") and
  hexCall.getArgument(1) = strlenCall and
  not exists(IfStmt guard |
    guard.getCondition().getAChild*().(FunctionCall).getTarget().hasName("strlen") and
    guard.getAChild*() = hexCall
  )
select hexCall, "hex_to_binary called with strlen as length without prior bounds check on input at " + hexCall.getLocation().toString()
