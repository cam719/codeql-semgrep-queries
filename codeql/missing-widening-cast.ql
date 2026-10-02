/**
 * @name Missing widening cast in multiplication assigned to 64-bit
 * @description int*int multiplication assigned to 64-bit type without cast — potential overflow
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @id custom/missing-widening-cast
 */

import cpp

from AssignExpr assign, MulExpr mul
where
  assign.getRValue().getAChild*() = mul and
  mul.getType().getSize() <= 4 and
  (
    assign.getLValue().getType().getSize() >= 8
    or
    assign.getLValue().getType().getName() = "sf_count_t"
  ) and
  not exists(Cast cast |
    cast.getExpr() = mul.getAnOperand() and
    cast.getType().getSize() >= 8
  )
select assign, "int*int multiplication assigned to wider type without widening cast at " + assign.getLocation().toString()
