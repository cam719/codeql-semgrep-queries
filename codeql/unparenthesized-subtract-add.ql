/**
 * @name Subtract-then-add without parentheses in size arithmetic
 * @description An expression of the form `a - b + c`, where `c` is not a
 *              constant. C parses this as `(a - b) + c`. When the author meant
 *              `a - (b + c)`, the result is too large by `2*c`, which turns a
 *              remaining-space or length calculation into a heap overflow.
 *              Generalizes CVE-2026-39043 (GStreamer matroskademux bz2
 *              decompression: `new_size - (hi << 32) + lo`).
 * @kind problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id custom/unparenthesized-subtract-add
 * @tags security external/cwe/cwe-783 external/cwe/cwe-131
 */

import cpp

from AddExpr add, SubExpr sub
where
  sub = add.getLeftOperand() and
  // written as `a - b + c`, not `(a - b) + c`
  not sub.isParenthesised() and
  // `end - start + 1` and similar constant adjustments are idiomatic
  not add.getRightOperand().isConstant() and
  // pointer arithmetic is handled by the copy-size queries
  not add.getType() instanceof PointerType and
  not add.isInMacroExpansion()
select add,
  "'" + sub.getLeftOperand().toString() + " - " + sub.getRightOperand().toString() +
    " + " + add.getRightOperand().toString() +
    "' parses as '(a - b) + c'. If 'a - (b + c)' was intended, the result is too large (CVE-2026-39043 pattern)."
