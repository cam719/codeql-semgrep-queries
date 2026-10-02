/**
 * @name Unchecked 32-bit multiplication in a bounds check
 * @description A size comparison whose bound contains a 32-bit multiplication of
 *              a non-constant value. If the product wraps, the check passes for
 *              an attacker-chosen count and the following loop reads or writes
 *              past the buffer. Generalizes CVE-2026-39044 (GStreamer wavparse
 *              cue chunk: `size < 4 + ncues * 24`).
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id custom/unchecked-mul-in-bounds-check
 * @tags security external/cwe/cwe-190 external/cwe/cwe-125
 */

import cpp

from RelationalOperation cmp, MulExpr mul
where
  mul.getParent*() = cmp and
  // a product computed in 32 bits or less can wrap
  mul.getType().getSize() <= 4 and
  not mul.isConstant() and
  // no widening cast on either operand
  not exists(Expr op | op = mul.getAnOperand() |
    op.getFullyConverted().getType().getSize() > 4
  ) and
  not cmp.isInMacroExpansion()
select cmp,
  "Bounds check uses '" + mul.toString() + "', computed in " +
    mul.getType().getSize() * 8 + " bits and unchecked for overflow (CVE-2026-39044 pattern)."
