/**
 * @name Assert-only array bounds check
 * @description Array access where bounds are only verified by assert (removed in release builds)
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @id custom/assert-only-bounds
 */

import cpp

from ArrayExpr access, FunctionCall assertCall
where
  exists(MacroInvocation mi |
    mi.getMacroName() = "assert" and
    mi.getAnExpandedElement() = assertCall and
    assertCall.getEnclosingFunction() = access.getEnclosingFunction() and
    assertCall.getLocation().getStartLine() < access.getLocation().getStartLine() and
    access.getLocation().getStartLine() - assertCall.getLocation().getStartLine() < 5
  )
select access, "Array access at " + access.getLocation().toString() + " protected only by assert (removed in release builds)"
