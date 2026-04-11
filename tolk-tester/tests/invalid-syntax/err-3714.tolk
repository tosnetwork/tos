fun main(am: slice) {
    return tos(am);
}

/**
@compilation_should_fail
@stderr function `tos` requires a constant string, like `tos("0.05")`
 */
