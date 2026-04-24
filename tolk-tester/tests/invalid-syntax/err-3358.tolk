fun main() {
    return tos("0.1234567891");
}

/**
@compilation_should_fail
@stderr too many digits after a dot, nanotomis are 10^9
 */
