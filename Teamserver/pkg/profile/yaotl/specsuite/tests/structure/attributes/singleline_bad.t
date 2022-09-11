# This test verifies that comma-separated attributes on the same line are
# reported as an error, rather than being parsed like an object constructor
# expression.

diagnostics {
  error {
    # Message like "missing newline after argument" or "each argument must be on its own line"
    from {
      line   = 1
      column = 14
      byte   = 13
    }
    to {
      line   = 1
      column = 15
      byte   = 14
    }
  }
}
