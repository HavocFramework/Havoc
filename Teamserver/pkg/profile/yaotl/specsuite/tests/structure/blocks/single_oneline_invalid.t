diagnostics {
  error {
    # Message like "Only one argument is allowed in a single-line block definition"
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
  error {
    # Message like "The closing brace for a single-line block definition must be on the same line"
    from {
      line   = 2
      column = 14
      byte   = 40
    }
    to {
      line   = 3
      column = 1
      byte   = 41
    }
  }
  error {
    # Message like "The closing brace for a single-line block definition must be on the same line"
    from {
      line   = 4
      column = 14
      byte   = 56
    }
    to {
      line   = 5
      column = 1
      byte   = 57
    }
  }
  error {
    # Message like "The closing brace for a single-line block definition must be on the same line"
    from {
      line   = 6
      column = 14
      byte   = 84
    }
    to {
      line   = 7
      column = 1
      byte   = 85
    }
  }
  error {
    # Message like "A single-line block definition cannot contain another block definition"
    from {
      line   = 9
      column = 5
      byte   = 103
    }
    to {
      line   = 9
      column = 8
      byte   = 106
    }
  }
}
