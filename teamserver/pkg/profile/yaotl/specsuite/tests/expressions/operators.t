result = {
  equality = {
    "==" = {
      exactly              = true
      not                  = false
      type_mismatch_number = false
      type_mismatch_bool   = false
    }
    "!=" = {
      exactly              = false
      not                  = true
      type_mismatch_number = true
      type_mismatch_bool   = true
    }
  }
  inequality = {
    "<" = {
      lt = true
      gt = false
      eq = false
    }
    "<=" = {
      lt = true
      gt = false
      eq = true
    }
    ">" = {
      lt = false
      gt = true
      eq = false
    }
    ">=" = {
      lt = false
      gt = true
      eq = true
    }
  }
  arithmetic = {
    add      = 5.5
    add_big  = 4.14159265358979323846264338327950288419716939937510582097494459
    sub      = 1.5
    sub_neg  = -1.5
    mul      = 9
    div      = 0.1
    mod      = 1
    mod_frac = 0.80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024
  }
  logical_binary = {
    "&&" = {
      tt = true
      tf = false
      ft = false
      ff = false
    }
    "||" = {
      tt = true
      tf = true
      ft = true
      ff = false
    }
  }
  logical_unary = {
    "!" = {
      t = false
      f = true
    }
  }
  conditional = {
    t = "a"
    f = "b"
  }
}
result_type = object({
  equality = map(object({
    exactly              = bool
    not                  = bool
    type_mismatch_number = bool
    type_mismatch_bool   = bool
  }))
  inequality = map(object({
    lt  = bool
    gt  = bool
    eq  = bool
  }))
  arithmetic = object({
    add      = number
    add_big  = number
    sub      = number
    sub_neg  = number
    mul      = number
    div      = number
    mod      = number
    mod_frac = number
  })
  logical_binary = map(object({
    tt  = bool
    tf  = bool
    ft  = bool
    ff  = bool
  }))
  logical_unary = map(object({
    t   = bool
    f   = bool
  }))
  conditional = object({
    t   = string
    f   = string
  })
})
