# This test ensures that we can successfully parse an empty file.
# Since an empty file has no content, the hcldec spec for this test is
# just a literal value, which we test below.

result = "ok"

traversals {
  # Explicitly no traversals
}
