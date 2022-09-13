# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/Havoc_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/Havoc_autogen.dir/ParseCache.txt"
  "Havoc_autogen"
  )
endif()
