# Test suites

# Tests for GL19
add_executable(GL19Test test_gl19.cpp)
target_link_libraries(GL19Test
  PUBLIC
  groupsig
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME GL19Test COMMAND GL19Test)

# Tests for BBS04
add_executable(BBS04Test test_bbs04.cpp)
target_link_libraries(BBS04Test
  PUBLIC
  groupsig
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME BBS04Test COMMAND BBS04Test)

# Tests for Bigz
add_executable(BigzTest test_bigz.cpp)
target_link_libraries(BigzTest
  PUBLIC
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME BigzTest COMMAND BigzTest)
