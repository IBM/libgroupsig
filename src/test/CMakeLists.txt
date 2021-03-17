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

# Tests for PS16
add_executable(PS16Test test_ps16.cpp)
target_link_libraries(PS16Test
  PUBLIC
  groupsig
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME PS16Test COMMAND PS16Test)

# Tests for KLAP20
add_executable(KLAP20Test test_klap20.cpp)
target_link_libraries(KLAP20Test
  PUBLIC
  groupsig
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME KLAP20Test COMMAND KLAP20Test)

# Tests for DL21
add_executable(DL21Test test_dl21.cpp)
target_link_libraries(DL21Test
  PUBLIC
  groupsig
  big
  sys
  logger
  gtest_main
  gtest
  pthread)
add_test(NAME DL21Test COMMAND DL21Test)

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
