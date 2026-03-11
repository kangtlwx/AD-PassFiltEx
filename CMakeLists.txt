cmake_minimum_required(VERSION 3.18)
project(PassFiltEx LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PassFiltExPolicy STATIC src/PasswordPolicy.cpp)
target_include_directories(PassFiltExPolicy PUBLIC src)

if(WIN32)
    add_library(PassFiltEx SHARED src/PassFiltEx.cpp src/PassFiltEx.def)
    target_link_libraries(PassFiltEx PRIVATE PassFiltExPolicy)
    set_target_properties(PassFiltEx PROPERTIES PREFIX "" OUTPUT_NAME "PassFiltEx")
endif()

option(PASSFILTEX_BUILD_TESTS "Build policy tests" ON)
if(PASSFILTEX_BUILD_TESTS)
    add_executable(password_policy_test tests/password_policy_test.cpp)
    target_link_libraries(password_policy_test PRIVATE PassFiltExPolicy)
endif()
