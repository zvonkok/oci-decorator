cmake_minimum_required (VERSION 2.8)


set(CMAKE_INSTALL_PREFIX /usr/libexec/oci/hooks.d CACHE PATH "hooks default path" FORCE)

project(oci-decorator)

include(CheckCXXCompilerFlag)

function(enable_cxx_compiler_flag_if_supported flag)
  string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
  if(flag_already_set EQUAL -1)
    check_cxx_compiler_flag("${flag}" flag_supported)
    if(flag_supported)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
    endif()
    unset(flag_supported CACHE)
  endif()
endfunction()


enable_cxx_compiler_flag_if_supported("-std=c++11")
enable_cxx_compiler_flag_if_supported("-Wall")
enable_cxx_compiler_flag_if_supported("-Wextra")
enable_cxx_compiler_flag_if_supported("-pedantic")


add_executable(oci-decorator src/oci-decorator.cpp)
target_link_libraries(oci-decorator yajl libconfig++.so.9)





install(TARGETS oci-decorator DESTINATION ${CMAKE_INSTALL_PREFIX})
