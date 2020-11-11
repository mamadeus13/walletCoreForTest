file(GLOB_RECURSE test_stuff FirstTest.cpp )

add_executable(firstTest ${test_stuff})

target_link_libraries(firstTest gtest_main TrezorCrypto walletconsolelib TrustWalletCore  protobuf) #Boost::boost walletconsolelib)
target_include_directories(firstTest PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_options(firstTest PRIVATE "-Wall")

option(CODE_COVERAGE "Enable coverage reporting" OFF)
if(CODE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Add required flags (GCC & LLVM/Clang)
    target_compile_options(firstTest INTERFACE
        -O0        # no optimization
        -g         # generate debug info
        --coverage # sets all required flags
    )
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_options(firstTest INTERFACE --coverage)
    else()
        target_link_libraries(firstTest INTERFACE --coverage)
    endif()
endif()


target_include_directories(firstTest
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)