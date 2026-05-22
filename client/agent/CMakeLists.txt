cmake_minimum_required(VERSION 3.16)
project(voidwatch_agent C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3 /O2 /D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -O2)
endif()

add_executable(voidwatch_agent
    src/main.c
    src/log.c
    src/json.c
    src/config.c
    src/metadata.c
    src/network_collector.c
    src/process_collector.c
    src/sender.c
    src/enroll.c
)

target_include_directories(voidwatch_agent PRIVATE src)

target_link_libraries(voidwatch_agent
    ws2_32
    winhttp
    iphlpapi
    wintrust
    psapi
    advapi32
    ole32
    ntdll
)

# Place the exe in the agent root for easy access
set_target_properties(voidwatch_agent PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_SOURCE_DIR}"
)
