file(GLOB ${PROJECT_NAME}_SOURCES *.cpp)
file(GLOB ${PROJECT_NAME}_HEADERS *.h)
file(GLOB_RECURSE ${PROJECT_NAME}_HEADERS cppcodec/*.hpp)

set(${PROJECT_NAME}_DEPS
    ${${PROJECT_NAME}_SOURCES}
    ${${PROJECT_NAME}_HEADERS}
)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_DEPS})

target_link_libraries(${PROJECT_NAME}
    crypto
    ws2_32
)
