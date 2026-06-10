cmake_minimum_required(VERSION 3.10)
project(ctminer_arm_extreme CXX)

# Force C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CRITICAL: Extreme Optimization & Hardware Silicon Flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=armv8-a+crypto -funroll-loops -flto -pthread")

# Source files
set(SOURCE_FILES src/miner.cpp)

# Define executable
add_executable(ctminer-arm-extreme ${SOURCE_FILES})

# Link threading library
target_link_libraries(ctminer-arm-extreme pthread)
