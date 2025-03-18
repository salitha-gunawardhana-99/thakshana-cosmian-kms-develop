# Specify the minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Define the project name
project(HelloWorld)

# Specify the C++ standard to use
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add an executable target
add_executable(HelloWorld main.cpp)
