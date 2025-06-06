cmake_minimum_required (VERSION 3.10)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy (SET CMP0141 NEW)
  set (CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif ()

# Create the project
project (rrlog)

# Set our C++ standard
set (CMAKE_CXX_STANDARD 23)

# Set our output directories
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include the FetchContent module
include (FetchContent)

# Fetch the latest version of nlohmann/json
FetchContent_Declare (
	json 
	URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable (json)

# Set the header files.
set (HDR
	"include/native.hpp"
	"include/memory.hpp"

	"include/rbx/offsets.hpp"
	"include/rbx/scanner.hpp"
)

# Set the source files.
set (SRC
	"src/main.cpp"
	"src/memory.cpp"

	"src/rbx/offsets.cpp"
	"src/rbx/scanner.cpp"
)

# Add the DLL target
add_library (rrlog SHARED ${HDR} ${SRC})

# Set the include directories for the target
target_include_directories (rrlog PRIVATE "include")

# Link libraries to the target
target_link_libraries(rrlog PRIVATE nlohmann_json::nlohmann_json)