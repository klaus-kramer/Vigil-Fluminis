cmake_minimum_required(VERSION 3.20)
project("Vigil Fluminis" VERSION 0.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOUIC_SEARCH_PATHS resources/ui)

set(QT_PATH "S:/prog/Qt/6.9.3/msvc2022_64" CACHE PATH "Path to Qt installation")
list(PREPEND CMAKE_PREFIX_PATH "${QT_PATH}")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

# --- llama.cpp ---
include(FetchContent)
FetchContent_Declare(llama
    GIT_REPOSITORY https://github.com/ggerganov/llama.cpp
    GIT_TAG master
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
    SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/llama-src"
)
set(LLAMA_BUILD_TESTS   OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER  OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(llama)

add_executable(firewall WIN32
    src/main.cpp
    resources/app.rc
    resources/ui/MainWindow.ui

    src/core/FirewallRule.h
    src/core/FirewallRule.cpp
    src/core/IFirewall.h
    src/core/FirewallManager.h
    src/core/FirewallManager.cpp
    src/core/ThreatDatabase.h
    src/core/ThreatDatabase.cpp
    src/core/KnownMalwareDb.h
    src/core/KnownMalwareDb.cpp
    src/core/BackupManager.h
    src/core/BackupManager.cpp
    src/core/SignatureChecker.h
    src/core/SignatureChecker.cpp
    src/core/IpReputationDb.h
    src/core/IpReputationDb.cpp
    src/core/RiskAnalyzer.h
    src/core/RiskAnalyzer.cpp
    src/core/FileAnalyzer.h
    src/core/FileAnalyzer.cpp
    src/core/BehavioralAnalyzer.h
    src/core/BehavioralAnalyzer.cpp
    src/core/AiAssistant.h
    src/core/AiAssistant.cpp

    src/gui/MainWindow.h
    src/gui/MainWindow.cpp
    src/gui/RuleTableModel.h
    src/gui/RuleTableModel.cpp
    src/gui/RuleDialog.h
    src/gui/RuleDialog.cpp
    src/gui/OverviewWidget.h
    src/gui/OverviewWidget.cpp
    src/gui/AppsWidget.h
    src/gui/AppsWidget.cpp
    src/gui/OptionsDialog.h
    src/gui/OptionsDialog.cpp
    src/gui/ConnectionsWidget.h
    src/gui/ConnectionsWidget.cpp
    src/gui/TrojanTestDialog.h
    src/gui/TrojanTestDialog.cpp
    src/gui/AiResultDialog.h
    src/gui/AiResultDialog.cpp
    src/core/ConnectionInfo.h
)

set_target_properties(firewall PROPERTIES OUTPUT_NAME "Vigil_Fluminis")

target_include_directories(firewall PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(firewall PRIVATE
    Qt6::Widgets
    wintrust
    crypt32
    llama
)

add_custom_command(TARGET firewall POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/resources/Vigil_Fluminis_256.png"
        "$<TARGET_FILE_DIR:firewall>/Vigil_Fluminis_256.png"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/resources/Vigil Fluminis.ico"
        "$<TARGET_FILE_DIR:firewall>/Vigil Fluminis.ico"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/resources/ip_reputation.json"
        "$<TARGET_FILE_DIR:firewall>/ip_reputation.json"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/resources/LICENSES"
        "$<TARGET_FILE_DIR:firewall>/LICENSES"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/llama.dll"
        "$<TARGET_FILE_DIR:firewall>/llama.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ggml.dll"
        "$<TARGET_FILE_DIR:firewall>/ggml.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ggml-base.dll"
        "$<TARGET_FILE_DIR:firewall>/ggml-base.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_BINARY_DIR}/bin/$<CONFIG>/ggml-cpu.dll"
        "$<TARGET_FILE_DIR:firewall>/ggml-cpu.dll"
    COMMAND "${QT_PATH}/bin/windeployqt.exe"
        "$<TARGET_FILE:firewall>"
    COMMENT "Copying application resources"
)

if(WIN32)
    target_sources(firewall PRIVATE
        src/platform/windows/ComFirewall.h
        src/platform/windows/ComFirewall.cpp
        src/platform/windows/Elevation.h
        src/platform/windows/Elevation.cpp
        src/platform/windows/ConnectionEnumerator.h
        src/platform/windows/ConnectionEnumerator.cpp
    )
    target_compile_definitions(firewall PRIVATE
        FIREWALL_PLATFORM_WINDOWS=1
    )
elseif(UNIX)
    target_compile_definitions(firewall PRIVATE
        FIREWALL_PLATFORM_LINUX=1
    )
endif()
