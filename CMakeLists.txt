cmake_minimum_required(VERSION 3.24)
project(mloody LANGUAGES C CXX OBJC OBJCXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(MLOODY_BUILD_TESTS "Build mloody unit tests" ON)

find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(IOKIT_FRAMEWORK IOKit REQUIRED)

add_library(mloody_domain STATIC
    src/domain/entities/MLDMouseDevice.m
    src/domain/value_objects/MLDPerformanceProfile.m
    src/domain/services/MLDProfilePolicy.m
    src/domain/services/MLDSupportedDeviceCatalog.m
)
target_include_directories(mloody_domain PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_compile_options(mloody_domain PRIVATE -fobjc-arc)
target_link_libraries(mloody_domain PUBLIC ${FOUNDATION_FRAMEWORK})

add_library(mloody_application STATIC
    src/application/use_cases/MLDDiscoverSupportedDevicesUseCase.m
    src/application/use_cases/MLDApplyPerformanceProfileUseCase.m
    src/application/use_cases/MLDWriteFeatureReportUseCase.m
    src/application/use_cases/MLDReadFeatureReportUseCase.m
    src/application/use_cases/MLDT50ExchangeVendorCommandUseCase.m
)
target_include_directories(mloody_application PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_compile_options(mloody_application PRIVATE -fobjc-arc)
target_link_libraries(mloody_application PUBLIC mloody_domain ${FOUNDATION_FRAMEWORK})

add_library(mloody_adapters_memory STATIC
    src/adapters/outbound/memory/MLDInMemoryDeviceDiscoveryAdapter.m
    src/adapters/outbound/memory/MLDInMemoryFeatureTransportAdapter.m
)
target_include_directories(mloody_adapters_memory PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_compile_options(mloody_adapters_memory PRIVATE -fobjc-arc)
target_link_libraries(mloody_adapters_memory PUBLIC mloody_application ${FOUNDATION_FRAMEWORK})

add_library(mloody_adapters_iokit STATIC
    src/adapters/outbound/iokit/MLDIOKitDeviceDiscoveryAdapter.mm
    src/adapters/outbound/iokit/MLDIOKitFeatureTransportAdapter.mm
)
target_include_directories(mloody_adapters_iokit PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_compile_options(mloody_adapters_iokit PRIVATE -fobjc-arc)
target_link_libraries(mloody_adapters_iokit PUBLIC
    mloody_application
    ${FOUNDATION_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
    ${IOKIT_FRAMEWORK}
)

add_library(mloody_adapters_cli STATIC
    src/adapters/inbound/cli/MLDCliApplication.mm
)
target_include_directories(mloody_adapters_cli PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_compile_options(mloody_adapters_cli PRIVATE -fobjc-arc)
target_link_libraries(mloody_adapters_cli PUBLIC mloody_application ${FOUNDATION_FRAMEWORK})

add_executable(mloody src/bootstrap/main.mm)
target_compile_options(mloody PRIVATE -fobjc-arc)
target_link_libraries(mloody PRIVATE
    mloody_adapters_cli
    mloody_adapters_iokit
)

if(MLOODY_BUILD_TESTS)
    enable_testing()

    add_executable(discover_supported_devices_tests tests/unit/DiscoverSupportedDevicesTests.mm)
    target_compile_options(discover_supported_devices_tests PRIVATE -fobjc-arc)
    target_link_libraries(discover_supported_devices_tests PRIVATE
        mloody_adapters_memory
        mloody_application
        mloody_domain
        ${FOUNDATION_FRAMEWORK}
    )
    add_test(NAME discover_supported_devices_tests COMMAND discover_supported_devices_tests)

    add_executable(apply_profile_tests tests/unit/ApplyPerformanceProfileTests.mm)
    target_compile_options(apply_profile_tests PRIVATE -fobjc-arc)
    target_link_libraries(apply_profile_tests PRIVATE
        mloody_adapters_memory
        mloody_application
        mloody_domain
        ${FOUNDATION_FRAMEWORK}
    )
    add_test(NAME apply_profile_tests COMMAND apply_profile_tests)

    add_executable(raw_feature_control_tests tests/unit/RawFeatureControlTests.mm)
    target_compile_options(raw_feature_control_tests PRIVATE -fobjc-arc)
    target_link_libraries(raw_feature_control_tests PRIVATE
        mloody_adapters_memory
        mloody_application
        mloody_domain
        ${FOUNDATION_FRAMEWORK}
    )
    add_test(NAME raw_feature_control_tests COMMAND raw_feature_control_tests)

    add_executable(supported_device_catalog_tests tests/unit/SupportedDeviceCatalogTests.mm)
    target_compile_options(supported_device_catalog_tests PRIVATE -fobjc-arc)
    target_link_libraries(supported_device_catalog_tests PRIVATE
        mloody_domain
        ${FOUNDATION_FRAMEWORK}
    )
    add_test(NAME supported_device_catalog_tests COMMAND supported_device_catalog_tests)

    add_executable(t50_exchange_vendor_command_tests tests/unit/T50ExchangeVendorCommandTests.mm)
    target_compile_options(t50_exchange_vendor_command_tests PRIVATE -fobjc-arc)
    target_link_libraries(t50_exchange_vendor_command_tests PRIVATE
        mloody_adapters_memory
        mloody_application
        mloody_domain
        ${FOUNDATION_FRAMEWORK}
    )
    add_test(NAME t50_exchange_vendor_command_tests COMMAND t50_exchange_vendor_command_tests)
endif()
