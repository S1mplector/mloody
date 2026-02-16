#import <Foundation/Foundation.h>

#import "adapters/inbound/cli/MLDCliApplication.h"
#import "adapters/outbound/iokit/MLDIOKitDeviceDiscoveryAdapter.h"
#import "adapters/outbound/iokit/MLDIOKitFeatureTransportAdapter.h"
#import "application/use_cases/MLDApplyPerformanceProfileUseCase.h"
#import "application/use_cases/MLDDiscoverSupportedDevicesUseCase.h"
#import "application/use_cases/MLDReadFeatureReportUseCase.h"
#import "application/use_cases/MLDT50ExchangeVendorCommandUseCase.h"
#import "application/use_cases/MLDWriteFeatureReportUseCase.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        MLDIOKitDeviceDiscoveryAdapter *discoveryAdapter = [[MLDIOKitDeviceDiscoveryAdapter alloc] init];
        MLDIOKitFeatureTransportAdapter *featureAdapter = [[MLDIOKitFeatureTransportAdapter alloc] init];

        MLDDiscoverSupportedDevicesUseCase *discoverUseCase =
            [[MLDDiscoverSupportedDevicesUseCase alloc] initWithDiscoveryPort:discoveryAdapter];
        MLDApplyPerformanceProfileUseCase *applyUseCase =
            [[MLDApplyPerformanceProfileUseCase alloc] initWithFeatureTransportPort:featureAdapter];
        MLDWriteFeatureReportUseCase *writeFeatureUseCase =
            [[MLDWriteFeatureReportUseCase alloc] initWithFeatureTransportPort:featureAdapter];
        MLDReadFeatureReportUseCase *readFeatureUseCase =
            [[MLDReadFeatureReportUseCase alloc] initWithFeatureTransportPort:featureAdapter];
        MLDT50ExchangeVendorCommandUseCase *t50ExchangeUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:featureAdapter];

        MLDCliApplication *app = [[MLDCliApplication alloc] initWithDiscoverUseCase:discoverUseCase
                                                                 applyProfileUseCase:applyUseCase
                                                         writeFeatureReportUseCase:writeFeatureUseCase
                                                          readFeatureReportUseCase:readFeatureUseCase
                                                     t50ExchangeCommandUseCase:t50ExchangeUseCase];
        return [app runWithArgc:argc argv:argv];
    }
}
