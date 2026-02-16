#import "adapters/inbound/cli/MLDCliApplication.h"

#import "application/use_cases/MLDApplyPerformanceProfileUseCase.h"
#import "application/use_cases/MLDDiscoverSupportedDevicesUseCase.h"
#import "application/use_cases/MLDReadFeatureReportUseCase.h"
#import "application/use_cases/MLDWriteFeatureReportUseCase.h"
#import "domain/entities/MLDMouseDevice.h"
#import "domain/services/MLDSupportedDeviceCatalog.h"
#import "domain/value_objects/MLDPerformanceProfile.h"

#include <errno.h>
#include <stdlib.h>

@interface MLDCliApplication ()

@property(nonatomic, strong) MLDDiscoverSupportedDevicesUseCase *discoverUseCase;
@property(nonatomic, strong) MLDApplyPerformanceProfileUseCase *applyProfileUseCase;
@property(nonatomic, strong) MLDWriteFeatureReportUseCase *writeFeatureReportUseCase;
@property(nonatomic, strong) MLDReadFeatureReportUseCase *readFeatureReportUseCase;

@end

@implementation MLDCliApplication

- (instancetype)initWithDiscoverUseCase:(MLDDiscoverSupportedDevicesUseCase *)discoverUseCase
                    applyProfileUseCase:(MLDApplyPerformanceProfileUseCase *)applyProfileUseCase
            writeFeatureReportUseCase:(MLDWriteFeatureReportUseCase *)writeFeatureReportUseCase
             readFeatureReportUseCase:(MLDReadFeatureReportUseCase *)readFeatureReportUseCase {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _discoverUseCase = discoverUseCase;
    _applyProfileUseCase = applyProfileUseCase;
    _writeFeatureReportUseCase = writeFeatureReportUseCase;
    _readFeatureReportUseCase = readFeatureReportUseCase;
    return self;
}

- (int)runWithArgc:(int)argc argv:(const char * _Nonnull const * _Nonnull)argv {
    NSMutableArray<NSString *> *arguments = [NSMutableArray array];
    for (int i = 1; i < argc; ++i) {
        [arguments addObject:[NSString stringWithUTF8String:argv[i]]];
    }

    if (arguments.count == 0 || [arguments.firstObject isEqualToString:@"help"]) {
        [self printUsage];
        return 0;
    }

    NSString *command = arguments.firstObject;
    NSArray<NSString *> *commandArgs = [arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)];

    if ([command isEqualToString:@"list"]) {
        return [self runListCommand];
    }
    if ([command isEqualToString:@"probe"]) {
        return [self runProbeCommandWithArguments:commandArgs];
    }
    if ([command isEqualToString:@"apply"]) {
        return [self runApplyCommandWithArguments:commandArgs];
    }
    if ([command isEqualToString:@"feature-set"]) {
        return [self runFeatureSetCommandWithArguments:commandArgs];
    }
    if ([command isEqualToString:@"feature-get"]) {
        return [self runFeatureGetCommandWithArguments:commandArgs];
    }
    if ([command isEqualToString:@"feature-scan"]) {
        return [self runFeatureScanCommandWithArguments:commandArgs];
    }

    fprintf(stderr, "Unknown command: %s\n", command.UTF8String);
    [self printUsage];
    return 1;
}

- (void)printUsage {
    printf("mloody commands:\n");
    printf("  list\n");
    printf("  probe [--vid <n>] [--pid <n>] [--serial <value>] [--model <value>]\n");
    printf("  apply [--dpi <n>] [--polling <n>] [--lod <n>] [--vid <n>] [--pid <n>] [--serial <value>] [--model <value>]\n");
    printf("  feature-set --report-id <n> --data <hex> [--vid <n>] [--pid <n>] [--serial <value>] [--model <value>]\n");
    printf("  feature-get --report-id <n> --length <n> [--vid <n>] [--pid <n>] [--serial <value>] [--model <value>]\n");
    printf("  feature-scan [--from <n>] [--to <n>] [--length <n>] [--vid <n>] [--pid <n>] [--serial <value>] [--model <value>]\n");
    printf("\n");
    printf("Notes:\n");
    printf("  - Numeric values accept decimal or hex (for example 4096 or 0x1000).\n");
    printf("  - If no selector is provided, T50 devices are preferred automatically.\n");
}

- (int)runListCommand {
    NSError *error = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&error];
    if (error != nil) {
        fprintf(stderr, "Discovery error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    if (devices.count == 0) {
        printf("No supported Bloody devices found.\n");
        return 0;
    }

    for (MLDMouseDevice *device in devices) {
        printf("vendor=0x%04x product=0x%04x location=0x%08x model=%s serial=%s t50=%s\n",
               device.vendorID,
               device.productID,
               device.locationID,
               device.modelName.UTF8String,
               device.serialNumber.UTF8String,
               [MLDSupportedDeviceCatalog isT50Device:device] ? "yes" : "no");
    }

    return 0;
}

- (int)runProbeCommandWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        fprintf(stderr, "Discovery error: %s\n", discoveryError.localizedDescription.UTF8String);
        return 1;
    }

    if (devices.count == 0) {
        printf("No supported Bloody devices found.\n");
        return 0;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        fprintf(stderr, "Selector error: %s\n", selectionError.localizedDescription.UTF8String);
        return 1;
    }

    if (candidates.count == 0) {
        fprintf(stderr, "No matching Bloody device for the provided selectors.\n");
        return 1;
    }

    MLDMouseDevice *selected = [self preferredDeviceFromCandidates:candidates];
    printf("selected: vendor=0x%04x product=0x%04x location=0x%08x model=%s serial=%s t50=%s\n",
           selected.vendorID,
           selected.productID,
           selected.locationID,
           selected.modelName.UTF8String,
           selected.serialNumber.UTF8String,
           [MLDSupportedDeviceCatalog isT50Device:selected] ? "yes" : "no");
    printf("candidates=%lu\n", (unsigned long)candidates.count);
    return 0;
}

- (int)runApplyCommandWithArguments:(NSArray<NSString *> *)arguments {
    NSUInteger dpi = 1600;
    NSUInteger polling = 1000;
    NSUInteger liftOffDistance = 2;

    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        [self printUsage];
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--dpi", @"--polling", @"--lod", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (![self parseOptionalUnsigned:options[@"--dpi"] maxValue:20000 fieldName:@"--dpi" output:&dpi errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--polling"] maxValue:4000 fieldName:@"--polling" output:&polling errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--lod"] maxValue:10 fieldName:@"--lod" output:&liftOffDistance errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        fprintf(stderr, "Discovery error: %s\n", discoveryError.localizedDescription.UTF8String);
        return 1;
    }
    if (devices.count == 0) {
        fprintf(stderr, "No supported Bloody device found to apply profile.\n");
        return 1;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        fprintf(stderr, "Selector error: %s\n", selectionError.localizedDescription.UTF8String);
        return 1;
    }
    if (candidates.count == 0) {
        fprintf(stderr, "No matching Bloody device for the provided selectors.\n");
        return 1;
    }

    MLDMouseDevice *target = [self preferredDeviceFromCandidates:candidates];
    MLDPerformanceProfile *profile = [[MLDPerformanceProfile alloc] initWithDPI:dpi
                                                                   pollingRateHz:polling
                                                                 liftOffDistance:liftOffDistance];

    NSError *applyError = nil;
    BOOL success = [self.applyProfileUseCase executeForDevice:target profile:profile error:&applyError];
    if (!success) {
        NSString *errorMessage = applyError.localizedDescription ?: @"Unknown apply failure.";
        fprintf(stderr, "Apply error: %s\n", errorMessage.UTF8String);
        return 1;
    }

    printf("Applied profile to %s (dpi=%lu polling=%lu lod=%lu).\n",
           target.modelName.UTF8String,
           (unsigned long)dpi,
           (unsigned long)polling,
           (unsigned long)liftOffDistance);
    return 0;
}

- (int)runFeatureSetCommandWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--report-id", @"--data", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *reportIDString = options[@"--report-id"];
    NSString *dataString = options[@"--data"];
    if (reportIDString == nil || dataString == nil) {
        fprintf(stderr, "feature-set requires --report-id and --data.\n");
        return 1;
    }

    NSUInteger reportIDValue = 0;
    if (![self parseRequiredUnsigned:reportIDString maxValue:255 fieldName:@"--report-id" output:&reportIDValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSData *payload = [self dataFromHexInput:dataString errorMessage:&parseError];
    if (payload == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        fprintf(stderr, "Discovery error: %s\n", discoveryError.localizedDescription.UTF8String);
        return 1;
    }
    if (devices.count == 0) {
        fprintf(stderr, "No supported Bloody devices found.\n");
        return 1;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        fprintf(stderr, "Selector error: %s\n", selectionError.localizedDescription.UTF8String);
        return 1;
    }
    if (candidates.count == 0) {
        fprintf(stderr, "No matching Bloody device for the provided selectors.\n");
        return 1;
    }

    MLDMouseDevice *target = [self preferredDeviceFromCandidates:candidates];

    NSError *writeError = nil;
    BOOL success = [self.writeFeatureReportUseCase executeForDevice:target
                                                           reportID:(uint8_t)reportIDValue
                                                            payload:payload
                                                              error:&writeError];
    if (!success) {
        fprintf(stderr, "Feature set error: %s\n", writeError.localizedDescription.UTF8String);
        return 1;
    }

    NSString *hex = [self hexStringFromData:payload];
    printf("feature-set ok device=%s report=0x%02lx bytes=%s\n",
           target.modelName.UTF8String,
           (unsigned long)reportIDValue,
           hex.UTF8String);
    return 0;
}

- (int)runFeatureGetCommandWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--report-id", @"--length", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *reportIDString = options[@"--report-id"];
    NSString *lengthString = options[@"--length"];
    if (reportIDString == nil || lengthString == nil) {
        fprintf(stderr, "feature-get requires --report-id and --length.\n");
        return 1;
    }

    NSUInteger reportIDValue = 0;
    NSUInteger length = 0;
    if (![self parseRequiredUnsigned:reportIDString maxValue:255 fieldName:@"--report-id" output:&reportIDValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseRequiredUnsigned:lengthString maxValue:4096 fieldName:@"--length" output:&length errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        fprintf(stderr, "Discovery error: %s\n", discoveryError.localizedDescription.UTF8String);
        return 1;
    }
    if (devices.count == 0) {
        fprintf(stderr, "No supported Bloody devices found.\n");
        return 1;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        fprintf(stderr, "Selector error: %s\n", selectionError.localizedDescription.UTF8String);
        return 1;
    }
    if (candidates.count == 0) {
        fprintf(stderr, "No matching Bloody device for the provided selectors.\n");
        return 1;
    }

    MLDMouseDevice *target = [self preferredDeviceFromCandidates:candidates];
    NSError *readError = nil;
    NSData *data = [self.readFeatureReportUseCase executeForDevice:target
                                                          reportID:(uint8_t)reportIDValue
                                                            length:length
                                                             error:&readError];
    if (data == nil) {
        fprintf(stderr, "Feature get error: %s\n", readError.localizedDescription.UTF8String);
        return 1;
    }

    NSString *hex = [self hexStringFromData:data];
    printf("feature-get ok device=%s report=0x%02lx bytes=%s\n",
           target.modelName.UTF8String,
           (unsigned long)reportIDValue,
           hex.UTF8String);
    return 0;
}

- (int)runFeatureScanCommandWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--from", @"--to", @"--length", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger reportFrom = 1;
    NSUInteger reportTo = 32;
    NSUInteger length = 16;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:255 fieldName:@"--from" output:&reportFrom errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--to"] maxValue:255 fieldName:@"--to" output:&reportTo errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--length"] maxValue:4096 fieldName:@"--length" output:&length errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (reportFrom > reportTo) {
        fprintf(stderr, "Option '--from' must be <= '--to'.\n");
        return 1;
    }

    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        fprintf(stderr, "Discovery error: %s\n", discoveryError.localizedDescription.UTF8String);
        return 1;
    }
    if (devices.count == 0) {
        fprintf(stderr, "No supported Bloody devices found.\n");
        return 1;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        fprintf(stderr, "Selector error: %s\n", selectionError.localizedDescription.UTF8String);
        return 1;
    }
    if (candidates.count == 0) {
        fprintf(stderr, "No matching Bloody device for the provided selectors.\n");
        return 1;
    }

    MLDMouseDevice *target = [self preferredDeviceFromCandidates:candidates];
    printf("feature-scan device=%s from=0x%02lx to=0x%02lx length=%lu\n",
           target.modelName.UTF8String,
           (unsigned long)reportFrom,
           (unsigned long)reportTo,
           (unsigned long)length);

    NSUInteger successCount = 0;
    for (NSUInteger reportID = reportFrom; reportID <= reportTo; ++reportID) {
        NSError *readError = nil;
        NSData *data = [self.readFeatureReportUseCase executeForDevice:target
                                                              reportID:(uint8_t)reportID
                                                                length:length
                                                                 error:&readError];
        if (data == nil) {
            printf("  report=0x%02lx err=%s\n", (unsigned long)reportID, readError.localizedDescription.UTF8String);
            continue;
        }

        NSString *hex = [self hexStringFromData:data];
        printf("  report=0x%02lx ok bytes=%s\n", (unsigned long)reportID, hex.UTF8String);
        successCount += 1;
    }

    printf("feature-scan done success=%lu total=%lu\n",
           (unsigned long)successCount,
           (unsigned long)(reportTo - reportFrom + 1));
    return 0;
}

- (nullable NSDictionary<NSString *, NSString *> *)parseOptionMapFromArguments:(NSArray<NSString *> *)arguments
                                                                   errorMessage:(NSString **)errorMessage {
    NSMutableDictionary<NSString *, NSString *> *map = [NSMutableDictionary dictionary];

    NSUInteger index = 0;
    while (index < arguments.count) {
        NSString *key = arguments[index];
        if (![key hasPrefix:@"--"]) {
            if (errorMessage != nil) {
                *errorMessage = [NSString stringWithFormat:@"Invalid option '%@'. Expected --key <value> pairs.", key];
            }
            return nil;
        }
        if (index + 1 >= arguments.count) {
            if (errorMessage != nil) {
                *errorMessage = [NSString stringWithFormat:@"Missing value for option '%@'.", key];
            }
            return nil;
        }

        map[key] = arguments[index + 1];
        index += 2;
    }

    return [map copy];
}

- (BOOL)validateAllowedOptions:(NSSet<NSString *> *)allowed
                       options:(NSDictionary<NSString *, NSString *> *)options
                  errorMessage:(NSString **)errorMessage {
    for (NSString *key in options) {
        if (![allowed containsObject:key]) {
            if (errorMessage != nil) {
                *errorMessage = [NSString stringWithFormat:@"Unknown option '%@'.", key];
            }
            return NO;
        }
    }
    return YES;
}

- (BOOL)parseOptionalUnsigned:(nullable NSString *)value
                     maxValue:(NSUInteger)maxValue
                    fieldName:(NSString *)fieldName
                       output:(NSUInteger *)output
                 errorMessage:(NSString **)errorMessage {
    if (value == nil) {
        return YES;
    }

    return [self parseRequiredUnsigned:value maxValue:maxValue fieldName:fieldName output:output errorMessage:errorMessage];
}

- (BOOL)parseRequiredUnsigned:(NSString *)value
                     maxValue:(NSUInteger)maxValue
                    fieldName:(NSString *)fieldName
                       output:(NSUInteger *)output
                 errorMessage:(NSString **)errorMessage {
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value.UTF8String, &end, 0);

    if (errno != 0 || end == value.UTF8String || *end != '\0') {
        if (errorMessage != nil) {
            *errorMessage = [NSString stringWithFormat:@"Option '%@' must be numeric (decimal or 0x-hex).", fieldName];
        }
        return NO;
    }
    if (parsed > maxValue) {
        if (errorMessage != nil) {
            *errorMessage = [NSString stringWithFormat:@"Option '%@' must be <= %lu.", fieldName, (unsigned long)maxValue];
        }
        return NO;
    }

    *output = (NSUInteger)parsed;
    return YES;
}

- (nullable NSArray<MLDMouseDevice *> *)filterDevices:(NSArray<MLDMouseDevice *> *)devices
                                               options:(NSDictionary<NSString *, NSString *> *)options
                                                 error:(NSError **)error {
    NSUInteger vendorID = 0;
    NSUInteger productID = 0;
    NSString *serial = options[@"--serial"];
    NSString *model = options[@"--model"];

    NSString *parseError = nil;
    BOOL hasVID = options[@"--vid"] != nil;
    BOOL hasPID = options[@"--pid"] != nil;

    if (hasVID && ![self parseRequiredUnsigned:options[@"--vid"] maxValue:0xFFFF fieldName:@"--vid" output:&vendorID errorMessage:&parseError]) {
        if (error != nil) {
            *error = [NSError errorWithDomain:@"com.mloody.cli" code:1 userInfo:@{NSLocalizedDescriptionKey : parseError}];
        }
        return nil;
    }
    if (hasPID && ![self parseRequiredUnsigned:options[@"--pid"] maxValue:0xFFFF fieldName:@"--pid" output:&productID errorMessage:&parseError]) {
        if (error != nil) {
            *error = [NSError errorWithDomain:@"com.mloody.cli" code:1 userInfo:@{NSLocalizedDescriptionKey : parseError}];
        }
        return nil;
    }

    NSMutableArray<MLDMouseDevice *> *result = [NSMutableArray array];
    for (MLDMouseDevice *device in devices) {
        if (hasVID && device.vendorID != (uint16_t)vendorID) {
            continue;
        }
        if (hasPID && device.productID != (uint16_t)productID) {
            continue;
        }
        if (serial != nil && ![serial isEqualToString:device.serialNumber]) {
            continue;
        }
        if (model != nil && [device.modelName rangeOfString:model options:NSCaseInsensitiveSearch].location == NSNotFound) {
            continue;
        }

        [result addObject:device];
    }

    return [result copy];
}

- (MLDMouseDevice *)preferredDeviceFromCandidates:(NSArray<MLDMouseDevice *> *)candidates {
    for (MLDMouseDevice *device in candidates) {
        if ([MLDSupportedDeviceCatalog isT50Device:device]) {
            return device;
        }
    }

    return candidates.firstObject;
}

- (nullable NSData *)dataFromHexInput:(NSString *)input errorMessage:(NSString **)errorMessage {
    NSCharacterSet *splitSet = [NSCharacterSet characterSetWithCharactersInString:@" ,:;"];
    NSArray<NSString *> *parts = [input componentsSeparatedByCharactersInSet:splitSet];

    NSMutableArray<NSString *> *tokens = [NSMutableArray array];
    for (NSString *part in parts) {
        if (part.length > 0) {
            [tokens addObject:part];
        }
    }

    NSMutableData *data = [NSMutableData data];

    if (tokens.count > 1) {
        for (NSString *token in tokens) {
            NSString *normalized = token;
            if ([normalized hasPrefix:@"0x"] || [normalized hasPrefix:@"0X"]) {
                normalized = [normalized substringFromIndex:2];
            }

            if (normalized.length == 0 || normalized.length > 2) {
                if (errorMessage != nil) {
                    *errorMessage = [NSString stringWithFormat:@"Invalid hex byte token '%@' in --data.", token];
                }
                return nil;
            }

            unsigned value = 0;
            NSScanner *scanner = [NSScanner scannerWithString:normalized];
            if (![scanner scanHexInt:&value] || !scanner.isAtEnd) {
                if (errorMessage != nil) {
                    *errorMessage = [NSString stringWithFormat:@"Invalid hex byte token '%@' in --data.", token];
                }
                return nil;
            }

            uint8_t byte = (uint8_t)value;
            [data appendBytes:&byte length:1];
        }

        return [data copy];
    }

    NSString *compact = tokens.count == 1 ? tokens.firstObject : input;
    if ([compact hasPrefix:@"0x"] || [compact hasPrefix:@"0X"]) {
        compact = [compact substringFromIndex:2];
    }

    if (compact.length == 0) {
        return [NSData data];
    }

    if ((compact.length % 2) != 0) {
        if (errorMessage != nil) {
            *errorMessage = @"Hex payload must contain an even number of characters.";
        }
        return nil;
    }

    for (NSUInteger index = 0; index < compact.length; index += 2) {
        NSString *pair = [compact substringWithRange:NSMakeRange(index, 2)];
        unsigned value = 0;
        NSScanner *scanner = [NSScanner scannerWithString:pair];
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd) {
            if (errorMessage != nil) {
                *errorMessage = [NSString stringWithFormat:@"Invalid hex byte '%@' in --data.", pair];
            }
            return nil;
        }

        uint8_t byte = (uint8_t)value;
        [data appendBytes:&byte length:1];
    }

    return [data copy];
}

- (NSString *)hexStringFromData:(NSData *)data {
    if (data.length == 0) {
        return @"";
    }

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    NSMutableArray<NSString *> *parts = [NSMutableArray arrayWithCapacity:data.length];
    for (NSUInteger i = 0; i < data.length; ++i) {
        [parts addObject:[NSString stringWithFormat:@"%02x", bytes[i]]];
    }

    return [parts componentsJoinedByString:@" "];
}

@end
