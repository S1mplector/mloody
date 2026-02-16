#import "adapters/inbound/cli/MLDCliApplication.h"

#import "application/use_cases/MLDApplyPerformanceProfileUseCase.h"
#import "application/use_cases/MLDDiscoverSupportedDevicesUseCase.h"
#import "application/use_cases/MLDReadFeatureReportUseCase.h"
#import "application/use_cases/MLDT50ExchangeVendorCommandUseCase.h"
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
@property(nonatomic, strong) MLDT50ExchangeVendorCommandUseCase *t50ExchangeCommandUseCase;

@end

@implementation MLDCliApplication

- (instancetype)initWithDiscoverUseCase:(MLDDiscoverSupportedDevicesUseCase *)discoverUseCase
                    applyProfileUseCase:(MLDApplyPerformanceProfileUseCase *)applyProfileUseCase
            writeFeatureReportUseCase:(MLDWriteFeatureReportUseCase *)writeFeatureReportUseCase
             readFeatureReportUseCase:(MLDReadFeatureReportUseCase *)readFeatureReportUseCase
        t50ExchangeCommandUseCase:(MLDT50ExchangeVendorCommandUseCase *)t50ExchangeCommandUseCase {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _discoverUseCase = discoverUseCase;
    _applyProfileUseCase = applyProfileUseCase;
    _writeFeatureReportUseCase = writeFeatureReportUseCase;
    _readFeatureReportUseCase = readFeatureReportUseCase;
    _t50ExchangeCommandUseCase = t50ExchangeCommandUseCase;
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
    if ([command isEqualToString:@"t50"]) {
        return [self runT50CommandWithArguments:commandArgs];
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
    printf("  t50 <subcommand> [options]\n");
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

- (void)printT50Usage {
    printf("t50 subcommands:\n");
    printf("  t50 backlight-get [selectors]\n");
    printf("  t50 backlight-set --level <0..3> [selectors]\n");
    printf("  t50 core-get [selectors]\n");
    printf("  t50 core-state [selectors]\n");
    printf("  t50 core-set --core <1..4> [--save <0|1>] [--strategy <quick|capture-v1|capture-v2>] [selectors]\n");
    printf("  t50 save [--strategy <quick|capture-v1|capture-v2>] [selectors]\n");
    printf("  t50 command-read --opcode <n> [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 command-write --opcode <n> --data <hex> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 opcode-scan [--from <n>] [--to <n>] [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 capture --file <path> [--from <n>] [--to <n>] [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 capture-diff --before <path> --after <path>\n");
    printf("  t50 dpi-probe --opcode <n> --dpi <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 polling-probe --opcode <n> --hz <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 lod-probe --opcode <n> --lod <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 color-mode --mode <open|effect|discard> [selectors]\n");
    printf("  t50 color-direct --r <n> --g <n> --b <n> [--slots <1..20>] [--slot <1..20>] [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2>] [selectors]\n");
    printf("  t50 color-zone --zone <logo|wheel|rear|all> --r <n> --g <n> --b <n> [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2>] [selectors]\n");
    printf("  t50 color-probe --opcode <n> --r <n> --g <n> --b <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("\n");
    printf("selectors: --vid --pid --serial --model\n");
}

- (int)runT50CommandWithArguments:(NSArray<NSString *> *)arguments {
    if (arguments.count == 0 || [arguments.firstObject isEqualToString:@"help"]) {
        [self printT50Usage];
        return 0;
    }

    NSString *subcommand = arguments.firstObject;
    NSArray<NSString *> *subArguments = [arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)];

    if ([subcommand isEqualToString:@"backlight-get"]) {
        return [self runT50BacklightGetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"backlight-set"]) {
        return [self runT50BacklightSetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"core-get"]) {
        return [self runT50CoreGetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"core-state"]) {
        return [self runT50CoreStateWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"core-set"]) {
        return [self runT50CoreSetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"save"]) {
        return [self runT50SaveWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"command-read"]) {
        return [self runT50CommandReadWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"command-write"]) {
        return [self runT50CommandWriteWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"opcode-scan"]) {
        return [self runT50OpcodeScanWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"capture"]) {
        return [self runT50CaptureWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"capture-diff"]) {
        return [self runT50CaptureDiffWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"dpi-probe"]) {
        return [self runT50DPIProbeWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"polling-probe"]) {
        return [self runT50PollingProbeWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"lod-probe"]) {
        return [self runT50LODProbeWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"color-mode"]) {
        return [self runT50ColorModeWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"color-direct"]) {
        return [self runT50ColorDirectWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"color-zone"]) {
        return [self runT50ColorZoneWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"color-probe"]) {
        return [self runT50ColorProbeWithArguments:subArguments];
    }

    fprintf(stderr, "Unknown t50 subcommand: %s\n", subcommand.UTF8String);
    [self printT50Usage];
    return 1;
}

- (int)runT50BacklightGetWithArguments:(NSArray<NSString *> *)arguments {
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

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *error = nil;
    NSNumber *level = [self.t50ExchangeCommandUseCase readBacklightLevelForDevice:target error:&error];
    if (level == nil) {
        fprintf(stderr, "t50 backlight-get error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 backlight level=%lu\n", (unsigned long)level.unsignedIntegerValue);
    return 0;
}

- (int)runT50BacklightSetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--level", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *levelString = options[@"--level"];
    if (levelString == nil) {
        fprintf(stderr, "t50 backlight-set requires --level <0..3>.\n");
        return 1;
    }

    NSUInteger levelValue = 0;
    if (![self parseRequiredUnsigned:levelString maxValue:3 fieldName:@"--level" output:&levelValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *error = nil;
    BOOL ok = [self.t50ExchangeCommandUseCase setBacklightLevel:(uint8_t)levelValue onDevice:target error:&error];
    if (!ok) {
        fprintf(stderr, "t50 backlight-set error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 backlight-set ok level=%lu\n", (unsigned long)levelValue);
    return 0;
}

- (int)runT50CoreGetWithArguments:(NSArray<NSString *> *)arguments {
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

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *error = nil;
    NSDictionary<NSString *, NSNumber *> *state =
        [self.t50ExchangeCommandUseCase readCoreStateCandidateForDevice:target error:&error];
    if (state == nil) {
        fprintf(stderr, "t50 core-get error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    NSNumber *slot = state[@"slot"];
    NSNumber *lowBits = state[@"lowBits"];
    NSNumber *rawWord = state[@"rawWord"];
    printf("t50 core-get candidate=%lu low2=%lu raw=0x%04lx\n",
           (unsigned long)slot.unsignedIntegerValue,
           (unsigned long)lowBits.unsignedIntegerValue,
           (unsigned long)rawWord.unsignedIntegerValue);
    return 0;
}

- (int)runT50CoreStateWithArguments:(NSArray<NSString *> *)arguments {
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

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *error = nil;
    NSDictionary<NSString *, NSNumber *> *state =
        [self.t50ExchangeCommandUseCase readCoreStateCandidateForDevice:target error:&error];
    if (state == nil) {
        fprintf(stderr, "t50 core-state error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    NSNumber *opcode = state[@"opcode"];
    NSNumber *slot = state[@"slot"];
    NSNumber *lowBits = state[@"lowBits"];
    NSNumber *rawWord = state[@"rawWord"];

    printf("t50 core-state opcode=0x%02lx raw-word=0x%04lx low2=%lu core=%lu\n",
           (unsigned long)opcode.unsignedIntegerValue,
           (unsigned long)rawWord.unsignedIntegerValue,
           (unsigned long)lowBits.unsignedIntegerValue,
           (unsigned long)slot.unsignedIntegerValue);
    return 0;
}

- (int)runT50CoreSetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--core", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *coreString = options[@"--core"];
    if (coreString == nil) {
        fprintf(stderr, "t50 core-set requires --core <1..4>.\n");
        return 1;
    }

    NSUInteger coreValue = 0;
    NSUInteger saveValue = 1;
    if (![self parseRequiredUnsigned:coreString maxValue:4 fieldName:@"--core" output:&coreValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *strategyOption = options[@"--strategy"] ?: @"capture-v1";
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV1;
    if ([strategyOption isEqualToString:@"quick"]) {
        strategy = MLDT50SaveStrategyQuick;
    } else if ([strategyOption isEqualToString:@"capture-v1"]) {
        strategy = MLDT50SaveStrategyCaptureV1;
    } else if ([strategyOption isEqualToString:@"capture-v2"]) {
        strategy = MLDT50SaveStrategyCaptureV2;
    } else {
        fprintf(stderr, "t50 core-set --strategy must be one of: quick, capture-v1, capture-v2.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *setError = nil;
    BOOL setOK = [self.t50ExchangeCommandUseCase setCoreSlotCandidate:(uint8_t)coreValue onDevice:target error:&setError];
    if (!setOK) {
        fprintf(stderr, "t50 core-set error: %s\n", setError.localizedDescription.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saveOK) {
            fprintf(stderr, "t50 core-set save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 core-set candidate=%lu save=%lu strategy=%s\n",
           (unsigned long)coreValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50SaveWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--strategy", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *strategyOption = options[@"--strategy"] ?: @"quick";
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if ([strategyOption isEqualToString:@"quick"]) {
        strategy = MLDT50SaveStrategyQuick;
    } else if ([strategyOption isEqualToString:@"capture-v1"]) {
        strategy = MLDT50SaveStrategyCaptureV1;
    } else if ([strategyOption isEqualToString:@"capture-v2"]) {
        strategy = MLDT50SaveStrategyCaptureV2;
    } else {
        fprintf(stderr, "t50 save --strategy must be one of: quick, capture-v1, capture-v2.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *saveError = nil;
    BOOL ok = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
    if (!ok) {
        fprintf(stderr, "t50 save error: %s\n", saveError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 save ok strategy=%s steps=%lu\n",
           strategyOption.UTF8String,
           (unsigned long)[MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:strategy]);
    return 0;
}

- (int)runT50CommandReadWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--flag", @"--offset", @"--data", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    if (opcodeString == nil) {
        fprintf(stderr, "t50 command-read requires --opcode.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger flag = 0x00;
    NSUInteger offset = 8;

    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSData *payload = [NSData data];
    NSString *dataString = options[@"--data"];
    if (dataString != nil) {
        payload = [self dataFromHexInput:dataString errorMessage:&parseError];
        if (payload == nil) {
            fprintf(stderr, "%s\n", parseError.UTF8String);
            return 1;
        }
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *exchangeError = nil;
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                  opcode:(uint8_t)opcode
                                                               writeFlag:(uint8_t)flag
                                                           payloadOffset:offset
                                                                 payload:payload
                                                                   error:&exchangeError];
    if (response == nil) {
        fprintf(stderr, "t50 command-read error: %s\n", exchangeError.localizedDescription.UTF8String);
        return 1;
    }

    NSString *hex = [self hexStringFromData:response];
    printf("t50 command-read ok opcode=0x%02lx flag=0x%02lx response=%s\n",
           (unsigned long)opcode,
           (unsigned long)flag,
           hex.UTF8String);
    return 0;
}

- (int)runT50CommandWriteWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--data", @"--flag", @"--offset", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    NSString *dataString = options[@"--data"];
    if (opcodeString == nil || dataString == nil) {
        fprintf(stderr, "t50 command-write requires --opcode and --data.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger flag = 0x80;
    NSUInteger offset = 8;
    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSData *payload = [self dataFromHexInput:dataString errorMessage:&parseError];
    if (payload == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *exchangeError = nil;
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                  opcode:(uint8_t)opcode
                                                               writeFlag:(uint8_t)flag
                                                           payloadOffset:offset
                                                                 payload:payload
                                                                   error:&exchangeError];
    if (response == nil) {
        fprintf(stderr, "t50 command-write error: %s\n", exchangeError.localizedDescription.UTF8String);
        return 1;
    }

    NSString *responseHex = [self hexStringFromData:response];
    printf("t50 command-write ok opcode=0x%02lx flag=0x%02lx payload=%s response=%s\n",
           (unsigned long)opcode,
           (unsigned long)flag,
           [self hexStringFromData:payload].UTF8String,
           responseHex.UTF8String);
    return 0;
}

- (int)runT50OpcodeScanWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--from", @"--to", @"--flag", @"--offset", @"--data", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger from = 1;
    NSUInteger to = 64;
    NSUInteger flag = 0x00;
    NSUInteger offset = 8;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:255 fieldName:@"--from" output:&from errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--to"] maxValue:255 fieldName:@"--to" output:&to errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (from > to) {
        fprintf(stderr, "Option '--from' must be <= '--to'.\n");
        return 1;
    }

    NSData *payload = [NSData data];
    NSString *dataString = options[@"--data"];
    if (dataString != nil) {
        payload = [self dataFromHexInput:dataString errorMessage:&parseError];
        if (payload == nil) {
            fprintf(stderr, "%s\n", parseError.UTF8String);
            return 1;
        }
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    printf("t50 opcode-scan from=0x%02lx to=0x%02lx flag=0x%02lx offset=%lu\n",
           (unsigned long)from,
           (unsigned long)to,
           (unsigned long)flag,
           (unsigned long)offset);

    NSUInteger successCount = 0;
    for (NSUInteger opcode = from; opcode <= to; ++opcode) {
        NSError *exchangeError = nil;
        NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                      opcode:(uint8_t)opcode
                                                                   writeFlag:(uint8_t)flag
                                                               payloadOffset:offset
                                                                     payload:payload
                                                                       error:&exchangeError];
        if (response == nil) {
            printf("  opcode=0x%02lx err=%s\n", (unsigned long)opcode, exchangeError.localizedDescription.UTF8String);
            continue;
        }

        NSUInteger displayLength = MIN((NSUInteger)16, response.length);
        NSData *head = [response subdataWithRange:NSMakeRange(0, displayLength)];
        printf("  opcode=0x%02lx ok head=%s\n",
               (unsigned long)opcode,
               [self hexStringFromData:head].UTF8String);
        successCount += 1;
    }

    printf("t50 opcode-scan done success=%lu total=%lu\n",
           (unsigned long)successCount,
           (unsigned long)(to - from + 1));
    return 0;
}

- (int)runT50CaptureWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--file", @"--from", @"--to", @"--flag", @"--offset", @"--data", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *filePath = options[@"--file"];
    if (filePath == nil || filePath.length == 0) {
        fprintf(stderr, "t50 capture requires --file <path>.\n");
        return 1;
    }

    NSUInteger from = 16;
    NSUInteger to = 48;
    NSUInteger flag = 0x00;
    NSUInteger offset = 8;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:255 fieldName:@"--from" output:&from errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:255 fieldName:@"--to" output:&to errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (from > to) {
        fprintf(stderr, "Option '--from' must be <= '--to'.\n");
        return 1;
    }

    NSData *payload = [NSData data];
    NSString *dataString = options[@"--data"];
    if (dataString != nil) {
        payload = [self dataFromHexInput:dataString errorMessage:&parseError];
        if (payload == nil) {
            fprintf(stderr, "%s\n", parseError.UTF8String);
            return 1;
        }
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    NSUInteger successCount = 0;
    for (NSUInteger opcode = from; opcode <= to; ++opcode) {
        NSError *exchangeError = nil;
        NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                      opcode:(uint8_t)opcode
                                                                   writeFlag:(uint8_t)flag
                                                               payloadOffset:offset
                                                                     payload:payload
                                                                       error:&exchangeError];
        if (response == nil) {
            [entries addObject:@{
                @"opcode" : @(opcode),
                @"error" : exchangeError.localizedDescription ?: @"Unknown exchange error"
            }];
            continue;
        }

        [entries addObject:@{
            @"opcode" : @(opcode),
            @"response_hex" : [self hexStringFromData:response]
        }];
        successCount += 1;
    }

    NSDictionary *capture = @{
        @"timestamp_unix" : @([[NSDate date] timeIntervalSince1970]),
        @"device" : @{
            @"vendor_id" : @(target.vendorID),
            @"product_id" : @(target.productID),
            @"location_id" : @(target.locationID),
            @"model" : target.modelName,
            @"serial" : target.serialNumber
        },
        @"request" : @{
            @"from_opcode" : @(from),
            @"to_opcode" : @(to),
            @"flag" : @(flag),
            @"offset" : @(offset),
            @"payload_hex" : [self hexStringFromData:payload]
        },
        @"entries" : entries
    };

    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:capture options:NSJSONWritingPrettyPrinted error:&jsonError];
    if (jsonData == nil) {
        fprintf(stderr, "Failed to encode capture JSON: %s\n", jsonError.localizedDescription.UTF8String);
        return 1;
    }

    BOOL writeOK = [jsonData writeToFile:filePath options:NSDataWritingAtomic error:&jsonError];
    if (!writeOK) {
        fprintf(stderr, "Failed to write capture file: %s\n", jsonError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 capture saved file=%s success=%lu total=%lu\n",
           filePath.UTF8String,
           (unsigned long)successCount,
           (unsigned long)(to - from + 1));
    return 0;
}

- (int)runT50CaptureDiffWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--before", @"--after"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *beforePath = options[@"--before"];
    NSString *afterPath = options[@"--after"];
    if (beforePath == nil || afterPath == nil) {
        fprintf(stderr, "t50 capture-diff requires --before <path> and --after <path>.\n");
        return 1;
    }

    NSError *beforeReadError = nil;
    NSError *afterReadError = nil;
    NSData *beforeData = [NSData dataWithContentsOfFile:beforePath options:0 error:&beforeReadError];
    NSData *afterData = [NSData dataWithContentsOfFile:afterPath options:0 error:&afterReadError];
    if (beforeData == nil) {
        fprintf(stderr, "Failed to read --before file: %s\n", beforeReadError.localizedDescription.UTF8String);
        return 1;
    }
    if (afterData == nil) {
        fprintf(stderr, "Failed to read --after file: %s\n", afterReadError.localizedDescription.UTF8String);
        return 1;
    }

    NSError *beforeJSONError = nil;
    NSError *afterJSONError = nil;
    NSDictionary *beforeJSON = [NSJSONSerialization JSONObjectWithData:beforeData options:0 error:&beforeJSONError];
    NSDictionary *afterJSON = [NSJSONSerialization JSONObjectWithData:afterData options:0 error:&afterJSONError];
    if (![beforeJSON isKindOfClass:[NSDictionary class]]) {
        fprintf(stderr, "Invalid JSON in --before file: %s\n", beforeJSONError.localizedDescription.UTF8String);
        return 1;
    }
    if (![afterJSON isKindOfClass:[NSDictionary class]]) {
        fprintf(stderr, "Invalid JSON in --after file: %s\n", afterJSONError.localizedDescription.UTF8String);
        return 1;
    }

    NSArray *beforeEntries = beforeJSON[@"entries"];
    NSArray *afterEntries = afterJSON[@"entries"];
    if (![beforeEntries isKindOfClass:[NSArray class]] || ![afterEntries isKindOfClass:[NSArray class]]) {
        fprintf(stderr, "Capture files are missing 'entries' arrays.\n");
        return 1;
    }

    NSMutableDictionary<NSNumber *, NSDictionary *> *beforeByOpcode = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSDictionary *> *afterByOpcode = [NSMutableDictionary dictionary];
    for (NSDictionary *entry in beforeEntries) {
        if ([entry isKindOfClass:[NSDictionary class]] && entry[@"opcode"] != nil) {
            beforeByOpcode[entry[@"opcode"]] = entry;
        }
    }
    for (NSDictionary *entry in afterEntries) {
        if ([entry isKindOfClass:[NSDictionary class]] && entry[@"opcode"] != nil) {
            afterByOpcode[entry[@"opcode"]] = entry;
        }
    }

    printf("t50 capture-diff before=%s after=%s\n", beforePath.UTF8String, afterPath.UTF8String);

    NSUInteger changeCount = 0;
    for (NSUInteger opcode = 0; opcode <= 255; ++opcode) {
        NSDictionary *beforeEntry = beforeByOpcode[@(opcode)];
        NSDictionary *afterEntry = afterByOpcode[@(opcode)];
        if (beforeEntry == nil && afterEntry == nil) {
            continue;
        }

        NSString *beforeHex = beforeEntry[@"response_hex"];
        NSString *afterHex = afterEntry[@"response_hex"];
        NSString *beforeErr = beforeEntry[@"error"];
        NSString *afterErr = afterEntry[@"error"];

        BOOL different = NO;
        if ((beforeHex == nil) != (afterHex == nil)) {
            different = YES;
        } else if (beforeHex != nil && ![beforeHex isEqualToString:afterHex]) {
            different = YES;
        }
        if ((beforeErr == nil) != (afterErr == nil)) {
            different = YES;
        } else if (beforeErr != nil && ![beforeErr isEqualToString:afterErr]) {
            different = YES;
        }

        if (!different) {
            continue;
        }

        changeCount += 1;
        if (beforeHex != nil && afterHex != nil) {
            NSString *hexParseError = nil;
            NSData *beforeBytes = [self dataFromHexInput:beforeHex errorMessage:&hexParseError];
            NSData *afterBytes = [self dataFromHexInput:afterHex errorMessage:&hexParseError];
            if (beforeBytes != nil && afterBytes != nil) {
                const uint8_t *lhs = (const uint8_t *)beforeBytes.bytes;
                const uint8_t *rhs = (const uint8_t *)afterBytes.bytes;
                NSUInteger minLen = MIN(beforeBytes.length, afterBytes.length);
                NSMutableArray<NSString *> *segments = [NSMutableArray array];
                for (NSUInteger i = 0; i < minLen; ++i) {
                    if (lhs[i] != rhs[i]) {
                        [segments addObject:[NSString stringWithFormat:@"%lu:%02x->%02x",
                                             (unsigned long)i,
                                             lhs[i],
                                             rhs[i]]];
                    }
                    if (segments.count == 8) {
                        break;
                    }
                }
                if (beforeBytes.length != afterBytes.length) {
                    [segments addObject:[NSString stringWithFormat:@"len:%lu->%lu",
                                         (unsigned long)beforeBytes.length,
                                         (unsigned long)afterBytes.length]];
                }

                NSString *segmentString = segments.count > 0 ? [segments componentsJoinedByString:@", "] : @"content-changed";
                printf("  opcode=0x%02lx changed %s\n", (unsigned long)opcode, segmentString.UTF8String);
                continue;
            }
        }

        printf("  opcode=0x%02lx changed (non-hex or error state)\n", (unsigned long)opcode);
    }

    if (changeCount == 0) {
        printf("  no opcode changes detected.\n");
    } else {
        printf("  changed_opcodes=%lu\n", (unsigned long)changeCount);
    }

    return 0;
}

- (int)runT50DPIProbeWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--dpi", @"--flag", @"--offset", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    NSString *dpiString = options[@"--dpi"];
    if (opcodeString == nil || dpiString == nil) {
        fprintf(stderr, "t50 dpi-probe requires --opcode and --dpi.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger dpi = 0;
    NSUInteger flag = 0x80;
    NSUInteger offset = 8;
    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseRequiredUnsigned:dpiString maxValue:65535 fieldName:@"--dpi" output:&dpi errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    uint8_t dpiBytes[2] = {(uint8_t)(dpi & 0xFF), (uint8_t)((dpi >> 8) & 0xFF)};
    NSData *payload = [NSData dataWithBytes:dpiBytes length:sizeof(dpiBytes)];
    return [self runT50WriteProbeWithOptions:options
                                      opcode:opcode
                                        flag:flag
                                      offset:offset
                                     payload:payload
                                successLabel:@"t50 dpi-probe"];
}

- (int)runT50PollingProbeWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--hz", @"--flag", @"--offset", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    NSString *hzString = options[@"--hz"];
    if (opcodeString == nil || hzString == nil) {
        fprintf(stderr, "t50 polling-probe requires --opcode and --hz.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger hz = 0;
    NSUInteger flag = 0x80;
    NSUInteger offset = 8;
    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseRequiredUnsigned:hzString maxValue:65535 fieldName:@"--hz" output:&hz errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    uint8_t hzBytes[2] = {(uint8_t)(hz & 0xFF), (uint8_t)((hz >> 8) & 0xFF)};
    NSData *payload = [NSData dataWithBytes:hzBytes length:sizeof(hzBytes)];
    return [self runT50WriteProbeWithOptions:options
                                      opcode:opcode
                                        flag:flag
                                      offset:offset
                                     payload:payload
                                successLabel:@"t50 polling-probe"];
}

- (int)runT50LODProbeWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--lod", @"--flag", @"--offset", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    NSString *lodString = options[@"--lod"];
    if (opcodeString == nil || lodString == nil) {
        fprintf(stderr, "t50 lod-probe requires --opcode and --lod.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger lod = 0;
    NSUInteger flag = 0x80;
    NSUInteger offset = 8;
    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseRequiredUnsigned:lodString maxValue:255 fieldName:@"--lod" output:&lod errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    uint8_t lodByte = (uint8_t)lod;
    NSData *payload = [NSData dataWithBytes:&lodByte length:1];
    return [self runT50WriteProbeWithOptions:options
                                      opcode:opcode
                                        flag:flag
                                      offset:offset
                                     payload:payload
                                successLabel:@"t50 lod-probe"];
}

- (BOOL)sendT50ColorMenuPayload:(NSData *)payload
                        onDevice:(MLDMouseDevice *)device
                           error:(NSError **)error {
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:device
                                                                  opcode:0x03
                                                               writeFlag:0x00
                                                           payloadOffset:2
                                                                 payload:payload
                                                                   error:error];
    return response != nil;
}

- (BOOL)prepareT50ColorWriteSessionOnDevice:(MLDMouseDevice *)device
                                      error:(NSError **)error {
    const uint8_t openMode[] = {0x06, 0x01, 0x00, 0x00, 0x01, 0x02};
    NSData *openPayload = [NSData dataWithBytes:openMode length:sizeof(openMode)];
    if (![self sendT50ColorMenuPayload:openPayload onDevice:device error:error]) {
        return NO;
    }

    const uint8_t constantMode[] = {0x06, 0x01, 0x00, 0x00, 0x00, 0x02};
    NSData *constantPayload = [NSData dataWithBytes:constantMode length:sizeof(constantMode)];
    return [self sendT50ColorMenuPayload:constantPayload onDevice:device error:error];
}

- (int)runT50ColorModeWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[@"--mode", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *mode = options[@"--mode"];
    if (mode == nil) {
        fprintf(stderr, "t50 color-mode requires --mode <open|effect|discard>.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *normalizedMode = mode.lowercaseString;
    uint8_t modeBytes[6] = {0};
    if ([normalizedMode isEqualToString:@"open"]) {
        modeBytes[0] = 0x06;
        modeBytes[1] = 0x01;
        modeBytes[4] = 0x01;
        modeBytes[5] = 0x02;
    } else if ([normalizedMode isEqualToString:@"effect"] || [normalizedMode isEqualToString:@"constant"]) {
        modeBytes[0] = 0x06;
        modeBytes[1] = 0x01;
        modeBytes[4] = 0x00;
        modeBytes[5] = 0x02;
    } else if ([normalizedMode isEqualToString:@"discard"]) {
        modeBytes[0] = 0x06;
        modeBytes[1] = 0x01;
        modeBytes[4] = 0x00;
        modeBytes[5] = 0x00;
    } else {
        fprintf(stderr, "t50 color-mode --mode must be one of: open, effect, discard.\n");
        return 1;
    }

    NSData *payload = [NSData dataWithBytes:modeBytes length:sizeof(modeBytes)];
    NSError *writeError = nil;
    BOOL ok = [self sendT50ColorMenuPayload:payload onDevice:target error:&writeError];
    if (!ok) {
        fprintf(stderr, "t50 color-mode error: %s\n", writeError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 color-mode ok mode=%s payload=%s\n",
           normalizedMode.UTF8String,
           [self hexStringFromData:payload].UTF8String);
    return 0;
}

- (int)runT50ColorDirectWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--r", @"--g", @"--b", @"--slots", @"--slot", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *rString = options[@"--r"];
    NSString *gString = options[@"--g"];
    NSString *bString = options[@"--b"];
    if (rString == nil || gString == nil || bString == nil) {
        fprintf(stderr, "t50 color-direct requires --r, --g, and --b.\n");
        return 1;
    }

    NSUInteger red = 0;
    NSUInteger green = 0;
    NSUInteger blue = 0;
    NSUInteger slots = 20;
    NSUInteger slot = 0;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 1;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--slots"] maxValue:20 fieldName:@"--slots" output:&slots errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--slot"] maxValue:20 fieldName:@"--slot" output:&slot errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (slots == 0) {
        fprintf(stderr, "--slots must be at least 1.\n");
        return 1;
    }
    if (slot > 0 && slots != 20) {
        fprintf(stderr, "--slot cannot be combined with --slots.\n");
        return 1;
    }

    NSString *strategyOption = options[@"--strategy"] ?: @"capture-v2";
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV2;
    if ([strategyOption isEqualToString:@"quick"]) {
        strategy = MLDT50SaveStrategyQuick;
    } else if ([strategyOption isEqualToString:@"capture-v1"]) {
        strategy = MLDT50SaveStrategyCaptureV1;
    } else if ([strategyOption isEqualToString:@"capture-v2"]) {
        strategy = MLDT50SaveStrategyCaptureV2;
    } else {
        fprintf(stderr, "t50 color-direct --strategy must be one of: quick, capture-v1, capture-v2.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (prepareValue == 1) {
        NSError *prepareError = nil;
        BOOL prepared = [self prepareT50ColorWriteSessionOnDevice:target error:&prepareError];
        if (!prepared) {
            fprintf(stderr, "t50 color-direct prepare error: %s\n", prepareError.localizedDescription.UTF8String);
            return 1;
        }
    }

    static const NSUInteger kDirectSlotCount = 20;
    NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + (3 * kDirectSlotCount)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = 0x06;
    payloadBytes[1] = 0x02;
    NSUInteger startOffset = 6;
    for (NSUInteger index = 0; index < kDirectSlotCount; ++index) {
        BOOL shouldSet = (slot > 0) ? ((index + 1) == slot) : (index < slots);
        payloadBytes[startOffset + (3 * index) + 0] = shouldSet ? (uint8_t)red : 0x00;
        payloadBytes[startOffset + (3 * index) + 1] = shouldSet ? (uint8_t)green : 0x00;
        payloadBytes[startOffset + (3 * index) + 2] = shouldSet ? (uint8_t)blue : 0x00;
    }

    NSError *writeError = nil;
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                  opcode:0x03
                                                               writeFlag:0x00
                                                           payloadOffset:2
                                                                 payload:payload
                                                                   error:&writeError];
    if (response == nil) {
        fprintf(stderr, "t50 color-direct write error: %s\n", writeError.localizedDescription.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 color-direct save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    if (slot > 0) {
        printf("t50 color-direct ok r=%lu g=%lu b=%lu slot=%lu prepare=%lu save=%lu strategy=%s\n",
               (unsigned long)red,
               (unsigned long)green,
               (unsigned long)blue,
               (unsigned long)slot,
               (unsigned long)prepareValue,
               (unsigned long)saveValue,
               strategyOption.UTF8String);
        return 0;
    }

    printf("t50 color-direct ok r=%lu g=%lu b=%lu slots=%lu prepare=%lu save=%lu strategy=%s\n",
           (unsigned long)red,
           (unsigned long)green,
           (unsigned long)blue,
           (unsigned long)slots,
           (unsigned long)prepareValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50ColorZoneWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--zone", @"--r", @"--g", @"--b", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *zoneString = options[@"--zone"];
    NSString *rString = options[@"--r"];
    NSString *gString = options[@"--g"];
    NSString *bString = options[@"--b"];
    if (zoneString == nil || rString == nil || gString == nil || bString == nil) {
        fprintf(stderr, "t50 color-zone requires --zone, --r, --g, and --b.\n");
        return 1;
    }

    NSUInteger red = 0;
    NSUInteger green = 0;
    NSUInteger blue = 0;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *normalizedZone = zoneString.lowercaseString;
    static const NSUInteger kDirectSlotCount = 20;
    BOOL slotEnabled[kDirectSlotCount];
    memset(slotEnabled, 0, sizeof(slotEnabled));

    NSMutableArray<NSString *> *selectedSlots = [NSMutableArray array];
    if ([normalizedZone isEqualToString:@"logo"]) {
        slotEnabled[7] = YES;  // Slot 8 from OpenRGB W70/W90 map.
        [selectedSlots addObject:@"8"];
    } else if ([normalizedZone isEqualToString:@"wheel"]) {
        slotEnabled[14] = YES; // Slot 15 from OpenRGB W70/W90 map.
        [selectedSlots addObject:@"15"];
    } else if ([normalizedZone isEqualToString:@"rear"]) {
        const NSUInteger rearSlots[] = {1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14};
        const NSUInteger rearSlotCount = sizeof(rearSlots) / sizeof(rearSlots[0]);
        for (NSUInteger index = 0; index < rearSlotCount; ++index) {
            NSUInteger slot = rearSlots[index];
            slotEnabled[slot - 1] = YES;
            [selectedSlots addObject:[NSString stringWithFormat:@"%lu", (unsigned long)slot]];
        }
    } else if ([normalizedZone isEqualToString:@"all"]) {
        for (NSUInteger slot = 1; slot <= 15; ++slot) {
            slotEnabled[slot - 1] = YES;
            [selectedSlots addObject:[NSString stringWithFormat:@"%lu", (unsigned long)slot]];
        }
    } else {
        fprintf(stderr, "t50 color-zone --zone must be one of: logo, wheel, rear, all.\n");
        return 1;
    }

    NSString *strategyOption = options[@"--strategy"] ?: @"capture-v2";
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV2;
    if ([strategyOption isEqualToString:@"quick"]) {
        strategy = MLDT50SaveStrategyQuick;
    } else if ([strategyOption isEqualToString:@"capture-v1"]) {
        strategy = MLDT50SaveStrategyCaptureV1;
    } else if ([strategyOption isEqualToString:@"capture-v2"]) {
        strategy = MLDT50SaveStrategyCaptureV2;
    } else {
        fprintf(stderr, "t50 color-zone --strategy must be one of: quick, capture-v1, capture-v2.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (prepareValue == 1) {
        NSError *prepareError = nil;
        BOOL prepared = [self prepareT50ColorWriteSessionOnDevice:target error:&prepareError];
        if (!prepared) {
            fprintf(stderr, "t50 color-zone prepare error: %s\n", prepareError.localizedDescription.UTF8String);
            return 1;
        }
    }

    NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + (3 * kDirectSlotCount)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = 0x06;
    payloadBytes[1] = 0x02;
    NSUInteger startOffset = 6;
    for (NSUInteger index = 0; index < kDirectSlotCount; ++index) {
        BOOL shouldSet = slotEnabled[index];
        payloadBytes[startOffset + (3 * index) + 0] = shouldSet ? (uint8_t)red : 0x00;
        payloadBytes[startOffset + (3 * index) + 1] = shouldSet ? (uint8_t)green : 0x00;
        payloadBytes[startOffset + (3 * index) + 2] = shouldSet ? (uint8_t)blue : 0x00;
    }

    NSError *writeError = nil;
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                  opcode:0x03
                                                               writeFlag:0x00
                                                           payloadOffset:2
                                                                 payload:payload
                                                                   error:&writeError];
    if (response == nil) {
        fprintf(stderr, "t50 color-zone write error: %s\n", writeError.localizedDescription.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 color-zone save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    NSString *slotSummary = [selectedSlots componentsJoinedByString:@","];
    printf("t50 color-zone ok zone=%s slots=%s r=%lu g=%lu b=%lu prepare=%lu save=%lu strategy=%s\n",
           normalizedZone.UTF8String,
           slotSummary.UTF8String,
           (unsigned long)red,
           (unsigned long)green,
           (unsigned long)blue,
           (unsigned long)prepareValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50ColorProbeWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--opcode", @"--r", @"--g", @"--b", @"--flag", @"--offset", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *opcodeString = options[@"--opcode"];
    NSString *rString = options[@"--r"];
    NSString *gString = options[@"--g"];
    NSString *bString = options[@"--b"];
    if (opcodeString == nil || rString == nil || gString == nil || bString == nil) {
        fprintf(stderr, "t50 color-probe requires --opcode, --r, --g, and --b.\n");
        return 1;
    }

    NSUInteger opcode = 0;
    NSUInteger red = 0;
    NSUInteger green = 0;
    NSUInteger blue = 0;
    NSUInteger flag = 0x80;
    NSUInteger offset = 8;
    if (![self parseRequiredUnsigned:opcodeString maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--flag"] maxValue:255 fieldName:@"--flag" output:&flag errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--offset"] maxValue:71 fieldName:@"--offset" output:&offset errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    uint8_t rgb[3] = {(uint8_t)red, (uint8_t)green, (uint8_t)blue};
    NSData *payload = [NSData dataWithBytes:rgb length:sizeof(rgb)];
    return [self runT50WriteProbeWithOptions:options
                                      opcode:opcode
                                        flag:flag
                                      offset:offset
                                     payload:payload
                                successLabel:@"t50 color-probe"];
}

- (int)runT50WriteProbeWithOptions:(NSDictionary<NSString *, NSString *> *)options
                            opcode:(NSUInteger)opcode
                              flag:(NSUInteger)flag
                            offset:(NSUInteger)offset
                           payload:(NSData *)payload
                      successLabel:(NSString *)successLabel {
    NSString *selectionError = nil;
    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&selectionError];
    if (target == nil) {
        fprintf(stderr, "%s\n", selectionError.UTF8String);
        return 1;
    }

    NSError *exchangeError = nil;
    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                  opcode:(uint8_t)opcode
                                                               writeFlag:(uint8_t)flag
                                                           payloadOffset:offset
                                                                 payload:payload
                                                                   error:&exchangeError];
    if (response == nil) {
        fprintf(stderr, "%s error: %s\n", successLabel.UTF8String, exchangeError.localizedDescription.UTF8String);
        return 1;
    }

    printf("%s ok opcode=0x%02lx flag=0x%02lx offset=%lu payload=%s response_head=%s\n",
           successLabel.UTF8String,
           (unsigned long)opcode,
           (unsigned long)flag,
           (unsigned long)offset,
           [self hexStringFromData:payload].UTF8String,
           [self hexStringFromData:[response subdataWithRange:NSMakeRange(0, MIN((NSUInteger)16, response.length))]].UTF8String);
    return 0;
}

- (nullable MLDMouseDevice *)selectT50DeviceWithOptions:(NSDictionary<NSString *, NSString *> *)options
                                            errorMessage:(NSString **)errorMessage {
    NSError *discoveryError = nil;
    NSArray<MLDMouseDevice *> *devices = [self.discoverUseCase execute:&discoveryError];
    if (discoveryError != nil) {
        if (errorMessage != nil) {
            *errorMessage = [NSString stringWithFormat:@"Discovery error: %@", discoveryError.localizedDescription];
        }
        return nil;
    }

    if (devices.count == 0) {
        if (errorMessage != nil) {
            *errorMessage = @"No supported Bloody devices found.";
        }
        return nil;
    }

    NSError *selectionError = nil;
    NSArray<MLDMouseDevice *> *candidates = [self filterDevices:devices options:options error:&selectionError];
    if (selectionError != nil) {
        if (errorMessage != nil) {
            *errorMessage = [NSString stringWithFormat:@"Selector error: %@", selectionError.localizedDescription];
        }
        return nil;
    }
    if (candidates.count == 0) {
        if (errorMessage != nil) {
            *errorMessage = @"No matching Bloody device for the provided selectors.";
        }
        return nil;
    }

    for (MLDMouseDevice *device in candidates) {
        if ([MLDSupportedDeviceCatalog isT50Device:device]) {
            return device;
        }
    }

    if (errorMessage != nil) {
        *errorMessage = @"Matching Bloody devices were found, but none were recognized as T50.";
    }
    return nil;
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
