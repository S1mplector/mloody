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

static const NSUInteger MLDT50DirectColorSlotCount = 21;
static const NSUInteger MLDT50DirectColorStartOffset = 6;
static const NSUInteger MLDT50SimulatorColorIndexCount = 116;
static const NSUInteger MLDT50SimulatorChunkSize = 58;
static const NSUInteger MLDT50SimulatorChunkSplitOffset = 56;

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
    printf("  t50 sled-profile-get [selectors]\n");
    printf("  t50 sled-profile-set --index <0..255> [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 sled-enable-get [selectors]\n");
    printf("  t50 sled-enable-set --enabled <0|1> [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 core-get [selectors]\n");
    printf("  t50 core-state [selectors]\n");
    printf("  t50 core-set --core <1..4> [--verify <0|1>] [--retries <n>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 core-scan [--from <1..4>] [--to <1..4>] [--verify <0|1>] [--retries <n>] [--delay-ms <n>] [--restore <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 core-recover [--core <1..4>] [--verify <0|1>] [--retries <n>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 save [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 command-read --opcode <n> [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 command-write --opcode <n> --data <hex> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 flash-read8 --addr <n> [selectors]\n");
    printf("  t50 flash-read32 --addr <n> [--count <1..2>] [selectors]\n");
    printf("  t50 flash-write16 --addr <n> --data <hex> [--verify <0|1>] --unsafe <0|1> [selectors]\n");
    printf("  t50 flash-write32 --addr <n> --data <hex> --unsafe <0|1> [selectors]\n");
    printf("  t50 adjustgun-write16 --addr <n> --data <hex256> --unsafe <0|1> [selectors]\n");
    printf("  t50 adjustgun-dump --addr <n> [--words <n>] [--file <path>] [selectors]\n");
    printf("  t50 adjustgun-scan [--from <n>] [--to <n>] [--step <n>] [selectors]\n");
    printf("  t50 flash-scan8 --from <n> --to <n> [--step <n>] [--nonzero-only <0|1>] [selectors]\n");
    printf("  t50 flash-capture --file <path> [--from <n>] [--to <n>] [--step <n>] [--nonzero-only <0|1>] [selectors]\n");
    printf("  t50 flash-diff --before <path> --after <path>\n");
    printf("  t50 opcode-scan [--from <n>] [--to <n>] [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 capture --file <path> [--from <n>] [--to <n>] [--flag <n>] [--offset <n>] [--data <hex>] [selectors]\n");
    printf("  t50 capture-diff --before <path> --after <path>\n");
    printf("  t50 dpi-set --dpi <n> [--nearest <0|1>] [--calibrate-down <n>] [--delay-ms <n>] [--opcode <n>] [--commit <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 dpi-probe --opcode <n> --dpi <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 dpi-step --action <up|down|cycle> [--count <n>] [--delay-ms <n>] [--opcode <n>] [--commit <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 polling-probe --opcode <n> --hz <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 lod-probe --opcode <n> --lod <n> [--flag <n>] [--offset <n>] [selectors]\n");
    printf("  t50 color-mode --mode <open|effect|discard> [selectors]\n");
    printf("  t50 color-direct --r <n> --g <n> --b <n> [--slots <1..21>] [--slot <1..21>] [--frames <1..120>] [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 color-zone --zone <logo|wheel|wheel-indicator|rear|all> --r <n> --g <n> --b <n> [--frames <1..120>] [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 color-sweep --r <n> --g <n> --b <n> [--from <1..21>] [--to <1..21>] [--delay-ms <n>] [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
    printf("  t50 color-sim116 --r <n> --g <n> --b <n> [--index <0..115>] [--from <0..115>] [--to <0..115>] [--delay-ms <n>] [--prepare <0|1>] [--save <0|1>] [--strategy <quick|capture-v1|capture-v2|capture-v3|capture-v4|major-sync>] [selectors]\n");
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
    if ([subcommand isEqualToString:@"sled-profile-get"]) {
        return [self runT50SLEDProfileGetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"sled-profile-set"]) {
        return [self runT50SLEDProfileSetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"sled-enable-get"]) {
        return [self runT50SLEDEnableGetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"sled-enable-set"]) {
        return [self runT50SLEDEnableSetWithArguments:subArguments];
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
    if ([subcommand isEqualToString:@"core-scan"]) {
        return [self runT50CoreScanWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"core-recover"]) {
        return [self runT50CoreRecoverWithArguments:subArguments];
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
    if ([subcommand isEqualToString:@"flash-read8"]) {
        return [self runT50FlashRead8WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-read32"]) {
        return [self runT50FlashRead32WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-write16"]) {
        return [self runT50FlashWrite16WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-write32"]) {
        return [self runT50FlashWrite32WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"adjustgun-write16"]) {
        return [self runT50AdjustGunWrite16WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"adjustgun-dump"]) {
        return [self runT50AdjustGunDumpWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"adjustgun-scan"]) {
        return [self runT50AdjustGunScanWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-scan8"]) {
        return [self runT50FlashScan8WithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-capture"]) {
        return [self runT50FlashCaptureWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"flash-diff"]) {
        return [self runT50FlashDiffWithArguments:subArguments];
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
    if ([subcommand isEqualToString:@"dpi-set"]) {
        return [self runT50DPISetWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"dpi-probe"]) {
        return [self runT50DPIProbeWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"dpi-step"]) {
        return [self runT50DPIStepWithArguments:subArguments];
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
    if ([subcommand isEqualToString:@"color-sweep"]) {
        return [self runT50ColorSweepWithArguments:subArguments];
    }
    if ([subcommand isEqualToString:@"color-sim116"]) {
        return [self runT50ColorSimulator116WithArguments:subArguments];
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

- (int)runT50SLEDProfileGetWithArguments:(NSArray<NSString *> *)arguments {
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
    NSNumber *index = [self.t50ExchangeCommandUseCase readSLEDProfileIndexCandidateForDevice:target error:&error];
    if (index == nil) {
        fprintf(stderr, "t50 sled-profile-get error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 sled-profile-get candidate-index=%lu\n", (unsigned long)index.unsignedIntegerValue);
    return 0;
}

- (int)runT50SLEDProfileSetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--index", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *indexString = options[@"--index"];
    if (indexString == nil) {
        fprintf(stderr, "t50 sled-profile-set requires --index <0..255>.\n");
        return 1;
    }

    NSUInteger indexValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:indexString maxValue:255 fieldName:@"--index" output:&indexValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV3;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v3"
                               subcommand:@"t50 sled-profile-set"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *setError = nil;
    BOOL setOK = [self.t50ExchangeCommandUseCase setSLEDProfileIndexCandidate:(uint8_t)indexValue
                                                                      onDevice:target
                                                                         error:&setError];
    if (!setOK) {
        fprintf(stderr, "t50 sled-profile-set error: %s\n", setError.localizedDescription.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saveOK) {
            fprintf(stderr, "t50 sled-profile-set save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 sled-profile-set requested=%lu save=%lu strategy=%s\n",
           (unsigned long)indexValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50SLEDEnableGetWithArguments:(NSArray<NSString *> *)arguments {
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
    NSNumber *enabled = [self.t50ExchangeCommandUseCase readSLEDEnabledCandidateForDevice:target error:&error];
    if (enabled == nil) {
        fprintf(stderr, "t50 sled-enable-get error: %s\n", error.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 sled-enable-get enabled=%lu\n", (unsigned long)enabled.unsignedIntegerValue);
    return 0;
}

- (int)runT50SLEDEnableSetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--enabled", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *enabledString = options[@"--enabled"];
    if (enabledString == nil) {
        fprintf(stderr, "t50 sled-enable-set requires --enabled <0|1>.\n");
        return 1;
    }

    NSUInteger enabledValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:enabledString maxValue:1 fieldName:@"--enabled" output:&enabledValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV3;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v3"
                               subcommand:@"t50 sled-enable-set"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *setError = nil;
    BOOL setOK = [self.t50ExchangeCommandUseCase setSLEDEnabledCandidate:(enabledValue == 1)
                                                                 onDevice:target
                                                                    error:&setError];
    if (!setOK) {
        fprintf(stderr, "t50 sled-enable-set error: %s\n", setError.localizedDescription.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saveOK) {
            fprintf(stderr, "t50 sled-enable-set save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 sled-enable-set requested=%lu save=%lu strategy=%s\n",
           (unsigned long)enabledValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
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

- (BOOL)applyT50CoreSlotCandidate:(uint8_t)slot
                          onDevice:(MLDMouseDevice *)device
                            verify:(BOOL)verify
                           retries:(NSUInteger)retries
                     observedState:(NSDictionary<NSString *, NSNumber *> * _Nullable * _Nullable)observedState
                      errorMessage:(NSString **)errorMessage {
    if (observedState != nil) {
        *observedState = nil;
    }

    const NSUInteger attempts = retries + 1;
    for (NSUInteger attempt = 0; attempt < attempts; ++attempt) {
        NSError *setError = nil;
        BOOL setOK = [self.t50ExchangeCommandUseCase setCoreSlotCandidate:slot onDevice:device error:&setError];
        if (!setOK) {
            if (errorMessage != nil) {
                *errorMessage = [NSString stringWithFormat:@"core write failed at attempt %lu/%lu: %@",
                                                           (unsigned long)(attempt + 1),
                                                           (unsigned long)attempts,
                                                           setError.localizedDescription];
            }
            return NO;
        }

        NSError *readError = nil;
        NSDictionary<NSString *, NSNumber *> *state =
            [self.t50ExchangeCommandUseCase readCoreStateCandidateForDevice:device error:&readError];
        if (state != nil && observedState != nil) {
            *observedState = state;
        }

        if (!verify) {
            return YES;
        }

        if (state != nil) {
            NSNumber *observedSlot = state[@"slot"];
            if (observedSlot != nil && observedSlot.unsignedIntegerValue == slot) {
                return YES;
            }
        }

        if (attempt + 1 < attempts) {
            [NSThread sleepForTimeInterval:0.05];
            continue;
        }

        if (errorMessage != nil) {
            if (state == nil) {
                *errorMessage = [NSString stringWithFormat:@"core verify read failed after %lu attempts: %@",
                                                           (unsigned long)attempts,
                                                           readError.localizedDescription];
            } else {
                NSUInteger observedSlot = [state[@"slot"] unsignedIntegerValue];
                NSUInteger lowBits = [state[@"lowBits"] unsignedIntegerValue];
                NSUInteger rawWord = [state[@"rawWord"] unsignedIntegerValue];
                *errorMessage = [NSString stringWithFormat:@"core verify mismatch after %lu attempts: requested=%u observed=%lu low2=%lu raw=0x%04lx",
                                                           (unsigned long)attempts,
                                                           slot,
                                                           (unsigned long)observedSlot,
                                                           (unsigned long)lowBits,
                                                           (unsigned long)rawWord];
            }
        }
        return NO;
    }

    if (errorMessage != nil) {
        *errorMessage = @"core write loop did not execute.";
    }
    return NO;
}

- (int)runT50CoreSetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--core", @"--verify", @"--retries", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
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
    NSUInteger verifyValue = 1;
    NSUInteger retries = 2;
    NSUInteger saveValue = 1;
    if (![self parseRequiredUnsigned:coreString maxValue:4 fieldName:@"--core" output:&coreValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--verify"] maxValue:1 fieldName:@"--verify" output:&verifyValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--retries"] maxValue:20 fieldName:@"--retries" output:&retries errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (coreValue == 0) {
        fprintf(stderr, "--core must be between 1 and 4.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV1;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v1"
                               subcommand:@"t50 core-set"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSDictionary<NSString *, NSNumber *> *observedState = nil;
    NSString *coreError = nil;
    BOOL setOK = [self applyT50CoreSlotCandidate:(uint8_t)coreValue
                                        onDevice:target
                                          verify:(verifyValue == 1)
                                         retries:retries
                                   observedState:&observedState
                                    errorMessage:&coreError];
    if (!setOK) {
        fprintf(stderr, "t50 core-set error: %s\n", coreError.UTF8String);
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

    NSUInteger observedSlot = [observedState[@"slot"] unsignedIntegerValue];
    NSUInteger lowBits = [observedState[@"lowBits"] unsignedIntegerValue];
    NSUInteger rawWord = [observedState[@"rawWord"] unsignedIntegerValue];
    printf("t50 core-set candidate=%lu observed=%lu low2=%lu raw=0x%04lx verify=%lu retries=%lu save=%lu strategy=%s\n",
           (unsigned long)coreValue,
           (unsigned long)observedSlot,
           (unsigned long)lowBits,
           (unsigned long)rawWord,
           (unsigned long)verifyValue,
           (unsigned long)retries,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50CoreScanWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--from", @"--to", @"--verify", @"--retries", @"--delay-ms", @"--restore", @"--save", @"--strategy", @"--vid", @"--pid",
        @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger fromCore = 1;
    NSUInteger toCore = 4;
    NSUInteger verifyValue = 1;
    NSUInteger retries = 1;
    NSUInteger delayMilliseconds = 150;
    NSUInteger restoreValue = 1;
    NSUInteger saveValue = 0;

    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:4 fieldName:@"--from" output:&fromCore errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:4 fieldName:@"--to" output:&toCore errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--verify"] maxValue:1 fieldName:@"--verify" output:&verifyValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--retries"] maxValue:20 fieldName:@"--retries" output:&retries errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--delay-ms"] maxValue:5000 fieldName:@"--delay-ms" output:&delayMilliseconds errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--restore"] maxValue:1 fieldName:@"--restore" output:&restoreValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (fromCore == 0 || toCore == 0 || fromCore > toCore) {
        fprintf(stderr, "t50 core-scan requires 1 <= --from <= --to <= 4.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV1;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v1"
                               subcommand:@"t50 core-scan"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *initialError = nil;
    NSDictionary<NSString *, NSNumber *> *initialState =
        [self.t50ExchangeCommandUseCase readCoreStateCandidateForDevice:target error:&initialError];
    if (initialState == nil) {
        fprintf(stderr, "t50 core-scan initial read error: %s\n", initialError.localizedDescription.UTF8String);
        return 1;
    }

    NSUInteger initialCore = [initialState[@"slot"] unsignedIntegerValue];
    printf("t50 core-scan begin from=%lu to=%lu initial-core=%lu verify=%lu retries=%lu delay-ms=%lu restore=%lu save=%lu strategy=%s\n",
           (unsigned long)fromCore,
           (unsigned long)toCore,
           (unsigned long)initialCore,
           (unsigned long)verifyValue,
           (unsigned long)retries,
           (unsigned long)delayMilliseconds,
           (unsigned long)restoreValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);

    BOOL failed = NO;
    for (NSUInteger core = fromCore; core <= toCore; ++core) {
        NSDictionary<NSString *, NSNumber *> *state = nil;
        NSString *coreError = nil;
        BOOL setOK = [self applyT50CoreSlotCandidate:(uint8_t)core
                                            onDevice:target
                                              verify:(verifyValue == 1)
                                             retries:retries
                                       observedState:&state
                                        errorMessage:&coreError];
        if (!setOK) {
            fprintf(stderr, "t50 core-scan set error core=%lu: %s\n",
                    (unsigned long)core,
                    coreError.UTF8String);
            failed = YES;
            break;
        }

        if (saveValue == 1) {
            NSError *saveError = nil;
            BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
            if (!saveOK) {
                fprintf(stderr, "t50 core-scan save error core=%lu: %s\n",
                        (unsigned long)core,
                        saveError.localizedDescription.UTF8String);
                failed = YES;
                break;
            }
        }

        NSUInteger observedCore = [state[@"slot"] unsignedIntegerValue];
        NSUInteger lowBits = [state[@"lowBits"] unsignedIntegerValue];
        NSUInteger rawWord = [state[@"rawWord"] unsignedIntegerValue];
        printf("t50 core-scan core=%lu observed=%lu low2=%lu raw=0x%04lx\n",
               (unsigned long)core,
               (unsigned long)observedCore,
               (unsigned long)lowBits,
               (unsigned long)rawWord);

        if (delayMilliseconds > 0 && core < toCore) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    if (restoreValue == 1 && initialCore >= 1 && initialCore <= 4) {
        NSDictionary<NSString *, NSNumber *> *restoredState = nil;
        NSString *restoreError = nil;
        BOOL restoreOK = [self applyT50CoreSlotCandidate:(uint8_t)initialCore
                                                onDevice:target
                                                  verify:(verifyValue == 1)
                                                 retries:retries
                                           observedState:&restoredState
                                            errorMessage:&restoreError];
        if (!restoreOK) {
            fprintf(stderr, "t50 core-scan restore error: %s\n", restoreError.UTF8String);
            failed = YES;
        } else {
            if (saveValue == 1) {
                NSError *saveError = nil;
                BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
                if (!saveOK) {
                    fprintf(stderr, "t50 core-scan restore save error: %s\n", saveError.localizedDescription.UTF8String);
                    failed = YES;
                }
            }

            NSUInteger observedCore = [restoredState[@"slot"] unsignedIntegerValue];
            NSUInteger lowBits = [restoredState[@"lowBits"] unsignedIntegerValue];
            NSUInteger rawWord = [restoredState[@"rawWord"] unsignedIntegerValue];
            printf("t50 core-scan restored core=%lu observed=%lu low2=%lu raw=0x%04lx\n",
                   (unsigned long)initialCore,
                   (unsigned long)observedCore,
                   (unsigned long)lowBits,
                   (unsigned long)rawWord);
        }
    }

    return failed ? 1 : 0;
}

- (int)runT50CoreRecoverWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--core", @"--verify", @"--retries", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger coreValue = 1;
    NSUInteger verifyValue = 1;
    NSUInteger retries = 3;
    NSUInteger saveValue = 1;
    if (![self parseOptionalUnsigned:options[@"--core"] maxValue:4 fieldName:@"--core" output:&coreValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--verify"] maxValue:1 fieldName:@"--verify" output:&verifyValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--retries"] maxValue:20 fieldName:@"--retries" output:&retries errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (coreValue == 0) {
        fprintf(stderr, "--core must be between 1 and 4.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV4;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v4"
                               subcommand:@"t50 core-recover"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSDictionary<NSString *, NSNumber *> *state = nil;
    NSString *coreError = nil;
    BOOL setOK = [self applyT50CoreSlotCandidate:(uint8_t)coreValue
                                        onDevice:target
                                          verify:(verifyValue == 1)
                                         retries:retries
                                   observedState:&state
                                    errorMessage:&coreError];
    if (!setOK) {
        fprintf(stderr, "t50 core-recover error: %s\n", coreError.UTF8String);
        return 1;
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saveOK = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saveOK) {
            fprintf(stderr, "t50 core-recover save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    NSUInteger observedCore = [state[@"slot"] unsignedIntegerValue];
    NSUInteger lowBits = [state[@"lowBits"] unsignedIntegerValue];
    NSUInteger rawWord = [state[@"rawWord"] unsignedIntegerValue];
    printf("t50 core-recover target=%lu observed=%lu low2=%lu raw=0x%04lx verify=%lu retries=%lu save=%lu strategy=%s\n",
           (unsigned long)coreValue,
           (unsigned long)observedCore,
           (unsigned long)lowBits,
           (unsigned long)rawWord,
           (unsigned long)verifyValue,
           (unsigned long)retries,
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

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"quick"
                               subcommand:@"t50 save"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
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

- (int)runT50FlashRead8WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--addr", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    if (addrString == nil) {
        fprintf(stderr, "t50 flash-read8 requires --addr <n>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFF fieldName:@"--addr" output:&addressValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *flashError = nil;
    NSData *bytes = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:(uint16_t)addressValue
                                                                       onDevice:target
                                                                          error:&flashError];
    if (bytes == nil) {
        fprintf(stderr, "t50 flash-read8 error: %s\n", flashError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 flash-read8 ok addr=0x%04lx data=%s\n",
           (unsigned long)addressValue,
           [self hexStringFromData:bytes].UTF8String);
    return 0;
}

- (int)runT50FlashRead32WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[@"--addr", @"--count", @"--vid", @"--pid", @"--serial", @"--model"]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    if (addrString == nil) {
        fprintf(stderr, "t50 flash-read32 requires --addr <n>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    NSUInteger countValue = 1;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFFFFFFu fieldName:@"--addr" output:&addressValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--count"] maxValue:2 fieldName:@"--count" output:&countValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (countValue == 0) {
        fprintf(stderr, "t50 flash-read32 --count must be between 1 and 2.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *flashError = nil;
    NSData *bytes = [self.t50ExchangeCommandUseCase readFlashDWordsFromAddress:(uint32_t)addressValue
                                                                         count:(uint8_t)countValue
                                                                      onDevice:target
                                                                         error:&flashError];
    if (bytes == nil) {
        fprintf(stderr, "t50 flash-read32 error: %s\n", flashError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 flash-read32 ok addr=0x%08lx count=%lu data=%s\n",
           (unsigned long)addressValue,
           (unsigned long)countValue,
           [self hexStringFromData:bytes].UTF8String);
    return 0;
}

- (int)runT50FlashWrite16WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--addr", @"--data", @"--verify", @"--unsafe", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    NSString *dataString = options[@"--data"];
    if (addrString == nil || dataString == nil) {
        fprintf(stderr, "t50 flash-write16 requires --addr <n> and --data <hex>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    NSUInteger verifyValue = 0;
    NSUInteger unsafeValue = 0;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFF fieldName:@"--addr" output:&addressValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--verify"] maxValue:1 fieldName:@"--verify" output:&verifyValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--unsafe"] maxValue:1 fieldName:@"--unsafe" output:&unsafeValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (unsafeValue != 1) {
        fprintf(stderr, "t50 flash-write16 requires --unsafe 1.\n");
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

    NSError *flashError = nil;
    BOOL ok = [self.t50ExchangeCommandUseCase writeFlashWordsToAddress:(uint16_t)addressValue
                                                               wordData:payload
                                                             verifyMode:(verifyValue == 1)
                                                               onDevice:target
                                                                  error:&flashError];
    if (!ok) {
        fprintf(stderr, "t50 flash-write16 error: %s\n", flashError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 flash-write16 ok addr=0x%04lx words=%lu verify=%lu payload=%s\n",
           (unsigned long)addressValue,
           (unsigned long)(payload.length / 2),
           (unsigned long)verifyValue,
           [self hexStringFromData:payload].UTF8String);
    return 0;
}

- (int)runT50FlashWrite32WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--addr", @"--data", @"--unsafe", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    NSString *dataString = options[@"--data"];
    if (addrString == nil || dataString == nil) {
        fprintf(stderr, "t50 flash-write32 requires --addr <n> and --data <hex>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    NSUInteger unsafeValue = 0;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFFFFFFu fieldName:@"--addr" output:&addressValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--unsafe"] maxValue:1 fieldName:@"--unsafe" output:&unsafeValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (unsafeValue != 1) {
        fprintf(stderr, "t50 flash-write32 requires --unsafe 1.\n");
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

    NSError *flashError = nil;
    BOOL ok = [self.t50ExchangeCommandUseCase writeFlashDWordsToAddress:(uint32_t)addressValue
                                                               dwordData:payload
                                                                onDevice:target
                                                                   error:&flashError];
    if (!ok) {
        fprintf(stderr, "t50 flash-write32 error: %s\n", flashError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 flash-write32 ok addr=0x%08lx dwords=%lu payload=%s\n",
           (unsigned long)addressValue,
           (unsigned long)(payload.length / 4),
           [self hexStringFromData:payload].UTF8String);
    return 0;
}

- (int)runT50AdjustGunWrite16WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--addr", @"--data", @"--unsafe", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    NSString *dataString = options[@"--data"];
    if (addrString == nil || dataString == nil) {
        fprintf(stderr, "t50 adjustgun-write16 requires --addr <n> and --data <hex256>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    NSUInteger unsafeValue = 0;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFF fieldName:@"--addr" output:&addressValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--unsafe"] maxValue:1 fieldName:@"--unsafe" output:&unsafeValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (unsafeValue != 1) {
        fprintf(stderr, "t50 adjustgun-write16 requires --unsafe 1.\n");
        return 1;
    }

    NSData *payload = [self dataFromHexInput:dataString errorMessage:&parseError];
    if (payload == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (payload.length != 256) {
        fprintf(stderr, "t50 adjustgun-write16 requires exactly 256 payload bytes (128 words).\n");
        return 1;
    }

    const uint8_t *rawPayload = (const uint8_t *)payload.bytes;
    uint16_t checksum1 = 0;
    uint16_t checksum2 = 0;
    for (NSUInteger index = 4; index < 128; ++index) {
        NSUInteger offset = index * 2;
        uint16_t value = (uint16_t)rawPayload[offset] | ((uint16_t)rawPayload[offset + 1] << 8);
        checksum1 = (uint16_t)(checksum1 + value);
        checksum2 = (uint16_t)(checksum2 + (uint16_t)(value * (uint16_t)index));
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSError *writeError = nil;
    BOOL ok = [self.t50ExchangeCommandUseCase writeAdjustGunWordTableToBaseAddress:(uint16_t)addressValue
                                                                           tableData:payload
                                                                            onDevice:target
                                                                               error:&writeError];
    if (!ok) {
        fprintf(stderr, "t50 adjustgun-write16 error: %s\n", writeError.localizedDescription.UTF8String);
        return 1;
    }

    NSError *headerError = nil;
    NSData *header = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:(uint16_t)addressValue
                                                                        onDevice:target
                                                                           error:&headerError];
    if (header == nil || header.length < 8) {
        fprintf(stderr, "t50 adjustgun-write16 warning: header readback failed: %s\n",
                headerError.localizedDescription.UTF8String);
        printf("t50 adjustgun-write16 ok addr=0x%04lx checksum1=0x%04x checksum2=0x%04x\n",
               (unsigned long)addressValue,
               checksum1,
               checksum2);
        return 0;
    }

    const uint8_t *headerBytes = (const uint8_t *)header.bytes;
    uint16_t marker = (uint16_t)headerBytes[0] | ((uint16_t)headerBytes[1] << 8);
    uint16_t headerWord1 = (uint16_t)headerBytes[2] | ((uint16_t)headerBytes[3] << 8);
    uint16_t headerChecksum1 = (uint16_t)headerBytes[4] | ((uint16_t)headerBytes[5] << 8);
    uint16_t headerChecksum2 = (uint16_t)headerBytes[6] | ((uint16_t)headerBytes[7] << 8);

    printf("t50 adjustgun-write16 ok addr=0x%04lx checksum1=0x%04x checksum2=0x%04x readback=%s\n",
           (unsigned long)addressValue,
           checksum1,
           checksum2,
           [self hexStringFromData:header].UTF8String);
    printf("  header marker=0x%04x word1=0x%04x checksum1=0x%04x checksum2=0x%04x\n",
           marker,
           headerWord1,
           headerChecksum1,
           headerChecksum2);
    return 0;
}

- (int)runT50AdjustGunScanWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--from", @"--to", @"--step", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger fromValue = 0x0000;
    NSUInteger toValue = 0xFFFF;
    NSUInteger stepValue = 0x0010;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:0xFFFF fieldName:@"--from" output:&fromValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:0xFFFF fieldName:@"--to" output:&toValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--step"] maxValue:0xFFFF fieldName:@"--step" output:&stepValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (fromValue > toValue) {
        fprintf(stderr, "t50 adjustgun-scan requires --from <= --to.\n");
        return 1;
    }
    if (stepValue == 0) {
        fprintf(stderr, "t50 adjustgun-scan --step must be >= 1.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    printf("t50 adjustgun-scan begin from=0x%04lx to=0x%04lx step=0x%04lx\n",
           (unsigned long)fromValue,
           (unsigned long)toValue,
           (unsigned long)stepValue);

    NSUInteger hitCount = 0;
    for (NSUInteger address = fromValue; address <= toValue; ) {
        NSError *readError = nil;
        NSData *data = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:(uint16_t)address
                                                                           onDevice:target
                                                                              error:&readError];
        if (data != nil && data.length >= 8) {
            const uint8_t *bytes = (const uint8_t *)data.bytes;
            if (bytes[0] == 0xA4 && bytes[1] == 0xA4 && bytes[2] == 0xFF && bytes[3] == 0xFF) {
                uint16_t checksum1 = (uint16_t)bytes[4] | ((uint16_t)bytes[5] << 8);
                uint16_t checksum2 = (uint16_t)bytes[6] | ((uint16_t)bytes[7] << 8);
                printf("  addr=0x%04lx marker=a4a4 word1=ffff checksum1=0x%04x checksum2=0x%04x raw=%s\n",
                       (unsigned long)address,
                       checksum1,
                       checksum2,
                       [self hexStringFromData:data].UTF8String);
                hitCount += 1;
            }
        }

        if (address > (NSUIntegerMax - stepValue)) {
            break;
        }
        NSUInteger next = address + stepValue;
        if (next <= address) {
            break;
        }
        address = next;
    }

    printf("t50 adjustgun-scan done hits=%lu\n", (unsigned long)hitCount);
    return 0;
}

- (int)runT50AdjustGunDumpWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--addr", @"--words", @"--file", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *addrString = options[@"--addr"];
    if (addrString == nil) {
        fprintf(stderr, "t50 adjustgun-dump requires --addr <n>.\n");
        return 1;
    }

    NSUInteger addressValue = 0;
    NSUInteger wordsValue = 128;
    if (![self parseRequiredUnsigned:addrString maxValue:0xFFFF fieldName:@"--addr" output:&addressValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--words"] maxValue:1024 fieldName:@"--words" output:&wordsValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (wordsValue == 0) {
        fprintf(stderr, "t50 adjustgun-dump --words must be >= 1.\n");
        return 1;
    }

    NSUInteger bytesToRead = wordsValue * 2;
    NSUInteger blockCount = (bytesToRead + 7) / 8;
    if (blockCount == 0) {
        fprintf(stderr, "t50 adjustgun-dump internal error: zero block count.\n");
        return 1;
    }
    NSUInteger lastAddress = addressValue + ((blockCount - 1) * 4);
    if (lastAddress > 0xFFFF) {
        fprintf(stderr, "t50 adjustgun-dump range exceeds flash address space (base=0x%04lx words=%lu).\n",
                (unsigned long)addressValue,
                (unsigned long)wordsValue);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSMutableData *tableData = [NSMutableData dataWithCapacity:(blockCount * 8)];
    for (NSUInteger blockIndex = 0; blockIndex < blockCount; ++blockIndex) {
        uint16_t readAddress = (uint16_t)(addressValue + (blockIndex * 4));
        NSError *readError = nil;
        NSData *block = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:readAddress
                                                                           onDevice:target
                                                                              error:&readError];
        if (block == nil || block.length < 8) {
            fprintf(stderr, "t50 adjustgun-dump read error at addr=0x%04x: %s\n",
                    readAddress,
                    readError.localizedDescription.UTF8String);
            return 1;
        }
        [tableData appendData:block];
    }
    if (tableData.length > bytesToRead) {
        [tableData setLength:bytesToRead];
    }

    if (tableData.length < 8) {
        fprintf(stderr, "t50 adjustgun-dump requires at least 8 bytes, got %lu.\n",
                (unsigned long)tableData.length);
        return 1;
    }

    const uint8_t *bytes = (const uint8_t *)tableData.bytes;
    uint16_t marker = (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
    uint16_t word1 = (uint16_t)bytes[2] | ((uint16_t)bytes[3] << 8);
    uint16_t headerChecksum1 = (uint16_t)bytes[4] | ((uint16_t)bytes[5] << 8);
    uint16_t headerChecksum2 = (uint16_t)bytes[6] | ((uint16_t)bytes[7] << 8);

    uint16_t computedChecksum1 = 0;
    uint16_t computedChecksum2 = 0;
    for (NSUInteger wordIndex = 4; wordIndex < wordsValue; ++wordIndex) {
        NSUInteger byteIndex = wordIndex * 2;
        if ((byteIndex + 1) >= tableData.length) {
            break;
        }
        uint16_t value = (uint16_t)bytes[byteIndex] | ((uint16_t)bytes[byteIndex + 1] << 8);
        computedChecksum1 = (uint16_t)(computedChecksum1 + value);
        computedChecksum2 = (uint16_t)(computedChecksum2 + (uint16_t)(value * (uint16_t)wordIndex));
    }

    BOOL markerLooksValid = (marker == 0xA4A4 && word1 == 0xFFFF);
    BOOL checksumsMatch = (headerChecksum1 == computedChecksum1 && headerChecksum2 == computedChecksum2);

    printf("t50 adjustgun-dump addr=0x%04lx words=%lu bytes=%lu\n",
           (unsigned long)addressValue,
           (unsigned long)wordsValue,
           (unsigned long)tableData.length);
    printf("  header marker=0x%04x word1=0x%04x checksum1=0x%04x checksum2=0x%04x\n",
           marker,
           word1,
           headerChecksum1,
           headerChecksum2);
    printf("  computed checksum1=0x%04x checksum2=0x%04x marker-valid=%s checksum-match=%s\n",
           computedChecksum1,
           computedChecksum2,
           markerLooksValid ? "yes" : "no",
           checksumsMatch ? "yes" : "no");
    printf("  data=%s\n", [self hexStringFromData:tableData].UTF8String);

    NSString *filePath = options[@"--file"];
    if (filePath != nil && filePath.length > 0) {
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
                @"base_addr" : @(addressValue),
                @"words" : @(wordsValue),
                @"bytes" : @(tableData.length)
            },
            @"header" : @{
                @"marker" : @(marker),
                @"word1" : @(word1),
                @"checksum1" : @(headerChecksum1),
                @"checksum2" : @(headerChecksum2)
            },
            @"computed" : @{
                @"checksum1" : @(computedChecksum1),
                @"checksum2" : @(computedChecksum2),
                @"marker_valid" : @(markerLooksValid),
                @"checksum_match" : @(checksumsMatch)
            },
            @"data_hex" : [self hexStringFromData:tableData]
        };

        NSError *jsonError = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:capture options:NSJSONWritingPrettyPrinted error:&jsonError];
        if (jsonData == nil) {
            fprintf(stderr, "t50 adjustgun-dump JSON encode error: %s\n", jsonError.localizedDescription.UTF8String);
            return 1;
        }

        BOOL wrote = [jsonData writeToFile:filePath options:NSDataWritingAtomic error:&jsonError];
        if (!wrote) {
            fprintf(stderr, "t50 adjustgun-dump file write error: %s\n", jsonError.localizedDescription.UTF8String);
            return 1;
        }
        printf("  saved=%s\n", filePath.UTF8String);
    }

    return 0;
}

- (int)runT50FlashScan8WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--from", @"--to", @"--step", @"--nonzero-only", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSUInteger fromValue = 0;
    NSUInteger toValue = 0xFFFF;
    NSUInteger stepValue = 0x0100;
    NSUInteger nonzeroOnlyValue = 1;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:0xFFFF fieldName:@"--from" output:&fromValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:0xFFFF fieldName:@"--to" output:&toValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--step"] maxValue:0xFFFF fieldName:@"--step" output:&stepValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--nonzero-only"] maxValue:1 fieldName:@"--nonzero-only" output:&nonzeroOnlyValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (fromValue > toValue) {
        fprintf(stderr, "t50 flash-scan8 requires --from <= --to.\n");
        return 1;
    }
    if (stepValue == 0) {
        fprintf(stderr, "t50 flash-scan8 --step must be >= 1.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    printf("t50 flash-scan8 begin from=0x%04lx to=0x%04lx step=0x%04lx nonzero-only=%lu\n",
           (unsigned long)fromValue,
           (unsigned long)toValue,
           (unsigned long)stepValue,
           (unsigned long)nonzeroOnlyValue);

    NSUInteger successCount = 0;
    NSUInteger printedCount = 0;
    for (NSUInteger address = fromValue; address <= toValue; ) {
        NSError *flashError = nil;
        NSData *bytes = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:(uint16_t)address
                                                                           onDevice:target
                                                                              error:&flashError];
        if (bytes == nil) {
            printf("  addr=0x%04lx err=%s\n",
                   (unsigned long)address,
                   flashError.localizedDescription.UTF8String);
        } else {
            successCount += 1;
            const uint8_t *raw = (const uint8_t *)bytes.bytes;
            BOOL allZero = YES;
            for (NSUInteger i = 0; i < bytes.length; ++i) {
                if (raw[i] != 0x00) {
                    allZero = NO;
                    break;
                }
            }
            if (!(nonzeroOnlyValue == 1 && allZero)) {
                printf("  addr=0x%04lx data=%s\n",
                       (unsigned long)address,
                       [self hexStringFromData:bytes].UTF8String);
                printedCount += 1;
            }
        }

        if (address > (NSUIntegerMax - stepValue)) {
            break;
        }
        NSUInteger next = address + stepValue;
        if (next <= address) {
            break;
        }
        address = next;
    }

    printf("t50 flash-scan8 done success=%lu printed=%lu\n",
           (unsigned long)successCount,
           (unsigned long)printedCount);
    return 0;
}

- (int)runT50FlashCaptureWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--file", @"--from", @"--to", @"--step", @"--nonzero-only", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *filePath = options[@"--file"];
    if (filePath == nil || filePath.length == 0) {
        fprintf(stderr, "t50 flash-capture requires --file <path>.\n");
        return 1;
    }

    NSUInteger fromValue = 0;
    NSUInteger toValue = 0xFFFF;
    NSUInteger stepValue = 0x0100;
    NSUInteger nonzeroOnlyValue = 1;
    if (![self parseOptionalUnsigned:options[@"--from"] maxValue:0xFFFF fieldName:@"--from" output:&fromValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:0xFFFF fieldName:@"--to" output:&toValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--step"] maxValue:0xFFFF fieldName:@"--step" output:&stepValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--nonzero-only"] maxValue:1 fieldName:@"--nonzero-only" output:&nonzeroOnlyValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (fromValue > toValue) {
        fprintf(stderr, "t50 flash-capture requires --from <= --to.\n");
        return 1;
    }
    if (stepValue == 0) {
        fprintf(stderr, "t50 flash-capture --step must be >= 1.\n");
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSMutableArray<NSDictionary *> *entries = [NSMutableArray array];
    NSUInteger successCount = 0;
    for (NSUInteger address = fromValue; address <= toValue; ) {
        NSError *flashError = nil;
        NSData *bytes = [self.t50ExchangeCommandUseCase readFlashBytes8FromAddress:(uint16_t)address
                                                                           onDevice:target
                                                                              error:&flashError];
        if (bytes == nil) {
            [entries addObject:@{
                @"addr" : @(address),
                @"error" : flashError.localizedDescription ?: @"Unknown flash read error"
            }];
        } else {
            successCount += 1;
            const uint8_t *raw = (const uint8_t *)bytes.bytes;
            BOOL allZero = YES;
            for (NSUInteger i = 0; i < bytes.length; ++i) {
                if (raw[i] != 0x00) {
                    allZero = NO;
                    break;
                }
            }
            if (!(nonzeroOnlyValue == 1 && allZero)) {
                [entries addObject:@{
                    @"addr" : @(address),
                    @"data_hex" : [self hexStringFromData:bytes]
                }];
            }
        }

        if (address > (NSUIntegerMax - stepValue)) {
            break;
        }
        NSUInteger next = address + stepValue;
        if (next <= address) {
            break;
        }
        address = next;
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
            @"from_addr" : @(fromValue),
            @"to_addr" : @(toValue),
            @"step" : @(stepValue),
            @"nonzero_only" : @(nonzeroOnlyValue)
        },
        @"summary" : @{
            @"success_reads" : @(successCount),
            @"entry_count" : @(entries.count)
        },
        @"entries" : entries
    };

    NSError *jsonError = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:capture options:NSJSONWritingPrettyPrinted error:&jsonError];
    if (jsonData == nil) {
        fprintf(stderr, "Failed to encode flash capture JSON: %s\n", jsonError.localizedDescription.UTF8String);
        return 1;
    }

    BOOL writeOK = [jsonData writeToFile:filePath options:NSDataWritingAtomic error:&jsonError];
    if (!writeOK) {
        fprintf(stderr, "Failed to write flash capture file: %s\n", jsonError.localizedDescription.UTF8String);
        return 1;
    }

    printf("t50 flash-capture saved file=%s success=%lu entries=%lu\n",
           filePath.UTF8String,
           (unsigned long)successCount,
           (unsigned long)entries.count);
    return 0;
}

- (int)runT50FlashDiffWithArguments:(NSArray<NSString *> *)arguments {
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
        fprintf(stderr, "t50 flash-diff requires --before <path> and --after <path>.\n");
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
        fprintf(stderr, "Flash capture files are missing 'entries' arrays.\n");
        return 1;
    }

    NSMutableDictionary<NSNumber *, NSDictionary *> *beforeByAddress = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSDictionary *> *afterByAddress = [NSMutableDictionary dictionary];
    for (NSDictionary *entry in beforeEntries) {
        if ([entry isKindOfClass:[NSDictionary class]] && entry[@"addr"] != nil) {
            beforeByAddress[entry[@"addr"]] = entry;
        }
    }
    for (NSDictionary *entry in afterEntries) {
        if ([entry isKindOfClass:[NSDictionary class]] && entry[@"addr"] != nil) {
            afterByAddress[entry[@"addr"]] = entry;
        }
    }

    NSMutableSet<NSNumber *> *allAddresses = [NSMutableSet setWithArray:beforeByAddress.allKeys];
    [allAddresses addObjectsFromArray:afterByAddress.allKeys];
    NSArray<NSNumber *> *sortedAddresses = [allAddresses.allObjects
        sortedArrayUsingComparator:^NSComparisonResult(NSNumber *lhs, NSNumber *rhs) {
          if (lhs.unsignedIntegerValue < rhs.unsignedIntegerValue) {
              return NSOrderedAscending;
          }
          if (lhs.unsignedIntegerValue > rhs.unsignedIntegerValue) {
              return NSOrderedDescending;
          }
          return NSOrderedSame;
        }];

    printf("t50 flash-diff before=%s after=%s\n", beforePath.UTF8String, afterPath.UTF8String);

    NSUInteger changeCount = 0;
    for (NSNumber *addressNumber in sortedAddresses) {
        NSDictionary *beforeEntry = beforeByAddress[addressNumber];
        NSDictionary *afterEntry = afterByAddress[addressNumber];

        NSString *beforeHex = beforeEntry[@"data_hex"];
        NSString *afterHex = afterEntry[@"data_hex"];
        NSString *beforeError = beforeEntry[@"error"];
        NSString *afterError = afterEntry[@"error"];

        BOOL different = NO;
        if ((beforeHex == nil) != (afterHex == nil)) {
            different = YES;
        } else if (beforeHex != nil && ![beforeHex isEqualToString:afterHex]) {
            different = YES;
        }
        if ((beforeError == nil) != (afterError == nil)) {
            different = YES;
        } else if (beforeError != nil && ![beforeError isEqualToString:afterError]) {
            different = YES;
        }
        if (!different) {
            continue;
        }

        changeCount += 1;
        NSUInteger address = addressNumber.unsignedIntegerValue;
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
                printf("  addr=0x%04lx changed %s\n", (unsigned long)address, segmentString.UTF8String);
                continue;
            }
        }

        printf("  addr=0x%04lx changed (non-hex or error state)\n", (unsigned long)address);
    }

    if (changeCount == 0) {
        printf("  no flash address changes detected.\n");
    } else {
        printf("  changed_addresses=%lu\n", (unsigned long)changeCount);
    }

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

- (int)runT50DPISetWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--dpi", @"--nearest", @"--calibrate-down", @"--delay-ms", @"--opcode", @"--commit", @"--save", @"--strategy", @"--vid",
        @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *dpiString = options[@"--dpi"];
    if (dpiString == nil) {
        fprintf(stderr, "t50 dpi-set requires --dpi <n>.\n");
        return 1;
    }

    NSUInteger dpiValue = 0;
    NSUInteger nearestValue = 1;
    NSUInteger calibrateDownValue = 10;
    NSUInteger delayMilliseconds = 40;
    NSUInteger opcode = 0x0F;
    NSUInteger commitValue = 1;
    NSUInteger saveValue = 1;
    if (![self parseRequiredUnsigned:dpiString maxValue:20000 fieldName:@"--dpi" output:&dpiValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--nearest"] maxValue:1 fieldName:@"--nearest" output:&nearestValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--calibrate-down"] maxValue:1000 fieldName:@"--calibrate-down" output:&calibrateDownValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--delay-ms"] maxValue:5000 fieldName:@"--delay-ms" output:&delayMilliseconds errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--opcode"] maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--commit"] maxValue:1 fieldName:@"--commit" output:&commitValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (calibrateDownValue == 0) {
        fprintf(stderr, "t50 dpi-set --calibrate-down must be at least 1.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV3;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v3"
                               subcommand:@"t50 dpi-set"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    static const NSUInteger kDefaultDPILadder[] = {400, 800, 1200, 1600, 2000, 3200, 4000};
    const NSUInteger ladderCount = sizeof(kDefaultDPILadder) / sizeof(kDefaultDPILadder[0]);
    NSUInteger targetIndex = NSNotFound;
    BOOL exactMatch = NO;
    for (NSUInteger index = 0; index < ladderCount; ++index) {
        if (kDefaultDPILadder[index] == dpiValue) {
            targetIndex = index;
            exactMatch = YES;
            break;
        }
    }

    if (targetIndex == NSNotFound && nearestValue == 1) {
        NSUInteger bestDiff = NSUIntegerMax;
        for (NSUInteger index = 0; index < ladderCount; ++index) {
            NSUInteger ladderValue = kDefaultDPILadder[index];
            NSUInteger diff = (ladderValue > dpiValue) ? (ladderValue - dpiValue) : (dpiValue - ladderValue);
            if (diff < bestDiff) {
                bestDiff = diff;
                targetIndex = index;
            }
        }
    }

    if (targetIndex == NSNotFound) {
        fprintf(stderr, "Unsupported dpi value %lu. Use one of: 400, 800, 1200, 1600, 2000, 3200, 4000 (or pass --nearest 1).\n",
                (unsigned long)dpiValue);
        return 1;
    }

    for (NSUInteger index = 0; index < calibrateDownValue; ++index) {
        BOOL shouldCommit = (commitValue == 1 && targetIndex == 0 && (index + 1) == calibrateDownValue);
        NSError *stepError = nil;
        BOOL stepped = [self.t50ExchangeCommandUseCase stepDPICandidateAction:MLDT50DPIStepActionDown
                                                                        opcode:(uint8_t)opcode
                                                                        commit:shouldCommit
                                                                      onDevice:target
                                                                         error:&stepError];
        if (!stepped) {
            fprintf(stderr, "t50 dpi-set calibrate error at %lu/%lu: %s\n",
                    (unsigned long)(index + 1),
                    (unsigned long)calibrateDownValue,
                    stepError.localizedDescription.UTF8String);
            return 1;
        }

        if (delayMilliseconds > 0 && ((index + 1) < calibrateDownValue || targetIndex > 0)) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    for (NSUInteger index = 0; index < targetIndex; ++index) {
        BOOL shouldCommit = (commitValue == 1 && (index + 1) == targetIndex);
        NSError *stepError = nil;
        BOOL stepped = [self.t50ExchangeCommandUseCase stepDPICandidateAction:MLDT50DPIStepActionUp
                                                                        opcode:(uint8_t)opcode
                                                                        commit:shouldCommit
                                                                      onDevice:target
                                                                         error:&stepError];
        if (!stepped) {
            fprintf(stderr, "t50 dpi-set apply error at %lu/%lu: %s\n",
                    (unsigned long)(index + 1),
                    (unsigned long)targetIndex,
                    stepError.localizedDescription.UTF8String);
            return 1;
        }

        if (delayMilliseconds > 0 && (index + 1) < targetIndex) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 dpi-set save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 dpi-set ok requested=%lu target=%lu index=%lu exact=%lu calibrate-down=%lu delay-ms=%lu opcode=0x%02lx commit=%lu save=%lu strategy=%s\n",
           (unsigned long)dpiValue,
           (unsigned long)kDefaultDPILadder[targetIndex],
           (unsigned long)targetIndex,
           (unsigned long)(exactMatch ? 1 : 0),
           (unsigned long)calibrateDownValue,
           (unsigned long)delayMilliseconds,
           (unsigned long)opcode,
           (unsigned long)commitValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
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

- (int)runT50DPIStepWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--action", @"--count", @"--delay-ms", @"--opcode", @"--commit", @"--save", @"--strategy", @"--vid", @"--pid",
        @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *action = options[@"--action"];
    if (action == nil) {
        fprintf(stderr, "t50 dpi-step requires --action <up|down|cycle>.\n");
        return 1;
    }

    NSString *normalizedAction = action.lowercaseString;
    MLDT50DPIStepAction stepAction = MLDT50DPIStepActionDown;
    if ([normalizedAction isEqualToString:@"down"]) {
        stepAction = MLDT50DPIStepActionDown;
    } else if ([normalizedAction isEqualToString:@"up"]) {
        stepAction = MLDT50DPIStepActionUp;
    } else if ([normalizedAction isEqualToString:@"cycle"]) {
        stepAction = MLDT50DPIStepActionCycle;
    } else {
        fprintf(stderr, "t50 dpi-step --action must be one of: up, down, cycle.\n");
        return 1;
    }

    NSUInteger countValue = 1;
    NSUInteger delayMilliseconds = 0;
    NSUInteger opcode = 0x0F;
    NSUInteger commitValue = 1;
    NSUInteger saveValue = 0;
    if (![self parseOptionalUnsigned:options[@"--count"] maxValue:1000 fieldName:@"--count" output:&countValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--delay-ms"] maxValue:5000 fieldName:@"--delay-ms" output:&delayMilliseconds errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--opcode"] maxValue:255 fieldName:@"--opcode" output:&opcode errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--commit"] maxValue:1 fieldName:@"--commit" output:&commitValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (countValue == 0) {
        fprintf(stderr, "t50 dpi-step --count must be at least 1.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyCaptureV2;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"capture-v2"
                               subcommand:@"t50 dpi-step"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    for (NSUInteger index = 0; index < countValue; ++index) {
        BOOL shouldCommit = (commitValue == 1 && index == (countValue - 1));
        NSError *stepError = nil;
        BOOL stepped = [self.t50ExchangeCommandUseCase stepDPICandidateAction:stepAction
                                                                        opcode:(uint8_t)opcode
                                                                        commit:shouldCommit
                                                                      onDevice:target
                                                                         error:&stepError];
        if (!stepped) {
            fprintf(stderr, "t50 dpi-step action error at %lu/%lu: %s\n",
                    (unsigned long)(index + 1),
                    (unsigned long)countValue,
                    stepError.localizedDescription.UTF8String);
            return 1;
        }

        if (delayMilliseconds > 0 && index + 1 < countValue) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 dpi-step save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 dpi-step ok action=%s count=%lu delay-ms=%lu opcode=0x%02lx commit=%lu save=%lu strategy=%s\n",
           normalizedAction.UTF8String,
           (unsigned long)countValue,
           (unsigned long)delayMilliseconds,
           (unsigned long)opcode,
           (unsigned long)commitValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
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
        @"--r", @"--g", @"--b", @"--slots", @"--slot", @"--frames", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
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
    NSUInteger slots = MLDT50DirectColorSlotCount;
    NSUInteger slot = 0;
    NSUInteger frames = 1;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--slots"] maxValue:MLDT50DirectColorSlotCount fieldName:@"--slots" output:&slots errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--slot"] maxValue:MLDT50DirectColorSlotCount fieldName:@"--slot" output:&slot errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--frames"] maxValue:120 fieldName:@"--frames" output:&frames errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (slots == 0) {
        fprintf(stderr, "--slots must be at least 1.\n");
        return 1;
    }
    if (slot > 0 && slots != MLDT50DirectColorSlotCount) {
        fprintf(stderr, "--slot cannot be combined with --slots.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"quick"
                               subcommand:@"t50 color-direct"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
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

    NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + (3 * MLDT50DirectColorSlotCount)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = 0x06;
    payloadBytes[1] = 0x02;
    for (NSUInteger index = 0; index < MLDT50DirectColorSlotCount; ++index) {
        BOOL shouldSet = (slot > 0) ? ((index + 1) == slot) : (index < slots);
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 0] = shouldSet ? (uint8_t)red : 0x00;
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 1] = shouldSet ? (uint8_t)green : 0x00;
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 2] = shouldSet ? (uint8_t)blue : 0x00;
    }

    for (NSUInteger frameIndex = 0; frameIndex < frames; ++frameIndex) {
        NSError *writeError = nil;
        NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                      opcode:0x03
                                                                   writeFlag:0x00
                                                               payloadOffset:2
                                                                     payload:payload
                                                                       error:&writeError];
        if (response == nil) {
            fprintf(stderr,
                    "t50 color-direct write error at frame %lu/%lu: %s\n",
                    (unsigned long)(frameIndex + 1),
                    (unsigned long)frames,
                    writeError.localizedDescription.UTF8String);
            return 1;
        }
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
        printf("t50 color-direct ok r=%lu g=%lu b=%lu slot=%lu frames=%lu prepare=%lu save=%lu strategy=%s\n",
               (unsigned long)red,
               (unsigned long)green,
               (unsigned long)blue,
               (unsigned long)slot,
               (unsigned long)frames,
               (unsigned long)prepareValue,
               (unsigned long)saveValue,
               strategyOption.UTF8String);
        return 0;
    }

    printf("t50 color-direct ok r=%lu g=%lu b=%lu slots=%lu frames=%lu prepare=%lu save=%lu strategy=%s\n",
           (unsigned long)red,
           (unsigned long)green,
           (unsigned long)blue,
           (unsigned long)slots,
           (unsigned long)frames,
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
        @"--zone", @"--r", @"--g", @"--b", @"--frames", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
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
    NSUInteger frames = 1;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--frames"] maxValue:120 fieldName:@"--frames" output:&frames errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *normalizedZone = zoneString.lowercaseString;
    BOOL slotEnabled[MLDT50DirectColorSlotCount];
    memset(slotEnabled, 0, sizeof(slotEnabled));

    NSMutableArray<NSString *> *selectedSlots = [NSMutableArray array];
    if ([normalizedZone isEqualToString:@"logo"]) {
        slotEnabled[14] = YES;  // T50/W70 hypothesis: rear logo channel sits on slot 15.
        [selectedSlots addObject:@"15"];
    } else if ([normalizedZone isEqualToString:@"wheel"]) {
        slotEnabled[6] = YES; // T50 hypothesis: wheel is tied to slots 7/8 and indicator slot 21.
        slotEnabled[7] = YES;
        slotEnabled[20] = YES;
        [selectedSlots addObject:@"7"];
        [selectedSlots addObject:@"8"];
        [selectedSlots addObject:@"21"];
    } else if ([normalizedZone isEqualToString:@"wheel-indicator"]) {
        slotEnabled[20] = YES;
        [selectedSlots addObject:@"21"];
    } else if ([normalizedZone isEqualToString:@"rear"]) {
        const NSUInteger rearSlots[] = {1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20};
        const NSUInteger rearSlotCount = sizeof(rearSlots) / sizeof(rearSlots[0]);
        for (NSUInteger index = 0; index < rearSlotCount; ++index) {
            NSUInteger slot = rearSlots[index];
            slotEnabled[slot - 1] = YES;
            [selectedSlots addObject:[NSString stringWithFormat:@"%lu", (unsigned long)slot]];
        }
    } else if ([normalizedZone isEqualToString:@"all"]) {
        for (NSUInteger slot = 1; slot <= MLDT50DirectColorSlotCount; ++slot) {
            slotEnabled[slot - 1] = YES;
            [selectedSlots addObject:[NSString stringWithFormat:@"%lu", (unsigned long)slot]];
        }
    } else {
        fprintf(stderr, "t50 color-zone --zone must be one of: logo, wheel, wheel-indicator, rear, all.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"quick"
                               subcommand:@"t50 color-zone"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
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

    NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + (3 * MLDT50DirectColorSlotCount)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = 0x06;
    payloadBytes[1] = 0x02;
    for (NSUInteger index = 0; index < MLDT50DirectColorSlotCount; ++index) {
        BOOL shouldSet = slotEnabled[index];
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 0] = shouldSet ? (uint8_t)red : 0x00;
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 1] = shouldSet ? (uint8_t)green : 0x00;
        payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 2] = shouldSet ? (uint8_t)blue : 0x00;
    }

    for (NSUInteger frameIndex = 0; frameIndex < frames; ++frameIndex) {
        NSError *writeError = nil;
        NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                      opcode:0x03
                                                                   writeFlag:0x00
                                                               payloadOffset:2
                                                                     payload:payload
                                                                       error:&writeError];
        if (response == nil) {
            fprintf(stderr,
                    "t50 color-zone write error at frame %lu/%lu: %s\n",
                    (unsigned long)(frameIndex + 1),
                    (unsigned long)frames,
                    writeError.localizedDescription.UTF8String);
            return 1;
        }
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
    printf("t50 color-zone ok zone=%s slots=%s r=%lu g=%lu b=%lu frames=%lu prepare=%lu save=%lu strategy=%s\n",
           normalizedZone.UTF8String,
           slotSummary.UTF8String,
           (unsigned long)red,
           (unsigned long)green,
           (unsigned long)blue,
           (unsigned long)frames,
           (unsigned long)prepareValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (int)runT50ColorSweepWithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--r", @"--g", @"--b", @"--from", @"--to", @"--delay-ms", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *rString = options[@"--r"];
    NSString *gString = options[@"--g"];
    NSString *bString = options[@"--b"];
    if (rString == nil || gString == nil || bString == nil) {
        fprintf(stderr, "t50 color-sweep requires --r, --g, and --b.\n");
        return 1;
    }

    NSUInteger red = 0;
    NSUInteger green = 0;
    NSUInteger blue = 0;
    NSUInteger fromSlot = 1;
    NSUInteger toSlot = MLDT50DirectColorSlotCount;
    NSUInteger delayMilliseconds = 350;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 0;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&red errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&green errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--from"] maxValue:MLDT50DirectColorSlotCount fieldName:@"--from" output:&fromSlot errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:MLDT50DirectColorSlotCount fieldName:@"--to" output:&toSlot errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--delay-ms"] maxValue:5000 fieldName:@"--delay-ms" output:&delayMilliseconds errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }
    if (fromSlot == 0 || toSlot == 0 || fromSlot > toSlot) {
        fprintf(stderr, "t50 color-sweep requires 1 <= --from <= --to <= %lu.\n", (unsigned long)MLDT50DirectColorSlotCount);
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"quick"
                               subcommand:@"t50 color-sweep"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
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
            fprintf(stderr, "t50 color-sweep prepare error: %s\n", prepareError.localizedDescription.UTF8String);
            return 1;
        }
    }

    for (NSUInteger slot = fromSlot; slot <= toSlot; ++slot) {
        NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + (3 * MLDT50DirectColorSlotCount)];
        uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
        payloadBytes[0] = 0x06;
        payloadBytes[1] = 0x02;
        for (NSUInteger index = 0; index < MLDT50DirectColorSlotCount; ++index) {
            BOOL shouldSet = (index + 1) == slot;
            payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 0] = shouldSet ? (uint8_t)red : 0x00;
            payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 1] = shouldSet ? (uint8_t)green : 0x00;
            payloadBytes[MLDT50DirectColorStartOffset + (3 * index) + 2] = shouldSet ? (uint8_t)blue : 0x00;
        }

        NSError *writeError = nil;
        NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:target
                                                                      opcode:0x03
                                                                   writeFlag:0x00
                                                               payloadOffset:2
                                                                     payload:payload
                                                                       error:&writeError];
        if (response == nil) {
            fprintf(stderr, "t50 color-sweep write error on slot %lu: %s\n",
                    (unsigned long)slot,
                    writeError.localizedDescription.UTF8String);
            return 1;
        }

        printf("t50 color-sweep slot=%lu/%lu\n", (unsigned long)slot, (unsigned long)toSlot);
        if (delayMilliseconds > 0 && slot < toSlot) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 color-sweep save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 color-sweep done range=%lu..%lu r=%lu g=%lu b=%lu delay-ms=%lu prepare=%lu save=%lu strategy=%s\n",
           (unsigned long)fromSlot,
           (unsigned long)toSlot,
           (unsigned long)red,
           (unsigned long)green,
           (unsigned long)blue,
           (unsigned long)delayMilliseconds,
           (unsigned long)prepareValue,
           (unsigned long)saveValue,
           strategyOption.UTF8String);
    return 0;
}

- (BOOL)sendT50SimulatorChunkWithSubcommand:(uint8_t)subcommand
                                      chunk:(const uint8_t *)chunk
                                   onDevice:(MLDMouseDevice *)device
                                      error:(NSError **)error {
    NSMutableData *payload = [NSMutableData dataWithLength:2 + 4 + MLDT50SimulatorChunkSplitOffset];
    uint8_t *bytes = (uint8_t *)payload.mutableBytes;
    bytes[0] = 0x06;
    bytes[1] = subcommand;
    bytes[2] = 0x00;
    bytes[3] = 0x00;
    bytes[4] = chunk[MLDT50SimulatorChunkSplitOffset];
    bytes[5] = chunk[MLDT50SimulatorChunkSplitOffset + 1];
    memcpy(bytes + 6, chunk, MLDT50SimulatorChunkSplitOffset);

    NSData *response = [self.t50ExchangeCommandUseCase executeForDevice:device
                                                                  opcode:0x03
                                                               writeFlag:0x00
                                                           payloadOffset:2
                                                                 payload:payload
                                                                   error:error];
    return response != nil;
}

- (BOOL)sendT50Simulator116Red:(const uint8_t *)red
                         green:(const uint8_t *)green
                          blue:(const uint8_t *)blue
                      onDevice:(MLDMouseDevice *)device
                         error:(NSError **)error {
    uint8_t redChunk1[MLDT50SimulatorChunkSize];
    uint8_t redChunk2[MLDT50SimulatorChunkSize];
    uint8_t greenChunk1[MLDT50SimulatorChunkSize];
    uint8_t greenChunk2[MLDT50SimulatorChunkSize];
    uint8_t blueChunk1[MLDT50SimulatorChunkSize];
    uint8_t blueChunk2[MLDT50SimulatorChunkSize];

    memcpy(redChunk1, red, MLDT50SimulatorChunkSize);
    memcpy(redChunk2, red + MLDT50SimulatorChunkSize, MLDT50SimulatorChunkSize);
    memcpy(greenChunk1, green, MLDT50SimulatorChunkSize);
    memcpy(greenChunk2, green + MLDT50SimulatorChunkSize, MLDT50SimulatorChunkSize);
    memcpy(blueChunk1, blue, MLDT50SimulatorChunkSize);
    memcpy(blueChunk2, blue + MLDT50SimulatorChunkSize, MLDT50SimulatorChunkSize);

    if (![self sendT50SimulatorChunkWithSubcommand:0x07 chunk:redChunk1 onDevice:device error:error]) {
        return NO;
    }
    if (![self sendT50SimulatorChunkWithSubcommand:0x08 chunk:redChunk2 onDevice:device error:error]) {
        return NO;
    }
    if (![self sendT50SimulatorChunkWithSubcommand:0x09 chunk:greenChunk1 onDevice:device error:error]) {
        return NO;
    }
    if (![self sendT50SimulatorChunkWithSubcommand:0x0A chunk:greenChunk2 onDevice:device error:error]) {
        return NO;
    }
    if (![self sendT50SimulatorChunkWithSubcommand:0x0B chunk:blueChunk1 onDevice:device error:error]) {
        return NO;
    }
    return [self sendT50SimulatorChunkWithSubcommand:0x0C chunk:blueChunk2 onDevice:device error:error];
}

- (int)runT50ColorSimulator116WithArguments:(NSArray<NSString *> *)arguments {
    NSString *parseError = nil;
    NSDictionary<NSString *, NSString *> *options = [self parseOptionMapFromArguments:arguments errorMessage:&parseError];
    if (options == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSSet<NSString *> *allowed = [NSSet setWithArray:@[
        @"--r", @"--g", @"--b", @"--index", @"--from", @"--to", @"--delay-ms", @"--prepare", @"--save", @"--strategy", @"--vid", @"--pid", @"--serial", @"--model"
    ]];
    if (![self validateAllowedOptions:allowed options:options errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    NSString *rString = options[@"--r"];
    NSString *gString = options[@"--g"];
    NSString *bString = options[@"--b"];
    if (rString == nil || gString == nil || bString == nil) {
        fprintf(stderr, "t50 color-sim116 requires --r, --g, and --b.\n");
        return 1;
    }

    NSUInteger redValue = 0;
    NSUInteger greenValue = 0;
    NSUInteger blueValue = 0;
    NSUInteger indexValue = 0;
    NSUInteger fromIndex = 0;
    NSUInteger toIndex = MLDT50SimulatorColorIndexCount - 1;
    NSUInteger delayMilliseconds = 250;
    NSUInteger prepareValue = 0;
    NSUInteger saveValue = 0;
    BOOL hasIndex = options[@"--index"] != nil;
    if (![self parseRequiredUnsigned:rString maxValue:255 fieldName:@"--r" output:&redValue errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:gString maxValue:255 fieldName:@"--g" output:&greenValue errorMessage:&parseError] ||
        ![self parseRequiredUnsigned:bString maxValue:255 fieldName:@"--b" output:&blueValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--index"] maxValue:(MLDT50SimulatorColorIndexCount - 1) fieldName:@"--index" output:&indexValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--from"] maxValue:(MLDT50SimulatorColorIndexCount - 1) fieldName:@"--from" output:&fromIndex errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--to"] maxValue:(MLDT50SimulatorColorIndexCount - 1) fieldName:@"--to" output:&toIndex errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--delay-ms"] maxValue:5000 fieldName:@"--delay-ms" output:&delayMilliseconds errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--prepare"] maxValue:1 fieldName:@"--prepare" output:&prepareValue errorMessage:&parseError] ||
        ![self parseOptionalUnsigned:options[@"--save"] maxValue:1 fieldName:@"--save" output:&saveValue errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (hasIndex) {
        fromIndex = indexValue;
        toIndex = indexValue;
    }
    if (fromIndex > toIndex) {
        fprintf(stderr, "t50 color-sim116 requires --from <= --to.\n");
        return 1;
    }

    NSString *strategyOption = nil;
    MLDT50SaveStrategy strategy = MLDT50SaveStrategyQuick;
    if (![self parseT50SaveStrategyOption:options[@"--strategy"]
                             defaultValue:@"quick"
                               subcommand:@"t50 color-sim116"
                                 strategy:&strategy
                            strategyLabel:&strategyOption
                             errorMessage:&parseError]) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    MLDMouseDevice *target = [self selectT50DeviceWithOptions:options errorMessage:&parseError];
    if (target == nil) {
        fprintf(stderr, "%s\n", parseError.UTF8String);
        return 1;
    }

    if (prepareValue == 1) {
        NSError *prepareError = nil;
        if (![self prepareT50ColorWriteSessionOnDevice:target error:&prepareError]) {
            fprintf(stderr, "t50 color-sim116 prepare error: %s\n", prepareError.localizedDescription.UTF8String);
            return 1;
        }
    }

    const uint8_t redByte = (uint8_t)redValue;
    const uint8_t greenByte = (uint8_t)greenValue;
    const uint8_t blueByte = (uint8_t)blueValue;
    for (NSUInteger index = fromIndex; index <= toIndex; ++index) {
        uint8_t red[MLDT50SimulatorColorIndexCount] = {0};
        uint8_t green[MLDT50SimulatorColorIndexCount] = {0};
        uint8_t blue[MLDT50SimulatorColorIndexCount] = {0};
        red[index] = redByte;
        green[index] = greenByte;
        blue[index] = blueByte;

        NSError *writeError = nil;
        if (![self sendT50Simulator116Red:red green:green blue:blue onDevice:target error:&writeError]) {
            fprintf(stderr, "t50 color-sim116 write error at index %lu: %s\n",
                    (unsigned long)index,
                    writeError.localizedDescription.UTF8String);
            return 1;
        }

        printf("t50 color-sim116 index=%lu/%lu\n", (unsigned long)index, (unsigned long)toIndex);
        if (delayMilliseconds > 0 && index < toIndex) {
            [NSThread sleepForTimeInterval:((NSTimeInterval)delayMilliseconds / 1000.0)];
        }
    }

    if (saveValue == 1) {
        NSError *saveError = nil;
        BOOL saved = [self.t50ExchangeCommandUseCase saveSettingsToDevice:target strategy:strategy error:&saveError];
        if (!saved) {
            fprintf(stderr, "t50 color-sim116 save error: %s\n", saveError.localizedDescription.UTF8String);
            return 1;
        }
    }

    printf("t50 color-sim116 done range=%lu..%lu r=%lu g=%lu b=%lu delay-ms=%lu prepare=%lu save=%lu strategy=%s\n",
           (unsigned long)fromIndex,
           (unsigned long)toIndex,
           (unsigned long)redValue,
           (unsigned long)greenValue,
           (unsigned long)blueValue,
           (unsigned long)delayMilliseconds,
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

- (BOOL)parseT50SaveStrategyOption:(nullable NSString *)optionValue
                      defaultValue:(NSString *)defaultValue
                        subcommand:(NSString *)subcommand
                          strategy:(MLDT50SaveStrategy *)strategy
                     strategyLabel:(NSString **)strategyLabel
                      errorMessage:(NSString **)errorMessage {
    NSString *value = optionValue ?: defaultValue;
    if (strategyLabel != nil) {
        *strategyLabel = value;
    }

    if ([value isEqualToString:@"quick"]) {
        *strategy = MLDT50SaveStrategyQuick;
        return YES;
    }
    if ([value isEqualToString:@"capture-v1"]) {
        *strategy = MLDT50SaveStrategyCaptureV1;
        return YES;
    }
    if ([value isEqualToString:@"capture-v2"]) {
        *strategy = MLDT50SaveStrategyCaptureV2;
        return YES;
    }
    if ([value isEqualToString:@"capture-v3"]) {
        *strategy = MLDT50SaveStrategyCaptureV3;
        return YES;
    }
    if ([value isEqualToString:@"capture-v4"]) {
        *strategy = MLDT50SaveStrategyCaptureV4;
        return YES;
    }
    if ([value isEqualToString:@"major-sync"]) {
        *strategy = MLDT50SaveStrategyMajorSync;
        return YES;
    }

    if (errorMessage != nil) {
        *errorMessage =
            [NSString stringWithFormat:@"%@ --strategy must be one of: quick, capture-v1, capture-v2, capture-v3, capture-v4, major-sync.", subcommand];
    }
    return NO;
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
