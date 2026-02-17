#import "application/use_cases/MLDT50ExchangeVendorCommandUseCase.h"

#import "domain/entities/MLDMouseDevice.h"
#include <string.h>

NSErrorDomain const MLDT50ControlErrorDomain = @"com.mloody.application.t50-control";

static const uint8_t MLDT50Magic = 0x07;
static const uint8_t MLDT50ReportID = 0x07;
static const NSUInteger MLDT50PacketLength = 72;
static const uint8_t MLDT50BacklightOpcode = 0x11;
static const uint8_t MLDT50WriteFlag = 0x80;
static const uint8_t MLDT50ReadFlag = 0x00;
static const NSUInteger MLDT50BacklightPayloadOffset = 8;
static const uint8_t MLDT50CoreSetOpcodeCandidate = 0x0C;
static const uint8_t MLDT50CoreReadOpcodeCandidate = 0x1F;
static const NSUInteger MLDT50CorePayloadOffset = 8;
static const uint8_t MLDT50CoreCommandPrefix0 = 0x06;
static const uint8_t MLDT50CoreCommandPrefix1 = 0x80;
static const uint8_t MLDT50CoreSlotMin = 1;
static const uint8_t MLDT50CoreSlotMax = 4;
static const NSUInteger MLDT50CoreReadWordOffset = MLDT50CorePayloadOffset + 2;
static const uint8_t MLDT50SLEDProfileOpcodeCandidate = 0x15;
static const uint8_t MLDT50SLEDEnableOpcodeCandidate = 0x16;
static const NSUInteger MLDT50SLEDPayloadOffset = 8;
static const uint8_t MLDT50DPIStepCommitOpcodeCandidate = 0x0A;
static const NSUInteger MLDT50DPIStepPayloadOffset = 8;
static const uint8_t MLDT50FlashOpcodeCandidate = 0x2F;
static const NSUInteger MLDT50FlashBridgeOffset = 2;
static const NSUInteger MLDT50FlashRead8ResponseOffset = 8;
static const NSUInteger MLDT50FlashRead32CountOffset = 24;
static const NSUInteger MLDT50FlashRead32AddressOffset = 28;
static const NSUInteger MLDT50FlashRead32ResponseOffset = 32;
static const uint8_t MLDT50FlashRead32Mode = 0x00;
static const uint8_t MLDT50FlashWrite32Mode = 0x01;

typedef struct {
    uint8_t opcode;
    uint8_t writeFlag;
    NSUInteger payloadOffset;
    uint8_t payload[8];
    NSUInteger payloadLength;
} MLDT50SaveStep;

static const MLDT50SaveStep MLDT50QuickSaveSequence[] = {
    {0x03, 0x00, 2, {0x03, 0x0B, 0x01}, 3},
    {0x03, 0x00, 2, {0x03, 0x0B, 0x00}, 3},
};

static const MLDT50SaveStep MLDT50CaptureV1SaveSequence[] = {
    {0x03, 0x00, 2, {0x06, 0x05}, 2},
    {0x03, 0x00, 2, {0x06, 0x06}, 2},
    {0x03, 0x00, 2, {0x06, 0x02}, 2},
    {0x03, 0x00, 2, {0x03, 0x0B, 0x01}, 3},
    {0x03, 0x00, 2, {0x03, 0x0B, 0x00}, 3},
};

// Capture-v2 mirrors the "press OK/save" transaction observed in Windows traces.
static const MLDT50SaveStep MLDT50CaptureV2SaveSequence[] = {
    {0x03, 0x00, 2, {0x03, 0x0B, 0x00}, 3},
    {0x14, 0x00, 8, {0x40}, 1},
    {0x05, 0x00, 8, {0x00}, 0},
    {0x2F, 0x00, 24, {0x02, 0x00, 0x00, 0x00, 0x00, 0xE2}, 6},
    {0x0E, 0x00, 8, {0x00}, 0},
    {0x0F, 0x00, 8, {0x07}, 1},
    {0x0C, 0x00, 8, {0x06, 0x80, 0x01}, 3},
    {0x0A, 0x00, 8, {0x00}, 0},
};

// Capture-v3 mirrors the full brightness "OK/save" transaction observed in
// Windows traces, then replays the same finalize tail plus 06 05/06.
static const MLDT50SaveStep MLDT50CaptureV3WarmupSequence[] = {
    {0x03, 0x00, 2, {0x06, 0x05}, 2},
    {0x03, 0x00, 2, {0x06, 0x06}, 2},
    {0x03, 0x00, 2, {0x06, 0x02}, 2},
    {0x03, 0x00, 2, {0x03, 0x0B, 0x01}, 3},
};

static const MLDT50SaveStep MLDT50CaptureV3BrightnessRampSequence[] = {
    {0x11, 0x80, 8, {0x00}, 1},
    {0x0A, 0x00, 8, {0x00}, 0},
    {0x11, 0x80, 8, {0x01}, 1},
    {0x0A, 0x00, 8, {0x00}, 0},
    {0x11, 0x80, 8, {0x02}, 1},
    {0x0A, 0x00, 8, {0x00}, 0},
    {0x11, 0x80, 8, {0x03}, 1},
    {0x0A, 0x00, 8, {0x00}, 0},
};

static const MLDT50SaveStep MLDT50CaptureV3FinalizeSequence[] = {
    {0x03, 0x00, 2, {0x03, 0x0B, 0x00}, 3},
    {0x14, 0x00, 8, {0x40}, 1},
    {0x05, 0x00, 8, {0x00}, 0},
    {0x2F, 0x00, 24, {0x02, 0x00, 0x00, 0x00, 0x00, 0xE2}, 6},
    {0x0E, 0x00, 8, {0x00}, 0},
    {0x0F, 0x00, 8, {0x07}, 1},
    {0x0C, 0x00, 8, {0x06, 0x80, 0x01}, 3},
    {0x0A, 0x00, 8, {0x00}, 0},
    {0x03, 0x00, 2, {0x06, 0x05}, 2},
    {0x03, 0x00, 2, {0x06, 0x06}, 2},
};

// Capture-v4 appends a Hid_major-style sync tail seen in static Bloody7 calls.
// These are still reverse-engineering candidates and should be validated in
// hardware persistence checks.
static const MLDT50SaveStep MLDT50MajorSyncSequence[] = {
    {0x07, 0x00, 8, {0x00}, 0},
    {0x08, 0x00, 8, {0x00}, 0},
    {0x06, 0x00, 8, {0x00}, 0},
    {0x1E, 0x00, 2, {0x01}, 1},
    {0x0A, 0x00, 8, {0x00}, 0},
};

@interface MLDT50ExchangeVendorCommandUseCase ()

@property(nonatomic, strong) id<MLDFeatureTransportPort> featureTransportPort;

@end

@implementation MLDT50ExchangeVendorCommandUseCase

- (instancetype)initWithFeatureTransportPort:(id<MLDFeatureTransportPort>)featureTransportPort {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _featureTransportPort = featureTransportPort;
    return self;
}

+ (NSUInteger)packetLength {
    return MLDT50PacketLength;
}

+ (uint8_t)reportID {
    return MLDT50ReportID;
}

+ (NSUInteger)saveStepCountForStrategy:(MLDT50SaveStrategy)strategy {
    switch (strategy) {
        case MLDT50SaveStrategyQuick:
            return sizeof(MLDT50QuickSaveSequence) / sizeof(MLDT50QuickSaveSequence[0]);
        case MLDT50SaveStrategyCaptureV1:
            return sizeof(MLDT50CaptureV1SaveSequence) / sizeof(MLDT50CaptureV1SaveSequence[0]);
        case MLDT50SaveStrategyCaptureV2:
            return sizeof(MLDT50CaptureV2SaveSequence) / sizeof(MLDT50CaptureV2SaveSequence[0]);
        case MLDT50SaveStrategyCaptureV3:
            return sizeof(MLDT50CaptureV3WarmupSequence) / sizeof(MLDT50CaptureV3WarmupSequence[0]) +
                   sizeof(MLDT50CaptureV3BrightnessRampSequence) / sizeof(MLDT50CaptureV3BrightnessRampSequence[0]) +
                   sizeof(MLDT50CaptureV3FinalizeSequence) / sizeof(MLDT50CaptureV3FinalizeSequence[0]);
        case MLDT50SaveStrategyCaptureV4:
            return [self saveStepCountForStrategy:MLDT50SaveStrategyCaptureV3] +
                   sizeof(MLDT50MajorSyncSequence) / sizeof(MLDT50MajorSyncSequence[0]);
        case MLDT50SaveStrategyMajorSync:
            return sizeof(MLDT50MajorSyncSequence) / sizeof(MLDT50MajorSyncSequence[0]);
    }

    return 0;
}

- (nullable NSData *)executeForDevice:(MLDMouseDevice *)device
                               opcode:(uint8_t)opcode
                            writeFlag:(uint8_t)writeFlag
                        payloadOffset:(NSUInteger)payloadOffset
                              payload:(NSData *)payload
                                error:(NSError **)error {
    if (payloadOffset >= MLDT50PacketLength) {
        if (error != nil) {
            NSString *message = [NSString stringWithFormat:@"Payload offset %lu must be < %lu.",
                                                         (unsigned long)payloadOffset,
                                                         (unsigned long)MLDT50PacketLength];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidPayloadOffset
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }

    if (payload.length > (MLDT50PacketLength - payloadOffset)) {
        if (error != nil) {
            NSString *message = [NSString stringWithFormat:@"Payload length %lu exceeds packet capacity from offset %lu.",
                                                         (unsigned long)payload.length,
                                                         (unsigned long)payloadOffset];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodePayloadTooLarge
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }

    NSMutableData *packet = [NSMutableData dataWithLength:MLDT50PacketLength];
    uint8_t *bytes = (uint8_t *)packet.mutableBytes;
    bytes[0] = MLDT50Magic;
    bytes[1] = opcode;
    bytes[4] = writeFlag;

    if (payload.length > 0) {
        memcpy(bytes + payloadOffset, payload.bytes, payload.length);
    }

    BOOL writeOK = [self.featureTransportPort writeFeatureReportWithID:MLDT50ReportID
                                                               payload:packet
                                                              toDevice:device
                                                                 error:error];
    if (!writeOK) {
        return nil;
    }

    NSData *response = [self.featureTransportPort readFeatureReportWithID:MLDT50ReportID
                                                                    length:MLDT50PacketLength
                                                                fromDevice:device
                                                                     error:error];
    if (response == nil) {
        if (error != nil && *error == nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeTransportReadFailed
                                     userInfo:@{NSLocalizedDescriptionKey : @"No response from T50 command read."}];
        }
        return nil;
    }

    if (response.length < MLDT50PacketLength) {
        if (error != nil) {
            NSString *message = [NSString stringWithFormat:@"Response too short: %lu bytes (expected %lu).",
                                                         (unsigned long)response.length,
                                                         (unsigned long)MLDT50PacketLength];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeResponseTooShort
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }

    return response;
}

- (BOOL)setBacklightLevel:(uint8_t)level
                 onDevice:(MLDMouseDevice *)device
                    error:(NSError **)error {
    if (level > 3) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidBacklightLevel
                                     userInfo:@{NSLocalizedDescriptionKey : @"Backlight level must be between 0 and 3."}];
        }
        return NO;
    }

    NSData *payload = [NSData dataWithBytes:&level length:1];
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50BacklightOpcode
                                    writeFlag:MLDT50WriteFlag
                                payloadOffset:MLDT50BacklightPayloadOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (nullable NSNumber *)readBacklightLevelForDevice:(MLDMouseDevice *)device
                                             error:(NSError **)error {
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50BacklightOpcode
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50BacklightPayloadOffset
                                      payload:[NSData data]
                                        error:error];
    if (response == nil || response.length <= MLDT50BacklightPayloadOffset) {
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)response.bytes;
    return @(bytes[MLDT50BacklightPayloadOffset]);
}

- (BOOL)setCoreSlotCandidate:(uint8_t)slot
                    onDevice:(MLDMouseDevice *)device
                       error:(NSError **)error {
    if (slot < MLDT50CoreSlotMin || slot > MLDT50CoreSlotMax) {
        if (error != nil) {
            NSString *message =
                [NSString stringWithFormat:@"Core slot must be between %u and %u.",
                                           MLDT50CoreSlotMin,
                                           MLDT50CoreSlotMax];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidCoreSlot
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return NO;
    }

    uint8_t payloadBytes[3] = {MLDT50CoreCommandPrefix0, MLDT50CoreCommandPrefix1, slot};
    NSData *payload = [NSData dataWithBytes:payloadBytes length:sizeof(payloadBytes)];
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50CoreSetOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50CorePayloadOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (nullable NSNumber *)readCoreSlotCandidateForDevice:(MLDMouseDevice *)device
                                                 error:(NSError **)error {
    NSDictionary<NSString *, NSNumber *> *state = [self readCoreStateCandidateForDevice:device error:error];
    if (state == nil) {
        return nil;
    }

    return state[@"slot"];
}

- (nullable NSDictionary<NSString *, NSNumber *> *)readCoreStateCandidateForDevice:(MLDMouseDevice *)device
                                                                              error:(NSError **)error {
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50CoreReadOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50CorePayloadOffset
                                      payload:[NSData data]
                                        error:error];
    if (response == nil || response.length <= (MLDT50CoreReadWordOffset + 1)) {
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)response.bytes;
    const uint16_t rawWord = (uint16_t)bytes[MLDT50CoreReadWordOffset] |
                             ((uint16_t)bytes[MLDT50CoreReadWordOffset + 1] << 8);
    const uint8_t lowBits = (uint8_t)(rawWord & 0x03);
    const uint8_t slot = (uint8_t)(lowBits + MLDT50CoreSlotMin);
    return @{
        @"opcode" : @(MLDT50CoreReadOpcodeCandidate),
        @"rawWord" : @(rawWord),
        @"lowBits" : @(lowBits),
        @"slot" : @(slot),
    };
}

- (BOOL)setSLEDProfileIndexCandidate:(uint8_t)index
                             onDevice:(MLDMouseDevice *)device
                                error:(NSError **)error {
    NSData *payload = [NSData dataWithBytes:&index length:1];
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50SLEDProfileOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50SLEDPayloadOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (nullable NSNumber *)readSLEDProfileIndexCandidateForDevice:(MLDMouseDevice *)device
                                                         error:(NSError **)error {
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50SLEDProfileOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50SLEDPayloadOffset
                                      payload:[NSData data]
                                        error:error];
    if (response == nil || response.length <= MLDT50SLEDPayloadOffset) {
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)response.bytes;
    return @(bytes[MLDT50SLEDPayloadOffset]);
}

- (BOOL)setSLEDEnabledCandidate:(BOOL)enabled
                        onDevice:(MLDMouseDevice *)device
                           error:(NSError **)error {
    const uint8_t value = enabled ? 1 : 0;
    NSData *payload = [NSData dataWithBytes:&value length:1];
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50SLEDEnableOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50SLEDPayloadOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (nullable NSNumber *)readSLEDEnabledCandidateForDevice:(MLDMouseDevice *)device
                                                    error:(NSError **)error {
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50SLEDEnableOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50SLEDPayloadOffset
                                      payload:[NSData data]
                                        error:error];
    if (response == nil || response.length <= MLDT50SLEDPayloadOffset) {
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)response.bytes;
    return @((bytes[MLDT50SLEDPayloadOffset] == 0) ? 0 : 1);
}

- (BOOL)stepDPICandidateAction:(MLDT50DPIStepAction)action
                        opcode:(uint8_t)opcode
                        commit:(BOOL)commit
                      onDevice:(MLDMouseDevice *)device
                         error:(NSError **)error {
    uint8_t actionByte = 0;
    switch (action) {
        case MLDT50DPIStepActionDown:
            actionByte = 0x00;
            break;
        case MLDT50DPIStepActionUp:
            actionByte = 0x01;
            break;
        case MLDT50DPIStepActionCycle:
            actionByte = 0x02;
            break;
        default:
            if (error != nil) {
                *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                             code:MLDT50ControlErrorCodeInvalidDPIStepAction
                                         userInfo:@{NSLocalizedDescriptionKey : @"DPI action must be down, up, or cycle."}];
            }
            return NO;
    }

    NSData *stepPayload = [NSData dataWithBytes:&actionByte length:1];
    NSData *stepResponse = [self executeForDevice:device
                                           opcode:opcode
                                        writeFlag:MLDT50ReadFlag
                                    payloadOffset:MLDT50DPIStepPayloadOffset
                                          payload:stepPayload
                                            error:error];
    if (stepResponse == nil) {
        return NO;
    }

    if (!commit) {
        return YES;
    }

    NSData *commitResponse = [self executeForDevice:device
                                             opcode:MLDT50DPIStepCommitOpcodeCandidate
                                          writeFlag:MLDT50ReadFlag
                                      payloadOffset:MLDT50DPIStepPayloadOffset
                                            payload:[NSData data]
                                              error:error];
    return commitResponse != nil;
}

- (nullable NSData *)readFlashBytes8FromAddress:(uint16_t)address
                                       onDevice:(MLDMouseDevice *)device
                                          error:(NSError **)error {
    uint8_t payloadBytes[6] = {
        0x00,
        (uint8_t)((address >> 8) & 0xFF),
        (uint8_t)(address & 0xFF),
        0x00,
        0x00,
        0x00,
    };
    NSData *payload = [NSData dataWithBytes:payloadBytes length:sizeof(payloadBytes)];
    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50FlashOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50FlashBridgeOffset
                                      payload:payload
                                        error:error];
    if (response == nil) {
        return nil;
    }

    if (response.length < (MLDT50FlashRead8ResponseOffset + 8)) {
        if (error != nil) {
            NSString *message = [NSString stringWithFormat:@"Flash read8 response too short: %lu bytes.",
                                                         (unsigned long)response.length];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeResponseTooShort
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }

    return [response subdataWithRange:NSMakeRange(MLDT50FlashRead8ResponseOffset, 8)];
}

- (nullable NSData *)readFlashDWordsFromAddress:(uint32_t)address
                                          count:(uint8_t)count
                                       onDevice:(MLDMouseDevice *)device
                                          error:(NSError **)error {
    if (count == 0 || count > 2) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidFlashCount
                                     userInfo:@{NSLocalizedDescriptionKey : @"Flash dword read count must be between 1 and 2."}];
        }
        return nil;
    }

    NSMutableData *payload = [NSMutableData dataWithLength:30];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = MLDT50FlashRead32Mode;

    uint32_t count32 = (uint32_t)count;
    memcpy(payloadBytes + (MLDT50FlashRead32CountOffset - MLDT50FlashBridgeOffset), &count32, sizeof(count32));
    memcpy(payloadBytes + (MLDT50FlashRead32AddressOffset - MLDT50FlashBridgeOffset), &address, sizeof(address));

    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50FlashOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50FlashBridgeOffset
                                      payload:payload
                                        error:error];
    if (response == nil) {
        return nil;
    }

    NSUInteger byteCount = (NSUInteger)count * 4;
    if (response.length < (MLDT50FlashRead32ResponseOffset + byteCount)) {
        if (error != nil) {
            NSString *message = [NSString stringWithFormat:@"Flash read32 response too short: %lu bytes.",
                                                         (unsigned long)response.length];
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeResponseTooShort
                                     userInfo:@{NSLocalizedDescriptionKey : message}];
        }
        return nil;
    }

    return [response subdataWithRange:NSMakeRange(MLDT50FlashRead32ResponseOffset, byteCount)];
}

- (BOOL)writeFlashWordsToAddress:(uint16_t)address
                        wordData:(NSData *)wordData
                      verifyMode:(BOOL)verifyMode
                        onDevice:(MLDMouseDevice *)device
                           error:(NSError **)error {
    if (wordData.length == 0 || (wordData.length % 2) != 0) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidFlashPayloadLength
                                     userInfo:@{NSLocalizedDescriptionKey : @"Flash word write payload must contain 2-byte word(s)."}];
        }
        return NO;
    }

    NSUInteger wordCount = wordData.length / 2;
    if (wordCount == 0 || wordCount > 32) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidFlashCount
                                     userInfo:@{NSLocalizedDescriptionKey : @"Flash word write count must be between 1 and 32."}];
        }
        return NO;
    }

    uint8_t modeByte = (uint8_t)(((wordCount - 1) << 3) + 0x01);
    NSMutableData *payload = [NSMutableData dataWithLength:(6 + wordData.length)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = modeByte;
    payloadBytes[1] = (uint8_t)((address >> 8) & 0xFF);
    payloadBytes[2] = (uint8_t)(address & 0xFF);
    payloadBytes[3] = verifyMode ? 0x80 : 0x00;
    payloadBytes[4] = 0x00;
    payloadBytes[5] = 0x00;
    memcpy(payloadBytes + 6, wordData.bytes, wordData.length);

    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50FlashOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50FlashBridgeOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (BOOL)writeFlashDWordsToAddress:(uint32_t)address
                        dwordData:(NSData *)dwordData
                         onDevice:(MLDMouseDevice *)device
                            error:(NSError **)error {
    if (dwordData.length == 0 || (dwordData.length % 4) != 0) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidFlashPayloadLength
                                     userInfo:@{NSLocalizedDescriptionKey : @"Flash dword write payload must contain 4-byte dword(s)."}];
        }
        return NO;
    }

    NSUInteger dwordCount = dwordData.length / 4;
    if (dwordCount == 0 || dwordCount > 8) {
        if (error != nil) {
            *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                         code:MLDT50ControlErrorCodeInvalidFlashCount
                                     userInfo:@{NSLocalizedDescriptionKey : @"Flash dword write count must be between 1 and 8."}];
        }
        return NO;
    }

    NSMutableData *payload = [NSMutableData dataWithLength:(30 + dwordData.length)];
    uint8_t *payloadBytes = (uint8_t *)payload.mutableBytes;
    payloadBytes[0] = MLDT50FlashWrite32Mode;

    uint32_t count32 = (uint32_t)dwordCount;
    memcpy(payloadBytes + (MLDT50FlashRead32CountOffset - MLDT50FlashBridgeOffset), &count32, sizeof(count32));
    memcpy(payloadBytes + (MLDT50FlashRead32AddressOffset - MLDT50FlashBridgeOffset), &address, sizeof(address));
    memcpy(payloadBytes + (MLDT50FlashRead32ResponseOffset - MLDT50FlashBridgeOffset), dwordData.bytes, dwordData.length);

    NSData *response = [self executeForDevice:device
                                       opcode:MLDT50FlashOpcodeCandidate
                                    writeFlag:MLDT50ReadFlag
                                payloadOffset:MLDT50FlashBridgeOffset
                                      payload:payload
                                        error:error];
    return response != nil;
}

- (BOOL)executeSaveStep:(MLDT50SaveStep)step
                onDevice:(MLDMouseDevice *)device
               stepIndex:(NSUInteger)stepIndex
              totalSteps:(NSUInteger)totalSteps
                   error:(NSError **)error {
    NSData *payload = [NSData dataWithBytes:step.payload length:step.payloadLength];
    NSError *stepError = nil;
    NSData *response = [self executeForDevice:device
                                       opcode:step.opcode
                                    writeFlag:step.writeFlag
                                payloadOffset:step.payloadOffset
                                      payload:payload
                                        error:&stepError];
    if (response != nil) {
        return YES;
    }

    if (error != nil) {
        NSString *message =
            [NSString stringWithFormat:@"T50 save failed at step %lu/%lu (opcode=0x%02x).",
                                       (unsigned long)(stepIndex + 1),
                                       (unsigned long)totalSteps,
                                       step.opcode];
        NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithObject:message
                                                                             forKey:NSLocalizedDescriptionKey];
        if (stepError != nil) {
            userInfo[NSUnderlyingErrorKey] = stepError;
        }
        *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                     code:MLDT50ControlErrorCodeSaveSequenceFailed
                                 userInfo:userInfo];
    }

    return NO;
}

- (BOOL)executeSaveSequence:(const MLDT50SaveStep *)steps
                  stepCount:(NSUInteger)stepCount
                   onDevice:(MLDMouseDevice *)device
             startingAtStep:(NSUInteger)startingAtStep
                 totalSteps:(NSUInteger)totalSteps
                      error:(NSError **)error {
    for (NSUInteger index = 0; index < stepCount; ++index) {
        if (![self executeSaveStep:steps[index]
                          onDevice:device
                         stepIndex:(startingAtStep + index)
                        totalSteps:totalSteps
                             error:error]) {
            return NO;
        }
    }
    return YES;
}

- (BOOL)executeCaptureV3OnDevice:(MLDMouseDevice *)device
                  startingAtStep:(NSUInteger)startingAtStep
                       totalSteps:(NSUInteger)totalSteps
                           error:(NSError **)error {
    const NSUInteger warmupCount = sizeof(MLDT50CaptureV3WarmupSequence) / sizeof(MLDT50CaptureV3WarmupSequence[0]);
    const NSUInteger rampCount =
        sizeof(MLDT50CaptureV3BrightnessRampSequence) / sizeof(MLDT50CaptureV3BrightnessRampSequence[0]);
    const NSUInteger finalizeCount =
        sizeof(MLDT50CaptureV3FinalizeSequence) / sizeof(MLDT50CaptureV3FinalizeSequence[0]);
    NSUInteger index = startingAtStep;

    if (![self executeSaveSequence:MLDT50CaptureV3WarmupSequence
                         stepCount:warmupCount
                          onDevice:device
                    startingAtStep:index
                        totalSteps:totalSteps
                             error:error]) {
        return NO;
    }
    index += warmupCount;

    if (![self executeSaveSequence:MLDT50CaptureV3BrightnessRampSequence
                         stepCount:rampCount
                          onDevice:device
                    startingAtStep:index
                        totalSteps:totalSteps
                             error:error]) {
        return NO;
    }
    index += rampCount;

    return [self executeSaveSequence:MLDT50CaptureV3FinalizeSequence
                           stepCount:finalizeCount
                            onDevice:device
                      startingAtStep:index
                          totalSteps:totalSteps
                               error:error];
}

- (BOOL)saveSettingsToDevice:(MLDMouseDevice *)device
                    strategy:(MLDT50SaveStrategy)strategy
                       error:(NSError **)error {
    const MLDT50SaveStep *steps = NULL;
    NSUInteger stepCount = 0;

    switch (strategy) {
        case MLDT50SaveStrategyQuick:
            steps = MLDT50QuickSaveSequence;
            stepCount = sizeof(MLDT50QuickSaveSequence) / sizeof(MLDT50QuickSaveSequence[0]);
            break;
        case MLDT50SaveStrategyCaptureV1:
            steps = MLDT50CaptureV1SaveSequence;
            stepCount = sizeof(MLDT50CaptureV1SaveSequence) / sizeof(MLDT50CaptureV1SaveSequence[0]);
            break;
        case MLDT50SaveStrategyCaptureV2:
            steps = MLDT50CaptureV2SaveSequence;
            stepCount = sizeof(MLDT50CaptureV2SaveSequence) / sizeof(MLDT50CaptureV2SaveSequence[0]);
            break;
        case MLDT50SaveStrategyCaptureV3:
            return [self executeCaptureV3OnDevice:device
                                   startingAtStep:0
                                        totalSteps:[MLDT50ExchangeVendorCommandUseCase
                                                       saveStepCountForStrategy:MLDT50SaveStrategyCaptureV3]
                                            error:error];
        case MLDT50SaveStrategyCaptureV4: {
            const NSUInteger captureStepCount =
                [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyCaptureV3];
            const NSUInteger majorStepCount =
                sizeof(MLDT50MajorSyncSequence) / sizeof(MLDT50MajorSyncSequence[0]);
            const NSUInteger totalSteps = captureStepCount + majorStepCount;

            if (![self executeCaptureV3OnDevice:device
                                   startingAtStep:0
                                        totalSteps:totalSteps
                                            error:error]) {
                return NO;
            }

            return [self executeSaveSequence:MLDT50MajorSyncSequence
                                   stepCount:majorStepCount
                                    onDevice:device
                              startingAtStep:captureStepCount
                                  totalSteps:totalSteps
                                       error:error];
        }
        case MLDT50SaveStrategyMajorSync:
            steps = MLDT50MajorSyncSequence;
            stepCount = sizeof(MLDT50MajorSyncSequence) / sizeof(MLDT50MajorSyncSequence[0]);
            break;
        default:
            if (error != nil) {
                NSString *message = [NSString stringWithFormat:@"Unsupported T50 save strategy: %lu.",
                                     (unsigned long)strategy];
                *error = [NSError errorWithDomain:MLDT50ControlErrorDomain
                                             code:MLDT50ControlErrorCodeUnsupportedSaveStrategy
                                         userInfo:@{NSLocalizedDescriptionKey : message}];
            }
            return NO;
    }

    return [self executeSaveSequence:steps
                           stepCount:stepCount
                            onDevice:device
                      startingAtStep:0
                          totalSteps:stepCount
                               error:error];
}

@end
