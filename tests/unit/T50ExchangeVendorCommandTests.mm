#import <Foundation/Foundation.h>

#import "adapters/outbound/memory/MLDInMemoryFeatureTransportAdapter.h"
#import "application/ports/MLDFeatureTransportPort.h"
#import "application/use_cases/MLDT50ExchangeVendorCommandUseCase.h"
#import "domain/entities/MLDMouseDevice.h"
#include <string.h>

static BOOL Expect(BOOL condition, NSString *message) {
    if (!condition) {
        fprintf(stderr, "Assertion failed: %s\n", message.UTF8String);
        return NO;
    }
    return YES;
}

@interface MLDRecordingFeatureTransportSpy : NSObject <MLDFeatureTransportPort>

@property(nonatomic, assign) BOOL shouldFail;
@property(nonatomic, strong) NSMutableArray<NSData *> *writes;
@property(nonatomic, strong, nullable) NSData *forcedReadPayload;

@end

@implementation MLDRecordingFeatureTransportSpy

- (instancetype)init {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _shouldFail = NO;
    _writes = [NSMutableArray array];
    _forcedReadPayload = nil;
    return self;
}

- (BOOL)applyPerformanceProfile:(MLDPerformanceProfile *)profile
                       toDevice:(MLDMouseDevice *)device
                          error:(NSError **)error {
    if (self.shouldFail && error != nil) {
        *error = [NSError errorWithDomain:@"test.transport"
                                     code:1
                                 userInfo:@{NSLocalizedDescriptionKey : @"forced apply failure"}];
    }
    return !self.shouldFail;
}

- (BOOL)writeFeatureReportWithID:(uint8_t)reportID
                         payload:(NSData *)payload
                        toDevice:(MLDMouseDevice *)device
                           error:(NSError **)error {
    if (self.shouldFail) {
        if (error != nil) {
            *error = [NSError errorWithDomain:@"test.transport"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey : @"forced write failure"}];
        }
        return NO;
    }

    (void)reportID;
    (void)device;
    [self.writes addObject:[payload copy]];
    return YES;
}

- (nullable NSData *)readFeatureReportWithID:(uint8_t)reportID
                                      length:(NSUInteger)length
                                  fromDevice:(MLDMouseDevice *)device
                                       error:(NSError **)error {
    if (self.shouldFail) {
        if (error != nil) {
            *error = [NSError errorWithDomain:@"test.transport"
                                         code:3
                                     userInfo:@{NSLocalizedDescriptionKey : @"forced read failure"}];
        }
        return nil;
    }

    (void)reportID;
    (void)device;

    NSData *lastWrite = self.forcedReadPayload ?: self.writes.lastObject ?: [NSData data];
    NSMutableData *response = [NSMutableData dataWithLength:length];
    NSUInteger copyLength = MIN(length, lastWrite.length);
    if (copyLength > 0) {
        memcpy(response.mutableBytes, lastWrite.bytes, copyLength);
    }
    return response;
}

@end

int main(void) {
    @autoreleasepool {
        MLDInMemoryFeatureTransportAdapter *transport = [[MLDInMemoryFeatureTransportAdapter alloc] init];
        MLDT50ExchangeVendorCommandUseCase *useCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:transport];

        MLDMouseDevice *device = [[MLDMouseDevice alloc] initWithVendorID:0x09DA
                                                                 productID:0x7F8D
                                                                 modelName:@"Bloody T50"
                                                              serialNumber:@"T50-TEST"];

        const uint8_t payloadBytes[] = {0x01, 0x02, 0x03};
        NSData *payload = [NSData dataWithBytes:payloadBytes length:sizeof(payloadBytes)];

        NSError *exchangeError = nil;
        NSData *response = [useCase executeForDevice:device
                                              opcode:0x22
                                           writeFlag:0x80
                                       payloadOffset:8
                                             payload:payload
                                               error:&exchangeError];
        if (!Expect(response != nil, @"Expected T50 exchange response data.")) {
            return 1;
        }
        if (!Expect(exchangeError == nil, @"Expected no error for valid T50 exchange.")) {
            return 1;
        }
        if (!Expect(response.length == [MLDT50ExchangeVendorCommandUseCase packetLength],
                    @"Expected fixed 72-byte response length.")) {
            return 1;
        }

        const uint8_t *responseBytes = (const uint8_t *)response.bytes;
        if (!Expect(responseBytes[0] == 0x07, @"Expected T50 magic byte in command packet.")) {
            return 1;
        }
        if (!Expect(responseBytes[1] == 0x22, @"Expected opcode to be set in command packet.")) {
            return 1;
        }
        if (!Expect(responseBytes[4] == 0x80, @"Expected write flag to be encoded in packet.")) {
            return 1;
        }
        if (!Expect(responseBytes[8] == 0x01 && responseBytes[9] == 0x02 && responseBytes[10] == 0x03,
                    @"Expected payload bytes to be copied at offset.")) {
            return 1;
        }

        NSError *invalidOffsetError = nil;
        NSData *invalid = [useCase executeForDevice:device
                                             opcode:0x22
                                          writeFlag:0x80
                                      payloadOffset:71
                                            payload:[NSData dataWithBytes:payloadBytes length:2]
                                              error:&invalidOffsetError];
        if (!Expect(invalid == nil, @"Expected overflow payload to fail.")) {
            return 1;
        }
        if (!Expect(invalidOffsetError != nil, @"Expected error for overflow payload.")) {
            return 1;
        }
        if (!Expect(invalidOffsetError.code == MLDT50ControlErrorCodePayloadTooLarge,
                    @"Expected payload-too-large error code.")) {
            return 1;
        }

        NSError *backlightError = nil;
        BOOL invalidBacklight = [useCase setBacklightLevel:5 onDevice:device error:&backlightError];
        if (!Expect(!invalidBacklight, @"Expected invalid backlight level to fail.")) {
            return 1;
        }
        if (!Expect(backlightError != nil, @"Expected backlight validation error.")) {
            return 1;
        }

        NSError *coreSetError = nil;
        BOOL coreSetOK = [useCase setCoreSlotCandidate:3 onDevice:device error:&coreSetError];
        if (!Expect(coreSetOK, @"Expected core slot candidate write to succeed.")) {
            return 1;
        }
        if (!Expect(coreSetError == nil, @"Expected no error for valid core slot candidate.")) {
            return 1;
        }

        NSData *corePacket = transport.writtenReports[@([MLDT50ExchangeVendorCommandUseCase reportID])];
        if (!Expect(corePacket != nil, @"Expected core candidate packet to be written.")) {
            return 1;
        }
        const uint8_t *corePacketBytes = (const uint8_t *)corePacket.bytes;
        if (!Expect(corePacketBytes[1] == 0x0c && corePacketBytes[4] == 0x00 && corePacketBytes[8] == 0x06 &&
                        corePacketBytes[9] == 0x80 && corePacketBytes[10] == 0x03,
                    @"Expected core candidate packet bytes to match 0x0c / 06 80 <slot> pattern.")) {
            return 1;
        }

        NSError *invalidCoreError = nil;
        BOOL invalidCore = [useCase setCoreSlotCandidate:0 onDevice:device error:&invalidCoreError];
        if (!Expect(!invalidCore, @"Expected out-of-range core slot to fail.")) {
            return 1;
        }
        if (!Expect(invalidCoreError != nil, @"Expected error for out-of-range core slot.")) {
            return 1;
        }
        if (!Expect(invalidCoreError.code == MLDT50ControlErrorCodeInvalidCoreSlot,
                    @"Expected invalid-core-slot error code.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *coreReadSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        NSMutableData *coreReadResponse = [NSMutableData dataWithLength:[MLDT50ExchangeVendorCommandUseCase packetLength]];
        uint8_t *coreReadBytes = (uint8_t *)coreReadResponse.mutableBytes;
        coreReadBytes[0] = 0x07;
        coreReadBytes[1] = 0x1f;
        coreReadBytes[10] = 0xE9;
        coreReadBytes[11] = 0x00;
        coreReadSpy.forcedReadPayload = coreReadResponse;
        MLDT50ExchangeVendorCommandUseCase *coreReadUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:coreReadSpy];

        NSError *coreReadError = nil;
        NSNumber *coreSlot = [coreReadUseCase readCoreSlotCandidateForDevice:device error:&coreReadError];
        if (!Expect(coreSlot != nil, @"Expected core candidate read to return value.")) {
            return 1;
        }
        if (!Expect(coreReadError == nil, @"Expected no error for core candidate read.")) {
            return 1;
        }
        if (!Expect(coreSlot.unsignedIntegerValue == 2, @"Expected core candidate read to decode low 2 bits + 1.")) {
            return 1;
        }

        NSData *coreReadRequest = coreReadSpy.writes.lastObject;
        const uint8_t *coreReadRequestBytes = (const uint8_t *)coreReadRequest.bytes;
        if (!Expect(coreReadRequestBytes != NULL && coreReadRequestBytes[1] == 0x1f,
                    @"Expected core candidate read to query opcode 0x1f.")) {
            return 1;
        }

        NSDictionary<NSString *, NSNumber *> *coreState = [coreReadUseCase readCoreStateCandidateForDevice:device error:&coreReadError];
        if (!Expect(coreState != nil, @"Expected core state candidate read to return decoded state.")) {
            return 1;
        }
        if (!Expect(coreState[@"rawWord"].unsignedIntegerValue == 0x00E9,
                    @"Expected core state to expose raw word from response bytes.")) {
            return 1;
        }
        if (!Expect(coreState[@"lowBits"].unsignedIntegerValue == 1,
                    @"Expected core state to expose low 2 bits.")) {
            return 1;
        }
        if (!Expect(coreState[@"slot"].unsignedIntegerValue == 2,
                    @"Expected core state to expose normalized core slot.")) {
            return 1;
        }

        NSError *sledProfileSetError = nil;
        BOOL sledProfileSetOK = [useCase setSLEDProfileIndexCandidate:5 onDevice:device error:&sledProfileSetError];
        if (!Expect(sledProfileSetOK, @"Expected SLED profile candidate write to succeed.")) {
            return 1;
        }
        if (!Expect(sledProfileSetError == nil, @"Expected no error for valid SLED profile candidate write.")) {
            return 1;
        }

        NSData *sledProfilePacket = transport.writtenReports[@([MLDT50ExchangeVendorCommandUseCase reportID])];
        if (!Expect(sledProfilePacket != nil, @"Expected SLED profile candidate packet to be written.")) {
            return 1;
        }
        const uint8_t *sledProfilePacketBytes = (const uint8_t *)sledProfilePacket.bytes;
        if (!Expect(sledProfilePacketBytes[1] == 0x15 && sledProfilePacketBytes[4] == 0x00 &&
                        sledProfilePacketBytes[8] == 0x05,
                    @"Expected SLED profile candidate packet bytes to match opcode 0x15 / payload index @ byte 8.")) {
            return 1;
        }

        NSError *sledEnableSetError = nil;
        BOOL sledEnableSetOK = [useCase setSLEDEnabledCandidate:YES onDevice:device error:&sledEnableSetError];
        if (!Expect(sledEnableSetOK, @"Expected SLED enable candidate write to succeed.")) {
            return 1;
        }
        if (!Expect(sledEnableSetError == nil, @"Expected no error for valid SLED enable candidate write.")) {
            return 1;
        }

        NSData *sledEnablePacket = transport.writtenReports[@([MLDT50ExchangeVendorCommandUseCase reportID])];
        if (!Expect(sledEnablePacket != nil, @"Expected SLED enable candidate packet to be written.")) {
            return 1;
        }
        const uint8_t *sledEnablePacketBytes = (const uint8_t *)sledEnablePacket.bytes;
        if (!Expect(sledEnablePacketBytes[1] == 0x16 && sledEnablePacketBytes[4] == 0x00 &&
                        sledEnablePacketBytes[8] == 0x01,
                    @"Expected SLED enable candidate packet bytes to match opcode 0x16 / boolean @ byte 8.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *sledReadSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        NSMutableData *sledProfileReadResponse = [NSMutableData dataWithLength:[MLDT50ExchangeVendorCommandUseCase packetLength]];
        uint8_t *sledProfileReadBytes = (uint8_t *)sledProfileReadResponse.mutableBytes;
        sledProfileReadBytes[0] = 0x07;
        sledProfileReadBytes[1] = 0x15;
        sledProfileReadBytes[8] = 0x06;
        sledReadSpy.forcedReadPayload = sledProfileReadResponse;
        MLDT50ExchangeVendorCommandUseCase *sledReadUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:sledReadSpy];

        NSError *sledProfileReadError = nil;
        NSNumber *sledProfile = [sledReadUseCase readSLEDProfileIndexCandidateForDevice:device error:&sledProfileReadError];
        if (!Expect(sledProfile != nil, @"Expected SLED profile read candidate to return value.")) {
            return 1;
        }
        if (!Expect(sledProfileReadError == nil, @"Expected no error for SLED profile read candidate.")) {
            return 1;
        }
        if (!Expect(sledProfile.unsignedIntegerValue == 6,
                    @"Expected SLED profile read candidate to decode byte 8.")) {
            return 1;
        }

        NSMutableData *sledEnableReadResponse = [NSMutableData dataWithLength:[MLDT50ExchangeVendorCommandUseCase packetLength]];
        uint8_t *sledEnableReadBytes = (uint8_t *)sledEnableReadResponse.mutableBytes;
        sledEnableReadBytes[0] = 0x07;
        sledEnableReadBytes[1] = 0x16;
        sledEnableReadBytes[8] = 0x01;
        sledReadSpy.forcedReadPayload = sledEnableReadResponse;

        NSError *sledEnableReadError = nil;
        NSNumber *sledEnabled = [sledReadUseCase readSLEDEnabledCandidateForDevice:device error:&sledEnableReadError];
        if (!Expect(sledEnabled != nil, @"Expected SLED enable read candidate to return value.")) {
            return 1;
        }
        if (!Expect(sledEnableReadError == nil, @"Expected no error for SLED enable read candidate.")) {
            return 1;
        }
        if (!Expect(sledEnabled.unsignedIntegerValue == 1,
                    @"Expected SLED enable read candidate to normalize non-zero byte to 1.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *dpiStepSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        MLDT50ExchangeVendorCommandUseCase *dpiStepUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:dpiStepSpy];

        NSError *dpiStepError = nil;
        BOOL dpiStepOK = [dpiStepUseCase stepDPICandidateAction:MLDT50DPIStepActionUp
                                                         opcode:0x0F
                                                         commit:NO
                                                       onDevice:device
                                                          error:&dpiStepError];
        if (!Expect(dpiStepOK, @"Expected DPI step candidate action to succeed without commit.")) {
            return 1;
        }
        if (!Expect(dpiStepError == nil, @"Expected no error for valid DPI step candidate action.")) {
            return 1;
        }
        if (!Expect(dpiStepSpy.writes.count == 1, @"Expected one packet for non-commit DPI step candidate action.")) {
            return 1;
        }
        const uint8_t *dpiStepPacket = (const uint8_t *)dpiStepSpy.writes.firstObject.bytes;
        if (!Expect(dpiStepPacket[1] == 0x0f && dpiStepPacket[8] == 0x01,
                    @"Expected non-commit DPI step packet to use opcode 0x0F with action byte 0x01.")) {
            return 1;
        }

        [dpiStepSpy.writes removeAllObjects];
        NSError *dpiCommitError = nil;
        BOOL dpiCommitOK = [dpiStepUseCase stepDPICandidateAction:MLDT50DPIStepActionCycle
                                                           opcode:0x0F
                                                           commit:YES
                                                         onDevice:device
                                                            error:&dpiCommitError];
        if (!Expect(dpiCommitOK, @"Expected DPI step candidate action with commit to succeed.")) {
            return 1;
        }
        if (!Expect(dpiCommitError == nil, @"Expected no error for committed DPI step candidate action.")) {
            return 1;
        }
        if (!Expect(dpiStepSpy.writes.count == 2, @"Expected two packets for committed DPI step candidate action.")) {
            return 1;
        }
        const uint8_t *dpiCommitStepPacket = (const uint8_t *)dpiStepSpy.writes.firstObject.bytes;
        if (!Expect(dpiCommitStepPacket[1] == 0x0f && dpiCommitStepPacket[8] == 0x02,
                    @"Expected committed DPI step packet to encode cycle action byte 0x02.")) {
            return 1;
        }
        const uint8_t *dpiCommitTailPacket = (const uint8_t *)dpiStepSpy.writes.lastObject.bytes;
        if (!Expect(dpiCommitTailPacket[1] == 0x0a,
                    @"Expected committed DPI step packet tail to issue opcode 0x0A commit.")) {
            return 1;
        }

        [dpiStepSpy.writes removeAllObjects];
        NSError *dpiInvalidError = nil;
        BOOL dpiInvalid = [dpiStepUseCase stepDPICandidateAction:(MLDT50DPIStepAction)99
                                                          opcode:0x0F
                                                          commit:NO
                                                        onDevice:device
                                                           error:&dpiInvalidError];
        if (!Expect(!dpiInvalid, @"Expected invalid DPI step action to fail.")) {
            return 1;
        }
        if (!Expect(dpiInvalidError != nil, @"Expected error for invalid DPI step action.")) {
            return 1;
        }
        if (!Expect(dpiInvalidError.code == MLDT50ControlErrorCodeInvalidDPIStepAction,
                    @"Expected invalid-DPI-step-action error code.")) {
            return 1;
        }
        if (!Expect(dpiStepSpy.writes.count == 0, @"Expected no packets when DPI step action is invalid.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *flashSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        MLDT50ExchangeVendorCommandUseCase *flashUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:flashSpy];

        NSMutableData *flashRead8Response = [NSMutableData dataWithLength:[MLDT50ExchangeVendorCommandUseCase packetLength]];
        uint8_t *flashRead8Bytes = (uint8_t *)flashRead8Response.mutableBytes;
        flashRead8Bytes[0] = 0x07;
        flashRead8Bytes[1] = 0x2f;
        flashRead8Bytes[8] = 0xa4;
        flashRead8Bytes[9] = 0xa4;
        flashRead8Bytes[10] = 0xff;
        flashRead8Bytes[11] = 0xff;
        flashRead8Bytes[12] = 0x31;
        flashRead8Bytes[13] = 0x23;
        flashRead8Bytes[14] = 0x1e;
        flashRead8Bytes[15] = 0xf2;
        flashSpy.forcedReadPayload = flashRead8Response;

        NSError *flashRead8Error = nil;
        NSData *flashRead8 = [flashUseCase readFlashBytes8FromAddress:0x1c00 onDevice:device error:&flashRead8Error];
        if (!Expect(flashRead8 != nil, @"Expected flash read8 to return 8 bytes.")) {
            return 1;
        }
        if (!Expect(flashRead8Error == nil, @"Expected no error for valid flash read8.")) {
            return 1;
        }
        if (!Expect(flashRead8.length == 8, @"Expected flash read8 length to be 8.")) {
            return 1;
        }
        const uint8_t *flashRead8Payload = (const uint8_t *)flashRead8.bytes;
        if (!Expect(flashRead8Payload[0] == 0xa4 && flashRead8Payload[7] == 0xf2,
                    @"Expected flash read8 payload bytes to match forced response.")) {
            return 1;
        }
        const uint8_t *flashRead8Request = (const uint8_t *)flashSpy.writes.lastObject.bytes;
        if (!Expect(flashRead8Request[1] == 0x2f && flashRead8Request[2] == 0x00 &&
                        flashRead8Request[3] == 0x1c && flashRead8Request[4] == 0x00,
                    @"Expected flash read8 request packet to encode mode=0 and address 0x1c00.")) {
            return 1;
        }

        [flashSpy.writes removeAllObjects];
        NSMutableData *flashRead32Response = [NSMutableData dataWithLength:[MLDT50ExchangeVendorCommandUseCase packetLength]];
        uint8_t *flashRead32Bytes = (uint8_t *)flashRead32Response.mutableBytes;
        flashRead32Bytes[0] = 0x07;
        flashRead32Bytes[1] = 0x2f;
        flashRead32Bytes[32] = 0x78;
        flashRead32Bytes[33] = 0x56;
        flashRead32Bytes[34] = 0x34;
        flashRead32Bytes[35] = 0x12;
        flashRead32Bytes[36] = 0xf0;
        flashRead32Bytes[37] = 0xde;
        flashRead32Bytes[38] = 0xbc;
        flashRead32Bytes[39] = 0x9a;
        flashSpy.forcedReadPayload = flashRead32Response;

        NSError *flashRead32Error = nil;
        NSData *flashRead32 = [flashUseCase readFlashDWordsFromAddress:0x00002e00
                                                                 count:2
                                                              onDevice:device
                                                                 error:&flashRead32Error];
        if (!Expect(flashRead32 != nil, @"Expected flash read32 to return dword bytes.")) {
            return 1;
        }
        if (!Expect(flashRead32Error == nil, @"Expected no error for valid flash read32.")) {
            return 1;
        }
        if (!Expect(flashRead32.length == 8, @"Expected flash read32 count=2 to return 8 bytes.")) {
            return 1;
        }
        const uint8_t *flashRead32Payload = (const uint8_t *)flashRead32.bytes;
        if (!Expect(flashRead32Payload[0] == 0x78 && flashRead32Payload[7] == 0x9a,
                    @"Expected flash read32 payload bytes to match forced response.")) {
            return 1;
        }
        const uint8_t *flashRead32Request = (const uint8_t *)flashSpy.writes.lastObject.bytes;
        if (!Expect(flashRead32Request[1] == 0x2f && flashRead32Request[2] == 0x00 &&
                        flashRead32Request[24] == 0x02 && flashRead32Request[28] == 0x00 &&
                        flashRead32Request[29] == 0x2e && flashRead32Request[30] == 0x00 &&
                        flashRead32Request[31] == 0x00,
                    @"Expected flash read32 request packet to encode mode=0, count=2, addr=0x00002e00.")) {
            return 1;
        }

        [flashSpy.writes removeAllObjects];
        const uint8_t flashWrite16Payload[] = {0x34, 0x12, 0x78, 0x56};
        NSError *flashWrite16Error = nil;
        BOOL flashWrite16OK = [flashUseCase writeFlashWordsToAddress:0x1d00
                                                            wordData:[NSData dataWithBytes:flashWrite16Payload
                                                                                     length:sizeof(flashWrite16Payload)]
                                                          verifyMode:NO
                                                            onDevice:device
                                                               error:&flashWrite16Error];
        if (!Expect(flashWrite16OK, @"Expected flash write16 to succeed with 2 words.")) {
            return 1;
        }
        if (!Expect(flashWrite16Error == nil, @"Expected no error for valid flash write16.")) {
            return 1;
        }
        const uint8_t *flashWrite16Request = (const uint8_t *)flashSpy.writes.lastObject.bytes;
        if (!Expect(flashWrite16Request[1] == 0x2f && flashWrite16Request[2] == 0x09 &&
                        flashWrite16Request[3] == 0x1d && flashWrite16Request[4] == 0x00 &&
                        flashWrite16Request[5] == 0x00 &&
                        flashWrite16Request[8] == 0x34 && flashWrite16Request[11] == 0x56,
                    @"Expected flash write16 request packet to encode count/mode/address and word payload.")) {
            return 1;
        }

        [flashSpy.writes removeAllObjects];
        const uint8_t flashWrite16VerifyPayload[] = {0xaa, 0xbb};
        NSError *flashWrite16VerifyError = nil;
        BOOL flashWrite16VerifyOK = [flashUseCase writeFlashWordsToAddress:0x1d00
                                                                  wordData:[NSData dataWithBytes:flashWrite16VerifyPayload
                                                                                           length:sizeof(flashWrite16VerifyPayload)]
                                                                verifyMode:YES
                                                                  onDevice:device
                                                                     error:&flashWrite16VerifyError];
        if (!Expect(flashWrite16VerifyOK, @"Expected flash write16 verify-mode packet to succeed.")) {
            return 1;
        }
        if (!Expect(flashWrite16VerifyError == nil, @"Expected no error for valid flash write16 verify-mode.")) {
            return 1;
        }
        const uint8_t *flashWrite16VerifyRequest = (const uint8_t *)flashSpy.writes.lastObject.bytes;
        if (!Expect(flashWrite16VerifyRequest[5] == 0x80,
                    @"Expected flash write16 verify-mode to encode 0x80 in byte 5.")) {
            return 1;
        }

        [flashSpy.writes removeAllObjects];
        const uint8_t flashWrite32Payload[] = {0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a};
        NSError *flashWrite32Error = nil;
        BOOL flashWrite32OK = [flashUseCase writeFlashDWordsToAddress:0x00002e00
                                                             dwordData:[NSData dataWithBytes:flashWrite32Payload
                                                                                        length:sizeof(flashWrite32Payload)]
                                                              onDevice:device
                                                                 error:&flashWrite32Error];
        if (!Expect(flashWrite32OK, @"Expected flash write32 to succeed with 2 dwords.")) {
            return 1;
        }
        if (!Expect(flashWrite32Error == nil, @"Expected no error for valid flash write32.")) {
            return 1;
        }
        const uint8_t *flashWrite32Request = (const uint8_t *)flashSpy.writes.lastObject.bytes;
        if (!Expect(flashWrite32Request[1] == 0x2f && flashWrite32Request[2] == 0x01 &&
                        flashWrite32Request[24] == 0x02 &&
                        flashWrite32Request[28] == 0x00 && flashWrite32Request[29] == 0x2e &&
                        flashWrite32Request[30] == 0x00 && flashWrite32Request[31] == 0x00 &&
                        flashWrite32Request[32] == 0x78 && flashWrite32Request[39] == 0x9a,
                    @"Expected flash write32 request packet to encode mode=1, count, addr, and payload.")) {
            return 1;
        }

        NSError *invalidFlashReadCountError = nil;
        NSData *invalidFlashRead = [flashUseCase readFlashDWordsFromAddress:0x00002e00
                                                                       count:0
                                                                    onDevice:device
                                                                       error:&invalidFlashReadCountError];
        if (!Expect(invalidFlashRead == nil, @"Expected flash read32 with count=0 to fail.")) {
            return 1;
        }
        if (!Expect(invalidFlashReadCountError != nil, @"Expected flash read32 count validation error.")) {
            return 1;
        }
        if (!Expect(invalidFlashReadCountError.code == MLDT50ControlErrorCodeInvalidFlashCount,
                    @"Expected invalid-flash-count error code for read32 count=0.")) {
            return 1;
        }

        NSError *invalidFlashWrite16LengthError = nil;
        BOOL invalidFlashWrite16 = [flashUseCase writeFlashWordsToAddress:0x1d00
                                                                 wordData:[NSData dataWithBytes:flashWrite16Payload length:3]
                                                               verifyMode:NO
                                                                 onDevice:device
                                                                    error:&invalidFlashWrite16LengthError];
        if (!Expect(!invalidFlashWrite16, @"Expected flash write16 with odd byte length to fail.")) {
            return 1;
        }
        if (!Expect(invalidFlashWrite16LengthError != nil, @"Expected flash write16 payload-length validation error.")) {
            return 1;
        }
        if (!Expect(invalidFlashWrite16LengthError.code == MLDT50ControlErrorCodeInvalidFlashPayloadLength,
                    @"Expected invalid-flash-payload-length code for flash write16 odd byte length.")) {
            return 1;
        }

        NSMutableData *tooManyDwords = [NSMutableData dataWithLength:36];
        NSError *invalidFlashWrite32CountError = nil;
        BOOL invalidFlashWrite32 = [flashUseCase writeFlashDWordsToAddress:0x00002e00
                                                                  dwordData:tooManyDwords
                                                                   onDevice:device
                                                                      error:&invalidFlashWrite32CountError];
        if (!Expect(!invalidFlashWrite32, @"Expected flash write32 with >8 dwords to fail.")) {
            return 1;
        }
        if (!Expect(invalidFlashWrite32CountError != nil, @"Expected flash write32 count validation error.")) {
            return 1;
        }
        if (!Expect(invalidFlashWrite32CountError.code == MLDT50ControlErrorCodeInvalidFlashCount,
                    @"Expected invalid-flash-count code for flash write32 >8 dwords.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *saveSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        MLDT50ExchangeVendorCommandUseCase *saveUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:saveSpy];

        NSError *saveError = nil;
        BOOL quickSaved = [saveUseCase saveSettingsToDevice:device
                                                   strategy:MLDT50SaveStrategyQuick
                                                      error:&saveError];
        if (!Expect(quickSaved, @"Expected quick T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(saveError == nil, @"Expected no error for quick save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count == [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyQuick],
                    @"Expected quick strategy to emit expected number of packets.")) {
            return 1;
        }

        const uint8_t *quickFirstPacket = (const uint8_t *)saveSpy.writes.firstObject.bytes;
        if (!Expect(quickFirstPacket[0] == 0x07 && quickFirstPacket[1] == 0x03 &&
                        quickFirstPacket[2] == 0x03 && quickFirstPacket[3] == 0x0B && quickFirstPacket[4] == 0x01,
                    @"Expected quick save arm packet bytes to match capture candidate.")) {
            return 1;
        }
        const uint8_t *quickLastPacket = (const uint8_t *)saveSpy.writes.lastObject.bytes;
        if (!Expect(quickLastPacket[2] == 0x03 && quickLastPacket[3] == 0x0B && quickLastPacket[4] == 0x00,
                    @"Expected quick save release packet bytes to match capture candidate.")) {
            return 1;
        }

        [saveSpy.writes removeAllObjects];
        NSError *captureSaveError = nil;
        BOOL captureSaved = [saveUseCase saveSettingsToDevice:device
                                                     strategy:MLDT50SaveStrategyCaptureV1
                                                        error:&captureSaveError];
        if (!Expect(captureSaved, @"Expected capture-v1 T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(captureSaveError == nil, @"Expected no error for capture-v1 save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count ==
                        [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyCaptureV1],
                    @"Expected capture-v1 strategy to emit expected number of packets.")) {
            return 1;
        }

        const uint8_t *captureFirstPacket = (const uint8_t *)saveSpy.writes.firstObject.bytes;
        if (!Expect(captureFirstPacket[1] == 0x03 && captureFirstPacket[2] == 0x06 && captureFirstPacket[3] == 0x05,
                    @"Expected capture-v1 first packet to start with 03 06 05.")) {
            return 1;
        }
        const uint8_t *captureLastPacket = (const uint8_t *)saveSpy.writes.lastObject.bytes;
        if (!Expect(captureLastPacket[1] == 0x03 && captureLastPacket[2] == 0x03 &&
                        captureLastPacket[3] == 0x0B && captureLastPacket[4] == 0x00,
                    @"Expected capture-v1 last packet to release save latch.")) {
            return 1;
        }

        [saveSpy.writes removeAllObjects];
        NSError *captureV2SaveError = nil;
        BOOL captureV2Saved = [saveUseCase saveSettingsToDevice:device
                                                       strategy:MLDT50SaveStrategyCaptureV2
                                                          error:&captureV2SaveError];
        if (!Expect(captureV2Saved, @"Expected capture-v2 T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(captureV2SaveError == nil, @"Expected no error for capture-v2 save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count ==
                        [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyCaptureV2],
                    @"Expected capture-v2 strategy to emit expected number of packets.")) {
            return 1;
        }

        const uint8_t *captureV2FirstPacket = (const uint8_t *)saveSpy.writes.firstObject.bytes;
        if (!Expect(captureV2FirstPacket[1] == 0x03 && captureV2FirstPacket[2] == 0x03 &&
                        captureV2FirstPacket[3] == 0x0B && captureV2FirstPacket[4] == 0x00,
                    @"Expected capture-v2 first packet to match 03 03 0B 00 save release.")) {
            return 1;
        }
        const uint8_t *captureV2FourthPacket = (const uint8_t *)saveSpy.writes[3].bytes;
        if (!Expect(captureV2FourthPacket[1] == 0x2F && captureV2FourthPacket[24] == 0x02 &&
                        captureV2FourthPacket[29] == 0xE2,
                    @"Expected capture-v2 fourth packet to match 2f save preamble bytes.")) {
            return 1;
        }
        const uint8_t *captureV2SeventhPacket = (const uint8_t *)saveSpy.writes[6].bytes;
        if (!Expect(captureV2SeventhPacket[1] == 0x0C && captureV2SeventhPacket[8] == 0x06 &&
                        captureV2SeventhPacket[9] == 0x80 && captureV2SeventhPacket[10] == 0x01,
                    @"Expected capture-v2 seventh packet to match 0c 06 80 01 apply candidate.")) {
            return 1;
        }
        const uint8_t *captureV2LastPacket = (const uint8_t *)saveSpy.writes.lastObject.bytes;
        if (!Expect(captureV2LastPacket[1] == 0x0A,
                    @"Expected capture-v2 tail packet to end with opcode 0x0A.")) {
            return 1;
        }

        [saveSpy.writes removeAllObjects];
        NSError *captureV3SaveError = nil;
        BOOL captureV3Saved = [saveUseCase saveSettingsToDevice:device
                                                       strategy:MLDT50SaveStrategyCaptureV3
                                                          error:&captureV3SaveError];
        if (!Expect(captureV3Saved, @"Expected capture-v3 T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(captureV3SaveError == nil, @"Expected no error for capture-v3 save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count ==
                        [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyCaptureV3],
                    @"Expected capture-v3 strategy to emit expected number of packets.")) {
            return 1;
        }

        const uint8_t *captureV3FirstPacket = (const uint8_t *)saveSpy.writes.firstObject.bytes;
        if (!Expect(captureV3FirstPacket[1] == 0x03 && captureV3FirstPacket[2] == 0x06 &&
                        captureV3FirstPacket[3] == 0x05,
                    @"Expected capture-v3 first packet to start with 03 06 05 warmup.")) {
            return 1;
        }
        const uint8_t *captureV3OpenBrightnessPacket = (const uint8_t *)saveSpy.writes[3].bytes;
        if (!Expect(captureV3OpenBrightnessPacket[1] == 0x03 && captureV3OpenBrightnessPacket[2] == 0x03 &&
                        captureV3OpenBrightnessPacket[3] == 0x0B && captureV3OpenBrightnessPacket[4] == 0x01,
                    @"Expected capture-v3 to open brightness menu via 03 03 0B 01.")) {
            return 1;
        }
        const uint8_t *captureV3BrightnessMinPacket = (const uint8_t *)saveSpy.writes[4].bytes;
        if (!Expect(captureV3BrightnessMinPacket[1] == 0x11 && captureV3BrightnessMinPacket[4] == 0x80 &&
                        captureV3BrightnessMinPacket[8] == 0x00,
                    @"Expected capture-v3 to set brightness ramp start to 0.")) {
            return 1;
        }
        const uint8_t *captureV3BrightnessMaxPacket = (const uint8_t *)saveSpy.writes[10].bytes;
        if (!Expect(captureV3BrightnessMaxPacket[1] == 0x11 && captureV3BrightnessMaxPacket[4] == 0x80 &&
                        captureV3BrightnessMaxPacket[8] == 0x03,
                    @"Expected capture-v3 to set brightness ramp end to 3.")) {
            return 1;
        }
        const uint8_t *captureV3TailPreamblePacket = (const uint8_t *)saveSpy.writes[15].bytes;
        if (!Expect(captureV3TailPreamblePacket[1] == 0x2F && captureV3TailPreamblePacket[24] == 0x02 &&
                        captureV3TailPreamblePacket[29] == 0xE2,
                    @"Expected capture-v3 tail to include 2F preamble bytes.")) {
            return 1;
        }
        const uint8_t *captureV3LastPacket = (const uint8_t *)saveSpy.writes.lastObject.bytes;
        if (!Expect(captureV3LastPacket[1] == 0x03 && captureV3LastPacket[2] == 0x06 &&
                        captureV3LastPacket[3] == 0x06,
                    @"Expected capture-v3 to end with 03 06 06 finalize packet.")) {
            return 1;
        }

        [saveSpy.writes removeAllObjects];
        NSError *captureV4SaveError = nil;
        BOOL captureV4Saved = [saveUseCase saveSettingsToDevice:device
                                                       strategy:MLDT50SaveStrategyCaptureV4
                                                          error:&captureV4SaveError];
        if (!Expect(captureV4Saved, @"Expected capture-v4 T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(captureV4SaveError == nil, @"Expected no error for capture-v4 save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count ==
                        [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyCaptureV4],
                    @"Expected capture-v4 strategy to emit expected number of packets.")) {
            return 1;
        }

        const uint8_t *captureV4MajorSyncFirstPacket = (const uint8_t *)saveSpy.writes[22].bytes;
        if (!Expect(captureV4MajorSyncFirstPacket[1] == 0x07,
                    @"Expected capture-v4 to append major-sync opcode 0x07 after capture-v3 flow.")) {
            return 1;
        }
        const uint8_t *captureV4MajorSyncSecondPacket = (const uint8_t *)saveSpy.writes[23].bytes;
        if (!Expect(captureV4MajorSyncSecondPacket[1] == 0x08,
                    @"Expected capture-v4 to append major-sync opcode 0x08.")) {
            return 1;
        }
        const uint8_t *captureV4MajorSyncFourthPacket = (const uint8_t *)saveSpy.writes[25].bytes;
        if (!Expect(captureV4MajorSyncFourthPacket[1] == 0x1e && captureV4MajorSyncFourthPacket[2] == 0x01,
                    @"Expected capture-v4 to include 0x1E with payload byte 0x01.")) {
            return 1;
        }

        [saveSpy.writes removeAllObjects];
        NSError *majorSyncSaveError = nil;
        BOOL majorSyncSaved = [saveUseCase saveSettingsToDevice:device
                                                       strategy:MLDT50SaveStrategyMajorSync
                                                          error:&majorSyncSaveError];
        if (!Expect(majorSyncSaved, @"Expected major-sync T50 save strategy to succeed.")) {
            return 1;
        }
        if (!Expect(majorSyncSaveError == nil, @"Expected no error for major-sync save strategy.")) {
            return 1;
        }
        if (!Expect(saveSpy.writes.count ==
                        [MLDT50ExchangeVendorCommandUseCase saveStepCountForStrategy:MLDT50SaveStrategyMajorSync],
                    @"Expected major-sync strategy to emit expected number of packets.")) {
            return 1;
        }
        const uint8_t *majorSyncFirstPacket = (const uint8_t *)saveSpy.writes.firstObject.bytes;
        if (!Expect(majorSyncFirstPacket[1] == 0x07,
                    @"Expected major-sync first packet opcode to be 0x07.")) {
            return 1;
        }
        const uint8_t *majorSyncLastPacket = (const uint8_t *)saveSpy.writes.lastObject.bytes;
        if (!Expect(majorSyncLastPacket[1] == 0x0a,
                    @"Expected major-sync last packet opcode to be 0x0A.")) {
            return 1;
        }

        MLDRecordingFeatureTransportSpy *failingSpy = [[MLDRecordingFeatureTransportSpy alloc] init];
        failingSpy.shouldFail = YES;
        MLDT50ExchangeVendorCommandUseCase *failingUseCase =
            [[MLDT50ExchangeVendorCommandUseCase alloc] initWithFeatureTransportPort:failingSpy];
        NSError *failingSaveError = nil;
        BOOL failingSave = [failingUseCase saveSettingsToDevice:device
                                                       strategy:MLDT50SaveStrategyQuick
                                                          error:&failingSaveError];
        if (!Expect(!failingSave, @"Expected save strategy to fail when transport fails.")) {
            return 1;
        }
        if (!Expect(failingSaveError != nil, @"Expected error for failed save strategy.")) {
            return 1;
        }
        if (!Expect(failingSaveError.code == MLDT50ControlErrorCodeSaveSequenceFailed,
                    @"Expected save failure error code for transport failure.")) {
            return 1;
        }
    }

    return 0;
}
