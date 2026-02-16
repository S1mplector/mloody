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

@end
