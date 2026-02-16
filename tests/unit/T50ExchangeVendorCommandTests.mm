#import <Foundation/Foundation.h>

#import "adapters/outbound/memory/MLDInMemoryFeatureTransportAdapter.h"
#import "application/use_cases/MLDT50ExchangeVendorCommandUseCase.h"
#import "domain/entities/MLDMouseDevice.h"

static BOOL Expect(BOOL condition, NSString *message) {
    if (!condition) {
        fprintf(stderr, "Assertion failed: %s\n", message.UTF8String);
        return NO;
    }
    return YES;
}

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
    }

    return 0;
}
