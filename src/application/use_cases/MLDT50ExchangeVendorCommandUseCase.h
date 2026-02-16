#import <Foundation/Foundation.h>
#include <stdint.h>

#import "application/ports/MLDFeatureTransportPort.h"

@class MLDMouseDevice;

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MLDT50ControlErrorDomain;

typedef NS_ERROR_ENUM(MLDT50ControlErrorDomain, MLDT50ControlErrorCode) {
    MLDT50ControlErrorCodeInvalidPayloadOffset = 1,
    MLDT50ControlErrorCodePayloadTooLarge = 2,
    MLDT50ControlErrorCodeTransportReadFailed = 3,
    MLDT50ControlErrorCodeResponseTooShort = 4,
    MLDT50ControlErrorCodeInvalidBacklightLevel = 5,
    MLDT50ControlErrorCodeSaveSequenceFailed = 6,
    MLDT50ControlErrorCodeUnsupportedSaveStrategy = 7,
    MLDT50ControlErrorCodeInvalidCoreSlot = 8,
};

typedef NS_ENUM(NSUInteger, MLDT50SaveStrategy) {
    MLDT50SaveStrategyQuick = 0,
    MLDT50SaveStrategyCaptureV1 = 1,
    MLDT50SaveStrategyCaptureV2 = 2,
    MLDT50SaveStrategyCaptureV3 = 3,
};

@interface MLDT50ExchangeVendorCommandUseCase : NSObject

- (instancetype)initWithFeatureTransportPort:(id<MLDFeatureTransportPort>)featureTransportPort NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

+ (NSUInteger)packetLength;
+ (uint8_t)reportID;
+ (NSUInteger)saveStepCountForStrategy:(MLDT50SaveStrategy)strategy;

- (nullable NSData *)executeForDevice:(MLDMouseDevice *)device
                               opcode:(uint8_t)opcode
                            writeFlag:(uint8_t)writeFlag
                        payloadOffset:(NSUInteger)payloadOffset
                              payload:(NSData *)payload
                                error:(NSError **)error;

- (BOOL)setBacklightLevel:(uint8_t)level
                 onDevice:(MLDMouseDevice *)device
                    error:(NSError **)error;

- (nullable NSNumber *)readBacklightLevelForDevice:(MLDMouseDevice *)device
                                             error:(NSError **)error;

- (BOOL)setCoreSlotCandidate:(uint8_t)slot
                    onDevice:(MLDMouseDevice *)device
                       error:(NSError **)error;

- (nullable NSNumber *)readCoreSlotCandidateForDevice:(MLDMouseDevice *)device
                                                 error:(NSError **)error;

- (nullable NSDictionary<NSString *, NSNumber *> *)readCoreStateCandidateForDevice:(MLDMouseDevice *)device
                                                                              error:(NSError **)error;

- (BOOL)saveSettingsToDevice:(MLDMouseDevice *)device
                    strategy:(MLDT50SaveStrategy)strategy
                       error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
