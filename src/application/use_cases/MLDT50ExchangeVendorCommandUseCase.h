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
    MLDT50ControlErrorCodeInvalidDPIStepAction = 9,
    MLDT50ControlErrorCodeInvalidFlashCount = 10,
    MLDT50ControlErrorCodeInvalidFlashPayloadLength = 11,
};

typedef NS_ENUM(NSUInteger, MLDT50SaveStrategy) {
    MLDT50SaveStrategyQuick = 0,
    MLDT50SaveStrategyCaptureV1 = 1,
    MLDT50SaveStrategyCaptureV2 = 2,
    MLDT50SaveStrategyCaptureV3 = 3,
    MLDT50SaveStrategyCaptureV4 = 4,
    MLDT50SaveStrategyMajorSync = 5,
};

typedef NS_ENUM(NSUInteger, MLDT50DPIStepAction) {
    MLDT50DPIStepActionDown = 0,
    MLDT50DPIStepActionUp = 1,
    MLDT50DPIStepActionCycle = 2,
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

- (BOOL)setSLEDProfileIndexCandidate:(uint8_t)index
                             onDevice:(MLDMouseDevice *)device
                                error:(NSError **)error;

- (nullable NSNumber *)readSLEDProfileIndexCandidateForDevice:(MLDMouseDevice *)device
                                                         error:(NSError **)error;

- (BOOL)setSLEDEnabledCandidate:(BOOL)enabled
                        onDevice:(MLDMouseDevice *)device
                           error:(NSError **)error;

- (nullable NSNumber *)readSLEDEnabledCandidateForDevice:(MLDMouseDevice *)device
                                                    error:(NSError **)error;

- (BOOL)stepDPICandidateAction:(MLDT50DPIStepAction)action
                        opcode:(uint8_t)opcode
                        commit:(BOOL)commit
                      onDevice:(MLDMouseDevice *)device
                         error:(NSError **)error;

- (nullable NSData *)readFlashBytes8FromAddress:(uint16_t)address
                                       onDevice:(MLDMouseDevice *)device
                                          error:(NSError **)error;

- (nullable NSData *)readFlashDWordsFromAddress:(uint32_t)address
                                          count:(uint8_t)count
                                       onDevice:(MLDMouseDevice *)device
                                          error:(NSError **)error;

- (BOOL)writeFlashWordsToAddress:(uint16_t)address
                        wordData:(NSData *)wordData
                      verifyMode:(BOOL)verifyMode
                        onDevice:(MLDMouseDevice *)device
                           error:(NSError **)error;

- (BOOL)writeFlashDWordsToAddress:(uint32_t)address
                        dwordData:(NSData *)dwordData
                         onDevice:(MLDMouseDevice *)device
                            error:(NSError **)error;

- (BOOL)saveSettingsToDevice:(MLDMouseDevice *)device
                    strategy:(MLDT50SaveStrategy)strategy
                       error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
