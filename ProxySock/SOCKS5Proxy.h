//
//  SOCKS5Proxy.h
//  Tether
//
//  Created by Christopher Ballinger on 11/26/13.
//  Copyright (c) 2013 Christopher Ballinger. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <GCDAsyncSocket.h>
#import "SOCKS5ProxySocket.h"

@class SOCKS5Proxy;

@protocol SOCKS5ProxyDelegate <NSObject>
- (void) SOCKS5Proxy:(SOCKS5Proxy*)SOCKS5Proxy clientDidConnect:(SOCKS5ProxySocket*)clientSocket;
- (void) SOCKS5Proxy:(SOCKS5Proxy*)SOCKS5Proxy clientDidDisconnect:(SOCKS5ProxySocket*)clientSocket;
@end

/**
 *  SOCKS proxy server implementation.
 */
@interface SOCKS5Proxy : NSObject <GCDAsyncSocketDelegate, SOCKS5ProxySocketDelegate>

@property (nonatomic, readonly) uint16_t listeningPort;
@property (nonatomic, weak) id<SOCKS5ProxyDelegate> delegate;
@property (nonatomic) dispatch_queue_t callbackQueue;
@property (nonatomic, readonly) NSUInteger connectionCount;

/**
 *  Total number of bytes written during lifetime of SOCKS5Proxy.
 *  @see resetNetworkStatistics
 */
@property (nonatomic, readonly) NSUInteger totalBytesWritten;

/**
 *  Total number of bytes read during lifetime of SOCKS5Proxy.
 *  @see resetNetworkStatistics
 */
@property (nonatomic, readonly) NSUInteger totalBytesRead;

/**
 *  Sets `totalBytesWritten` and `totalBytesRead` to 0.
 *  @see totalBytesWritten
 *  @see totalBytesRead
 */
- (void) resetNetworkStatistics;


- (BOOL) startProxy; // defaults to port 9050
- (BOOL) startProxyOnPort:(uint16_t)port;
- (BOOL) startProxyOnPort:(uint16_t)port error:(NSError**)error;
- (void) disconnect;

-(void)setOutgoingHost:(NSString*)host port:(uint16_t)port;
-(void)setOutgoingSocksUsername:(NSString*)username password:(NSString*)password;


// SOCKS authorization
// btw this is horribly insecure, especially over the open internet
- (void) addAuthorizedUser:(NSString*)username password:(NSString*)password;
- (void) removeAuthorizedUser:(NSString*)username;
- (void) removeAllAuthorizedUsers;
- (BOOL) checkAuthorizationForUser:(NSString*)username password:(NSString*)password;

@end
