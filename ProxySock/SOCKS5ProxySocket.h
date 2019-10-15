//
//  SOCKS5ProxySocket.h
//  Tether
//
//  Created by Christopher Ballinger on 11/26/13.
//  Copyright (c) 2013 Christopher Ballinger. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <GCDAsyncSocket.h>

@class SOCKS5ProxySocket;

@protocol SOCKS5ProxySocketDelegate <NSObject>
@optional
- (void) proxySocketDidDisconnect:(SOCKS5ProxySocket*)proxySocket withError:(NSError *)error;
- (void) proxySocket:(SOCKS5ProxySocket*)proxySocket didReadDataOfLength:(NSUInteger)numBytes;
- (void) proxySocket:(SOCKS5ProxySocket*)proxySocket didWriteDataOfLength:(NSUInteger)numBytes;
- (BOOL) proxySocket:(SOCKS5ProxySocket*)proxySocket
checkAuthorizationForUser:(NSString*)username
            password:(NSString*)password;



@end


//copy from SOCKS5ProxySocket, but change the outgoing to GCDAsyncProxySocket
@interface SOCKS5ProxySocket : NSObject <GCDAsyncSocketDelegate>

@property (nonatomic, readonly) uint16_t destinationPort;
@property (nonatomic, strong, readonly) NSString* destinationHost;
@property (nonatomic, weak) id<SOCKS5ProxySocketDelegate> delegate;
@property (nonatomic) dispatch_queue_t callbackQueue;
@property (nonatomic, readonly) NSUInteger totalBytesWritten;
@property (nonatomic, readonly) NSUInteger totalBytesRead;

- (void) disconnect;

- (id) initWithSocket:(GCDAsyncSocket*)socket delegate:(id<SOCKS5ProxySocketDelegate>)delegate;

@property (nonatomic, strong) NSString *outgoingHost;
@property (nonatomic, assign) uint16_t outgoingPort;
@property (nonatomic, strong) NSString *outgoingUsername;
@property (nonatomic, strong) NSString *outgoingPassword;

@end
