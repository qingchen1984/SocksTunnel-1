//
//  SOCKS5Proxy.m
//  Tether
//
//  Created by Christopher Ballinger on 11/26/13.
//  Copyright (c) 2013 Christopher Ballinger. All rights reserved.
//

#import "SOCKS5Proxy.h"
#import "SOCKS5ProxySocket.h"

@interface SOCKS5Proxy()
@property (nonatomic, strong) GCDAsyncSocket *listeningSocket;
@property (nonatomic) dispatch_queue_t listeningQueue;
@property (nonatomic, strong) NSMutableSet *activeSockets;
@property (nonatomic) NSUInteger totalBytesWritten;
@property (nonatomic) NSUInteger totalBytesRead;
@property (nonatomic, strong) NSMutableDictionary *authorizedUsers;

@property (nonatomic, strong) NSString *outgoingHost;
@property (nonatomic, assign) uint16_t outgoingPort;
@property (nonatomic, strong) NSString *outgoingUsername;
@property (nonatomic, strong) NSString *outgoingPassword;

@end

@implementation SOCKS5Proxy

-(void)setOutgoingHost:(NSString*)host port:(uint16_t)port
{
    self.outgoingHost = host;
    self.outgoingPort = port;
}

-(void)setOutgoingSocksUsername:(NSString*)username password:(NSString*)password
{
    self.outgoingUsername = username;
    self.outgoingPassword = password;
}

- (void) dealloc {
    [self disconnect];
}

- (id) init {
    if (self = [super init]) {
        self.listeningQueue = dispatch_queue_create("SOCKS delegate queue", 0);
        self.callbackQueue = dispatch_get_main_queue();
        self.authorizedUsers = [NSMutableDictionary dictionary];
    }
    return self;
}

- (BOOL) startProxy {
    return [self startProxyOnPort:9050];
}

- (BOOL) startProxyOnPort:(uint16_t)port {
    return [self startProxyOnPort:port error:nil];
}

- (BOOL) startProxyOnPort:(uint16_t)port error:(NSError**)error {
    [self disconnect];
    self.listeningSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:self.listeningQueue];
    self.activeSockets = [NSMutableSet set];
    _listeningPort = port;
    return [self.listeningSocket acceptOnPort:port error:error];
}

// SOCKS authorization
// btw this is horribly insecure, especially over the open internet
- (void) addAuthorizedUser:(NSString*)username password:(NSString*)password {
    [self.authorizedUsers setObject:password forKey:username];
}
- (void) removeAuthorizedUser:(NSString*)username {
    [self.authorizedUsers removeObjectForKey:username];
}
- (void) removeAllAuthorizedUsers {
    [self.authorizedUsers removeAllObjects];
}

- (BOOL) checkAuthorizationForUser:(NSString*)username password:(NSString*)password {
    NSString *existingPassword = [self.authorizedUsers objectForKey:username];
    if (!existingPassword.length) {
        return NO;
    }
    return [existingPassword isEqualToString:password];
}

- (void) socket:(GCDAsyncSocket *)sock didAcceptNewSocket:(GCDAsyncSocket *)newSocket {
//    NSLog(@"Accepted new socket: %@", newSocket);
#if TARGET_OS_IPHONE
    [newSocket performBlock:^{
        BOOL enableBackground = [newSocket enableBackgroundingOnSocket];
        if (!enableBackground) {
            NSLog(@"Error enabling background on new socket %@", newSocket);
        } else {
            NSLog(@"Backgrounding enabled for new socket: %@", newSocket);
        }
    }];
#endif
    SOCKS5ProxySocket *proxySocket = [[SOCKS5ProxySocket alloc] initWithSocket:newSocket delegate:self];
    proxySocket.outgoingHost = self.outgoingHost;
    proxySocket.outgoingPort = self.outgoingPort;
    proxySocket.outgoingUsername = self.outgoingUsername;
    proxySocket.outgoingPassword = self.outgoingPassword;
    
    [self.activeSockets addObject:proxySocket];
    
    if (self.delegate && [self.delegate respondsToSelector:@selector(SOCKS5Proxy:clientDidConnect:)]) {
        dispatch_async(self.callbackQueue, ^{
            [self.delegate SOCKS5Proxy:self clientDidConnect:proxySocket];
        });
    }
}

- (NSUInteger) connectionCount {
    return _activeSockets.count;
}

- (void) disconnect {
    [self.activeSockets enumerateObjectsUsingBlock:^(SOCKS5ProxySocket *proxySocket, BOOL * _Nonnull stop) {
        [proxySocket disconnect];
    }];
    self.activeSockets = nil;
    [self.listeningSocket disconnect];
    self.listeningSocket.delegate = nil;
    self.listeningSocket = nil;
}

- (void) proxySocketDidDisconnect:(SOCKS5ProxySocket *)proxySocket withError:(NSError *)error {
    dispatch_async(self.listeningQueue, ^{
        [self.activeSockets removeObject:proxySocket];
    });
    if (self.delegate && [self.delegate respondsToSelector:@selector(SOCKS5Proxy:clientDidDisconnect:)]) {
        dispatch_async(self.callbackQueue, ^{
            [self.delegate SOCKS5Proxy:self clientDidDisconnect:proxySocket];
        });
    }
}

- (void) proxySocket:(SOCKS5ProxySocket *)proxySocket didReadDataOfLength:(NSUInteger)numBytes {
    self.totalBytesRead += numBytes;
}

- (void) proxySocket:(SOCKS5ProxySocket *)proxySocket didWriteDataOfLength:(NSUInteger)numBytes {
    self.totalBytesWritten += numBytes;
}

- (BOOL) proxySocket:(SOCKS5ProxySocket*)proxySocket
checkAuthorizationForUser:(NSString*)username
            password:(NSString*)password {
    return [self checkAuthorizationForUser:username password:password];
}

- (void) resetNetworkStatistics {
    self.totalBytesWritten = 0;
    self.totalBytesRead = 0;
}

@end
