//
//  SOCKS5ProxySocket.m
//  Tether
//
//  Created by Christopher Ballinger on 11/26/13.
//  Copyright (c) 2013 Christopher Ballinger. All rights reserved.
//

#import "NSData+HexString.h"

// Define various socket tags
#define SOCKS_OPEN             20100
#define SOCKS_CONNECT_AUTH_INIT     20101
#define SOCKS_CONNECT_AUTH_USERNAME     20102
#define SOCKS_CONNECT_AUTH_PASSWORD     20103
#define SOCKS_OPEN0             20104

#define SOCKS_CONNECT_INIT     20200
#define SOCKS_CONNECT_IPv4     20201
#define SOCKS_CONNECT_DOMAIN   20202
#define SOCKS_CONNECT_DOMAIN_LENGTH   20212
#define SOCKS_CONNECT_IPv6     20203
#define SOCKS_CONNECT_PORT     20210
#define SOCKS_CONNECT_REPLY    20300
#define SOCKS_INCOMING_READ    20400
#define SOCKS_INCOMING_WRITE   20401
#define SOCKS_OUTGOING_READ    20500
#define SOCKS_OUTGOING_WRITE   20501

// Timeouts
#define TIMEOUT_CONNECT       8.00
#define TIMEOUT_READ          5.00
#define TIMEOUT_TOTAL        80.00

#import "SOCKS5ProxySocket.h"
#import "GCDAsyncProxySocket.h"
#import <CocoaLumberjack.h>
//#import "NSData+HexString.h"

#if DEBUG
static const int ddLogLevel = DDLogLevelAll;
#else
static const int ddLogLevel = DDLogLevelAll;
#endif
#include <arpa/inet.h>

@interface SOCKS5ProxySocket()
@property (nonatomic, strong) GCDAsyncSocket *proxySocket;
@property (nonatomic, strong) GCDAsyncProxySocket *outgoingSocket;
@property (nonatomic) dispatch_queue_t delegateQueue;
@property (nonatomic) NSUInteger totalBytesWritten;
@property (nonatomic) NSUInteger totalBytesRead;
@property (nonatomic, strong) NSString *username;
@end

@implementation SOCKS5ProxySocket

- (void) dealloc {
    [self disconnect];
}

- (id) initWithSocket:(GCDAsyncSocket *)socket delegate:(id<SOCKS5ProxySocketDelegate>)delegate {
    if (self = [super init]) {
        
//        [DDLog addLogger:[DDOSLogger sharedInstance]]; // Uses os_log
        
        _delegate = delegate;
        self.delegateQueue = dispatch_queue_create("SOCKS5ProxySocket socket delegate queue", 0);
        self.callbackQueue = dispatch_queue_create("SOCKS5ProxySocket callback queue", 0);
        self.proxySocket = socket;
        self.proxySocket.delegate = self;
        self.proxySocket.delegateQueue = self.delegateQueue;
        self.outgoingSocket = [[GCDAsyncProxySocket alloc] initWithDelegate:self delegateQueue:self.delegateQueue];
        [self socksOpen];
    }
    return self;
}

- (void) disconnect {
    [self.proxySocket disconnect];
    [self.outgoingSocket disconnect];
    self.proxySocket = nil;
    self.outgoingSocket = nil;
}

- (void) socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    
//    NSLog(@"didReadData: %@ %@", sock, data.hexString);
    
    if (tag == SOCKS_OPEN0) {
        uint8_t *bytes = (uint8_t*)data.bytes;
        uint8_t version = bytes[0];
        uint8_t methodsLength = bytes[1];
        if (version == 5) {
            [sock readDataToLength:methodsLength withTimeout:-1 tag:SOCKS_OPEN];
        }
    }
    else if (tag == SOCKS_OPEN) {
        /*
         The initial greeting from the client is
         
         field 1: SOCKS version number (must be 0x05 for this version)
         field 2: number of authentication methods supported, 1 byte
         field 3: authentication methods, variable length, 1 byte per method supported
         */
        uint8_t *bytes = (uint8_t*)data.bytes;
        //uint8_t version = bytes[0];
        //uint8_t methodsLength = bytes[1];
        // We only bother checking the first supported method
        
        bytes += 2;//by lg
        
        uint8_t firstSupportedMethod = bytes[2];
        uint8_t supportedMethod = 0x00;
        if (firstSupportedMethod == 0x02) { // Password auth
            supportedMethod = firstSupportedMethod;
        }
        //      +-----+--------+
        // NAME | VER | METHOD |
        //      +-----+--------+
        // SIZE |  1  |   1    |
        //      +-----+--------+
        //
        // Note: Size is in bytes
        //
        // Version = 5 (for SOCKS5)
        // Method  = 0 (No authentication, anonymous access)
        NSUInteger responseLength = 2;
        uint8_t *responseBytes = malloc(responseLength * sizeof(uint8_t));
        responseBytes[0] = 5; // VER = SOCKS5
        responseBytes[1] = supportedMethod;
        //            responseBytes[1] = 0x2;
        NSData *responseData = [NSData dataWithBytesNoCopy:responseBytes length:responseLength freeWhenDone:YES];
        [sock writeData:responseData withTimeout:-1 tag:SOCKS_OPEN];
        
        
        if (supportedMethod == 0x00) {
            [sock readDataToLength:4 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_INIT];
        } else if (supportedMethod == 0x02) {
            // read first 2 bytes of socks auth
            [sock readDataToLength:2 withTimeout:-1 tag:SOCKS_CONNECT_AUTH_INIT];
        }
        
        
    } else if (tag == SOCKS_CONNECT_AUTH_INIT) {
        // We don't actually bother checking user/pass
        /*
         For username/password authentication the client's authentication request is
         
         field 1: version number, 1 byte (must be 0x01)
         field 2: username length, 1 byte
         field 3: username
         field 4: password length, 1 byte
         field 5: password
         Server response for username/password authentication:
         
         field 1: version, 1 byte
         field 2: status code, 1 byte.
         0x00 = success
         any other value = failure, connection must be closed
         */
        if (data.length == 2) {
            uint8_t *bytes = (uint8_t*)data.bytes;
            uint8_t version = bytes[0];
            uint8_t usernameLength = bytes[1];
            DDLogVerbose(@"AUTH version %d. Reading username...", version);
            [sock readDataToLength:usernameLength+1 withTimeout:-1 tag:SOCKS_CONNECT_AUTH_USERNAME];
        }
    } else if (tag == SOCKS_CONNECT_AUTH_USERNAME) {
        if (data.length >= 2) {
            NSData *usernameData = [data subdataWithRange:NSMakeRange(0, data.length - 1)];
            NSString *usernameString = [[NSString alloc] initWithData:usernameData encoding:NSUTF8StringEncoding];
            self.username = usernameString;
            DDLogVerbose(@"AUTH username %@", usernameString);
            NSData *passwordLengthData = [data subdataWithRange:NSMakeRange(data.length - 1, 1)];
            if (passwordLengthData.length == 1) {
                uint8_t *passwordLengthBytes = (uint8_t*)passwordLengthData.bytes;
                uint8_t passwordLength = passwordLengthBytes[0];
                DDLogVerbose(@"Reading password of length %d...", passwordLength);
                [sock readDataToLength:passwordLength withTimeout:-1 tag:SOCKS_CONNECT_AUTH_PASSWORD];
            }
        }
    } else if (tag == SOCKS_CONNECT_AUTH_PASSWORD) {
        NSString *passwordString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        uint8_t success[2] = {0x01, 0x00};
        uint8_t failure[2] = {0x01, 0x00};
        NSData* responseData = nil;
        if ([self.delegate proxySocket:self checkAuthorizationForUser:self.username password:passwordString]) {
            responseData = [NSData dataWithBytes:&success length:2];
            [sock writeData:responseData withTimeout:-1 tag:SOCKS_CONNECT_INIT];
            [sock readDataToLength:4 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_INIT];
        } else {
            responseData = [NSData dataWithBytes:&failure length:2];
            [sock writeData:responseData withTimeout:-1 tag:SOCKS_CONNECT_INIT];
            [sock disconnectAfterWriting];
        }
        self.username = nil;
    } else if (tag == SOCKS_CONNECT_INIT) {
        //      +-----+-----+-----+------+------+------+
        // NAME | VER | CMD | RSV | ATYP | ADDR | PORT |
        //      +-----+-----+-----+------+------+------+
        // SIZE |  1  |  1  |  1  |  1   | var  |  2   |
        //      +-----+-----+-----+------+------+------+
        //
        // Note: Size is in bytes
        //
        // Version      = 5 (for SOCKS5)
        // Command      = 1 (for Connect)
        // Reserved     = 0
        // Address Type = 3 (1=IPv4, 3=DomainName 4=IPv6)
        // Address      = P:D (P=LengthOfDomain D=DomainWithoutNullTermination)
        // Port         = 0
        uint8_t *requestBytes = (uint8_t*)[data bytes];
        uint8_t addressType = requestBytes[3];
        if (addressType == 1) {
            [sock readDataToLength:4 withTimeout:-1 tag:SOCKS_CONNECT_IPv4];
        } else if (addressType == 3) {
            [sock readDataToLength:1 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_DOMAIN_LENGTH];
        } else if (addressType == 4) {
            [sock readDataToLength:16 withTimeout:-1 tag:SOCKS_CONNECT_IPv6];
        }
    } else if (tag == SOCKS_CONNECT_IPv4) {
        uint8_t *address = malloc(INET_ADDRSTRLEN * sizeof(uint8_t));
        inet_ntop(AF_INET, data.bytes, (char*) address, INET_ADDRSTRLEN);
        _destinationHost = [[NSString alloc] initWithBytesNoCopy:address length:INET_ADDRSTRLEN encoding:NSUTF8StringEncoding freeWhenDone:YES];
        [sock readDataToLength:2 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_PORT];
    } else if (tag == SOCKS_CONNECT_IPv6) {
        uint8_t *address = malloc(INET6_ADDRSTRLEN * sizeof(uint8_t));
        inet_ntop(AF_INET6, data.bytes, (char*) address, INET6_ADDRSTRLEN);
        _destinationHost = [[NSString alloc] initWithBytesNoCopy:address length:INET6_ADDRSTRLEN encoding:NSUTF8StringEncoding freeWhenDone:YES];
        [sock readDataToLength:2 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_PORT];
    } else if (tag == SOCKS_CONNECT_DOMAIN) {
        _destinationHost = [[NSString alloc] initWithBytes:data.bytes length:data.length encoding:NSUTF8StringEncoding];
        [sock readDataToLength:2 withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_PORT];
    } else if (tag == SOCKS_CONNECT_DOMAIN_LENGTH) {
        uint8_t *bytes = (uint8_t*)data.bytes;
        uint8_t addressLength = bytes[0];
        [sock readDataToLength:addressLength withTimeout:TIMEOUT_CONNECT tag:SOCKS_CONNECT_DOMAIN];
    } else if (tag == SOCKS_CONNECT_PORT) {
        uint16_t rawPort;
        memcpy(&rawPort, [data bytes], 2);
        _destinationPort = NSSwapBigShortToHost(rawPort);
        NSError *error = nil;
        
        [self.outgoingSocket setProxyHost:self.outgoingHost port:self.outgoingPort version: GCDAsyncSocketSOCKSVersion5];
        [self.outgoingSocket setProxyUsername:self.outgoingUsername password:self.outgoingPassword];
        
        [self.outgoingSocket connectToHost:self.destinationHost onPort:self.destinationPort error:&error];
        
        printf("connect: %s:%u\n", self.outgoingHost.UTF8String, self.outgoingPort);
        
    } else if (tag == SOCKS_INCOMING_READ) {

        
        [self.outgoingSocket writeData:data withTimeout:-1 tag:SOCKS_OUTGOING_WRITE];
        [self.proxySocket readDataWithTimeout:-1 tag:SOCKS_INCOMING_READ];
        
        NSUInteger dataLength = data.length;
        self.totalBytesWritten += dataLength;
        if (self.delegate && [self.delegate respondsToSelector:@selector(proxySocket:didWriteDataOfLength:)]) {
            dispatch_async(self.callbackQueue, ^{
                [self.delegate proxySocket:self didWriteDataOfLength:dataLength];
            });
        }
    } else if (tag == SOCKS_OUTGOING_READ) {
        [self.proxySocket writeData:data withTimeout:-1 tag:SOCKS_INCOMING_WRITE];
        [self.outgoingSocket readDataWithTimeout:-1 tag:SOCKS_OUTGOING_READ];
        
        NSUInteger dataLength = data.length;
        self.totalBytesRead += dataLength;
        if (self.delegate && [self.delegate respondsToSelector:@selector(proxySocket:didReadDataOfLength:)]) {
            dispatch_async(self.callbackQueue, ^{
                [self.delegate proxySocket:self didReadDataOfLength:dataLength];
            });
        }
    }
}

-(void)socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag
{
    if (tag == SOCKS_OUTGOING_WRITE) {
        [self.outgoingSocket readDataWithTimeout:-1 tag:SOCKS_OUTGOING_READ];
        NSAssert(sock == self.outgoingSocket, nil);
    }
    else if(tag == SOCKS_INCOMING_WRITE)
    {
        [self.proxySocket readDataWithTimeout:-1 tag:SOCKS_INCOMING_READ];
    }
}


- (void)socksOpen
{
	//      +-----+-----------+---------+
	// NAME | VER | NMETHODS  | METHODS |
	//      +-----+-----------+---------+
	// SIZE |  1  |    1      | 1 - 255 |
	//      +-----+-----------+---------+
	//
	// Note: Size is in bytes
	//
	// Version    = 5 (for SOCKS5)
	// NumMethods = 1
	// Method     = 0 (No authentication, anonymous access)
    
    [self.proxySocket readDataToLength:2 withTimeout:TIMEOUT_CONNECT tag:SOCKS_OPEN0];
}

- (void) socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    
    NSLog(@"%@", err);

    if (self.delegate && [self.delegate respondsToSelector:@selector(proxySocketDidDisconnect:withError:)]) {
        dispatch_async(self.callbackQueue, ^{
            [self.delegate proxySocketDidDisconnect:self withError:err];
        });
    }
    
    if (sock == self.outgoingSocket) {
        NSLog(@"outgoing socket closed, force disconnect proxy client now!");
//        [self.proxySocket disconnect];
    }else if(sock == self.proxySocket)
    {
        NSLog(@"proxy socket closed, force disconnect outgoin now!");
//        [self.outgoingSocket disconnect];
    }
    
}

- (void) socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
    // We write out 5 bytes which we expect to be:
    // 0: ver  = 5
    // 1: rep  = 0
    // 2: rsv  = 0
    // 3: atyp = 3
    // 4: size = size of addr field
    NSUInteger hostLength = [host lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    NSUInteger responseLength = 5 + hostLength + 2;
    uint8_t *responseBytes = malloc(responseLength * sizeof(uint8_t));
    responseBytes[0] = 5;
    responseBytes[1] = 0;
    responseBytes[2] = 0;
    responseBytes[3] = 3;
    responseBytes[4] = (uint8_t)hostLength;
    memcpy(responseBytes+5, [host UTF8String], hostLength);
    uint16_t bigEndianPort = NSSwapHostShortToBig(port);
    NSUInteger portLength = 2;
	memcpy(responseBytes+5+hostLength, &bigEndianPort, portLength);
    NSData *responseData = [NSData dataWithBytesNoCopy:responseBytes length:responseLength freeWhenDone:YES];
    
    NSLog(@"%@", responseData.debugDescription);
    [self.proxySocket writeData:responseData withTimeout:-1 tag:SOCKS_CONNECT_REPLY];
    [self.proxySocket readDataWithTimeout:-1 tag:SOCKS_INCOMING_READ];
}

@end
