//
//  main.m
//  SocksTunnel
//
//  Created by apple on 2019/10/15.
//  Copyright © 2019 apple. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <GCDAsyncSocket.h>
#import <GCDAsyncProxySocket.h>
#import "SOCKS5Proxy.h"


void printUsage()
{
    printf("SocksTunnel host port username password local_bind_port \n");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        
        if (argc == 6) {
            
            
            
            for (int i = 0; i < argc; i++) {
                NSLog(@"argc: %s", argv[i]);
            }
            
            
            const char *host_ = argv[1];
            const char *port_ = argv[2];
            
            const char *username_ = argv[3];
            const char *password_ = argv[4];
            
            const char *local_ = argv[5];
            
            NSString *host = [NSString stringWithUTF8String:host_];
            NSString *port = [NSString stringWithUTF8String:port_];
            NSString *username = [NSString stringWithUTF8String:username_];
            NSString *password = [NSString stringWithUTF8String:password_];
            NSString *local = [NSString stringWithUTF8String:local_];
            
            
            
            SOCKS5Proxy *forwardServer;
            forwardServer = [[SOCKS5Proxy alloc] init];
            [forwardServer setOutgoingHost:host port:port.intValue];
            [forwardServer setOutgoingSocksUsername:username password:password];
            [forwardServer startProxyOnPort:local.intValue];
            
            NSLog(@"forward sever working..");
            
            CFRunLoopRun();
        }
        else{
            printUsage();
        }
        
    }
    return 0;
}

