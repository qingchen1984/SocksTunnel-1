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
    printf("参数选项说明: r 远程地址:端口, u和p 远程socks用户名及密码[可不传此项],  l 本地本址:端口\n");
    printf("例子: socksTunnel -r 3.3.3.3:2020 -l 127.0.0.1:8888 -u username -p password\n");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        printUsage();
        
        NSString *host;
        NSString *port;
        NSString *username;
        NSString *password;
        NSString *localInterface;
        NSString *localPort;
        
        
        while( 1 )
        {
            int option = getopt(argc, (char**)argv, "r:l:u:p:h");
            if (option == -1) {
                break;
            }
            
            switch (option) {
                case 'r':
                {
                    printf("remote_server: %s\n", optarg);
                    NSString *tmp = [NSString stringWithUTF8String:optarg];
                    NSArray *a = [tmp componentsSeparatedByString:@":"];
                    host = a.firstObject;
                    port = a.lastObject;
                    break;
                }
                case 'l':
                {
                    printf("local_bind: %s\n", optarg);
                    NSString *tmp = [NSString stringWithUTF8String:optarg];
                    NSArray *a = [tmp componentsSeparatedByString:@":"];
                    localInterface = a.firstObject;
                    localPort = a.lastObject;
                    break;
                }
                case 'u':
                {
                    printf("username: %s\n", optarg);
                    NSString *tmp = [NSString stringWithUTF8String:optarg];
                    username = tmp;
                    break;
                }
                case 'p':
                {
                    printf("pasword: %s\n", optarg);
                    NSString *tmp = [NSString stringWithUTF8String:optarg];
                    password = tmp;
                    break;
                }
                default:
                {
                    break;
                }
            }
            
        }
        
        
        SOCKS5Proxy *forwardServer;
        forwardServer = [[SOCKS5Proxy alloc] init];
        [forwardServer setOutgoingHost:host port:port.intValue];
        if (username && password) {
            [forwardServer setOutgoingSocksUsername:username password:password];
        }
        
        uint16_t uport = localPort.intValue;
        
        if([forwardServer startProxyOnPort: uport])
        {
            printf("forward sever working on local port %d ..\n", uport);
            CFRunLoopRun();
        }
        else{
            printf("bind failed at port %d \n", uport);
        }
        
        return 0;
    }
}
