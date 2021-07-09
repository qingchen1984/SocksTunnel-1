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
#import <CocoaLumberjack/CocoaLumberjack.h>
#import <CocoaLumberjack/DDOSLogger.h>

void printUsage()
{
    printf("Socks5 转发管道服务,用以连接本地和远程socks5\n");
    printf("SocksTunnel -r remote_host:remote_port [-l localport] [-a username:password]\n");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        //[DDLog addLogger:[DDOSLogger sharedInstance]];
        
        NSString *host;
        NSString *port;
        NSString *username;
        NSString *password;
        
        NSString *localInterface;
        NSString *localPort;
        
        while( 1 )
        {
            int option = getopt(argc, (char**)argv, "r:l:a:");
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
                    if (a.count > 0) {
                        localInterface = a.firstObject;
                        localPort = a.lastObject;
                    }else{
                        localPort = tmp;
                    }
                    
                    break;
                }
                case 'a':
                {
                    printf("username password: %s\n", optarg);
                    NSString *tmp = [NSString stringWithUTF8String:optarg];
                    NSArray *a = [tmp componentsSeparatedByString:@":"];
                    username = a.firstObject;
                    password = a.lastObject;
                    break;
                }
                default:
                {
                    printUsage();
                    return 0;
                }
            }
        }
        
        if (host.length > 0 && port.length > 0) {
            

            SOCKS5Proxy *forwardServer;
            forwardServer = [[SOCKS5Proxy alloc] init];
            [forwardServer setOutgoingHost:host port:port.intValue];
            
            if (username.length > 0 && password.length > 0) {
                [forwardServer setOutgoingSocksUsername:username password:password];
            }
            
            uint16_t uport;
            if(localPort)
            {
                uport = localPort.intValue;
            }else{
                uport = random() % 1000 + 5000;
            }

            printf("\n");
            
            if([forwardServer startProxyOnPort: uport])
            {
                printf("forward sever working on local port %d ..\n", uport);
                CFRunLoopRun();
            }
            else{
                printf("bind failed at port %d.\n", uport);
                char *p = "sadf";
                if (getchar() == 0) {
                    p = 0;
                }
                
                char *cc = p;
                printf("%s, %s.", cc, p);
            }

        }
        else{
            printUsage();
        }

        return 0;
    }
}
