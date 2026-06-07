#import "TLS13URLProtocol.h"
#import <UIKit/UIKit.h>
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

// Include the dynamic bundle built by the Makefile/Python generation script
#include "certs_bundle.h"

@implementation TLS13URLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *scheme = [[request URL] scheme];
    if ([scheme caseInsensitiveCompare:@"https"] == NSOrderedSame) {
        if ([NSURLProtocol propertyForKey:@"TLS13Handled" inRequest:request]) {
            return NO;
        }
        return YES;
    }
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)sendLog:(NSString *)msg {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"TLS13LogNotification" object:msg];
}

- (void)startLoading {
    NSMutableURLRequest *newRequest = [self.request mutableCopy];
    [NSURLProtocol setProperty:[NSNumber numberWithBool:YES] forKey:@"TLS13Handled" inRequest:newRequest];
    NSURL *url = [newRequest URL];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self performTLS13Fetch:url];
    });
}

- (void)performTLS13Fetch:(NSURL *)url {
    NSString *host = [url host];
    NSString *path = [url path];
    if (path.length == 0) path = @"/";
    if ([url query]) path = [path stringByAppendingFormat:@"?%@", [url query]];

    [self sendLog:[NSString stringWithFormat:@"Connecting to host: %@", host]];

    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;
    
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&cacert);
    
    if (psa_crypto_init() != 0) {
        [self sendLog:@"Fatal: PSA Crypto Init Failed"];
        NSError *err = [NSError errorWithDomain:@"TLS13_PSA" code:501 userInfo:nil];
        [self.client URLProtocol:self didFailWithError:err];
        [self.client URLProtocolDidFinishLoading:self];
        return;
    }
    
    int certCount = 0;
    for (int i = 0; ca_certs_bundle[i] != 0; i++) {
        if (mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ca_certs_bundle[i], strlen(ca_certs_bundle[i]) + 1) == 0) {
            certCount++;
        }
    }
    [self sendLog:[NSString stringWithFormat:@"Loaded %d CA anchors.", certCount]];
    
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    
    if (mbedtls_net_connect(&server_fd, [host UTF8String], "443", MBEDTLS_NET_PROTO_TCP) != 0) {
        [self sendLog:@"Error: TCP Socket Connection Failed"];
        NSError *err = [NSError errorWithDomain:@"TLS13" code:500 userInfo:nil];
        [self.client URLProtocol:self didFailWithError:err];
        [self.client URLProtocolDidFinishLoading:self]; 
        mbedtls_x509_crt_free(&cacert);
        return;
    }
    
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    const char *alpn_protocols[] = { "http/1.1", NULL };
    mbedtls_ssl_conf_alpn_protocols(&conf, alpn_protocols);
    
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); 
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, [host UTF8String]);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            [self sendLog:[NSString stringWithFormat:@"Fatal Handshake Error: %d", ret]];
            mbedtls_net_free(&server_fd);
            mbedtls_x509_crt_free(&cacert);
            NSError *err = [NSError errorWithDomain:@"TLS13_Handshake" code:ret userInfo:nil];
            [self.client URLProtocol:self didFailWithError:err];
            [self.client URLProtocolDidFinishLoading:self]; 
            return;
        }
    }
    [self sendLog:@"TLS 1.3 Handshake SUCCESSFUL!"];
    
    // Modernized minimal HTTP/1.1 payload string targeting standard endpoints
    NSString *getPayload = [NSString stringWithFormat:
        @"GET %@ HTTP/1.1\r\n"
        "Host: %@\r\n"
        "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46\r\n"
        "Accept: text/html,*/*\r\n"
        "Accept-Encoding: identity\r\n"
        "Connection: close\r\n\r\n", 
        path, host];
        
    const char *req_str = [getPayload UTF8String];
    mbedtls_ssl_write(&ssl, (const unsigned char *)req_str, strlen(req_str));
    
    NSMutableData *rawResponse = [[NSMutableData alloc] init];
    unsigned char buf[1024];
    
    [self sendLog:@"Entering mbedtls_ssl_read loop..."];
    
    while (1) {
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret == -0x7B00) { // MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            continue; 
        }
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
            break;
        }
        if (ret < 0) {
            [self sendLog:[NSString stringWithFormat:@"Read error: 0x%04X", -ret]];
            break;
        }
        [rawResponse appendBytes:buf length:ret];
    }
    
    [self sendLog:[NSString stringWithFormat:@"Downloaded %lu raw bytes.", (unsigned long)[rawResponse length]]];
    
    // Clean up SSL engine assets safely
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);
    
    // --- ROBUST HTTP STATE PARSER ENGINE ---
    NSInteger statusCode = 200;
    NSMutableDictionary *headerDict = [[NSMutableDictionary alloc] init];
    NSData *bodyData = nil;
    
    // Convert response to string up to header boundary safely to parse lines
    NSString *responseString = [[NSString alloc] initWithData:rawResponse encoding:NSUTF8StringEncoding];
    
    if (!responseString) {
        // Fallback if binary mapping issues occur
        responseString = [[NSString alloc] initWithData:rawResponse encoding:NSASCIIStringEncoding];
    }
    
    if (responseString.length > 0) {
        // Uniform parsing across both \r\n and \n boundaries
        NSArray *lines = [responseString componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        NSInteger bodyLineIndex = 0;
        BOOL parsingHeaders = YES;
        
        for (NSInteger i = 0; i < lines.count; i++) {
            NSString *line = [lines objectAtIndex:i];
            
            // Clean out potential tracking whitespace issues
            line = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            
            if (i == 0) {
                // Parse HTTP Status Line (e.g., HTTP/1.1 302 Found)
                NSArray *statusParts = [line componentsSeparatedByString:@" "];
                if (statusParts.count > 1) {
                    statusCode = [[statusParts objectAtIndex:1] integerValue];
                }
                continue;
            }
            
            if (parsingHeaders) {
                if (line.length == 0) {
                    // Empty line signifies the header boundary end
                    parsingHeaders = NO;
                    bodyLineIndex = i + 1;
                    continue;
                }
                
                NSRange colonRange = [line rangeOfString:@":"];
                if (colonRange.location != NSNotFound) {
                    NSString *key = [[line substringToIndex:colonRange.location] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    NSString *value = [[line substringFromIndex:colonRange.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    if (key.length > 0 && value.length > 0) {
                        [headerDict setObject:value forKey:key];
                    }
                }
            } else {
                // Break early once body segment boundary hits to handle raw data array mapping safely
                break;
            }
        }
        
        // Re-locate body offset cleanly via binary markers instead of relying on string indices
        NSData *headerSeparator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange sepRange = [rawResponse rangeOfData:headerSeparator options:0 range:NSMakeRange(0, [rawResponse length])];
        if (sepRange.location == NSNotFound) {
            headerSeparator = [@"\n\n" dataUsingEncoding:NSUTF8StringEncoding];
            sepRange = [rawResponse rangeOfData:headerSeparator options:0 range:NSMakeRange(0, [rawResponse length])];
        }
        
        if (sepRange.location != NSNotFound) {
            NSUInteger bodyOffset = sepRange.location + sepRange.length;
            bodyData = [rawResponse subdataWithRange:NSMakeRange(bodyOffset, [rawResponse length] - bodyOffset)];
        }
    }
    
    if (!bodyData) {
        bodyData = rawResponse; // Fallback to avoid empty documents
    }
    
    [self sendLog:[NSString stringWithFormat:@"Parsed HTTP Status: %ld", (long)statusCode]];
    [self sendLog:[NSString stringWithFormat:@"Extracted Body: %lu bytes", (unsigned long)[bodyData length]]];
    
    // REDIRECT INTERACTION PIPELINE
    if (statusCode >= 300 && statusCode < 400) {
        NSString *location = [headerDict objectForKey:@"Location"] ?: [headerDict objectForKey:@"location"];
        if (location) {
            [self sendLog:[NSString stringWithFormat:@"Handling tracking redirect -> %@", location]];
            NSURL *redirectURL = [NSURL URLWithString:location relativeToURL:url];
            NSMutableURLRequest *redirectRequest = [NSMutableURLRequest requestWithURL:redirectURL];
            
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.client URLProtocol:self wasRedirectedToRequest:redirectRequest redirectResponse:[[NSHTTPURLResponse alloc] initWithURL:url statusCode:statusCode HTTPVersion:@"HTTP/1.1" headerFields:headerDict]];
            });
            return;
        }
    }
    
    if (![headerDict objectForKey:@"Content-Type"] && ![headerDict objectForKey:@"content-type"]) {
        [headerDict setObject:@"text/html; charset=utf-8" forKey:@"Content-Type"];
    }
    
    NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:url statusCode:statusCode HTTPVersion:@"HTTP/1.1" headerFields:headerDict];
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
        if (bodyData && [bodyData length] > 0) {
            [self.client URLProtocol:self didLoadData:bodyData];
        }
        [self.client URLProtocolDidFinishLoading:self];
    });
}

- (void)stopLoading {
}

@end
