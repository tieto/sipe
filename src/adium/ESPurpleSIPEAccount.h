//
//  ESSIPEAccount.h
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Copyright 2009 Matt Meissner. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <AdiumLibpurple/CBPurpleAccount.h>

#define KEY_SIPE_WINDOWS_LOGIN          @"SIPE:Windows Login"
#define KEY_SIPE_CONNECTION_TYPE        @"SIPE:Connection Type"
#define KEY_SIPE_EMAIL                  @"SIPE:Email"
#define KEY_SIPE_EMAIL_URL              @"SIPE:Email URL"
#define KEY_SIPE_EMAIL_PASSWORD         @"SIPE:Email Password"
#define KEY_SIPE_GROUP_CHAT_PROXY       @"SIPE:Group Chat Proxy"
#define KEY_SIPE_USER_AGENT             @"SIPE:User Agent"

@interface ESPurpleSIPEAccount : CBPurpleAccount <AIAccount_Files> {

}
@end
