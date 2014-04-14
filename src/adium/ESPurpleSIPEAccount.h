//
//  ESSIPEAccount.h
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import <AdiumLibpurple/CBPurpleAccount.h>

#define KEY_SIPE_WINDOWS_LOGIN          @"SIPE:Windows Login"
#define KEY_SIPE_CONNECT_HOST           @"SIPE:Connect Host"
#define KEY_SIPE_PASSWORD               @"SIPE:Password"  // TODO: Do we need to keep this key? PurpleAccount should store this for us
#define KEY_SIPE_CONNECTION_TYPE        @"SIPE:Connection Type"
#define KEY_SIPE_EMAIL                  @"SIPE:Email"
#define KEY_SIPE_EMAIL_LOGIN            @"SIPE:Email Login"
#define KEY_SIPE_EMAIL_URL              @"SIPE:Email URL"
#define KEY_SIPE_EMAIL_PASSWORD         @"SIPE:Email Password"
#define KEY_SIPE_GROUP_CHAT_PROXY       @"SIPE:Group Chat Proxy"
#define KEY_SIPE_USER_AGENT             @"SIPE:User Agent"
#define KEY_SIPE_SINGLE_SIGN_ON         @"SIPE:Single Sign On"
#define KEY_SIPE_DONT_PUBLISH           @"SIPE:Dont Publish"
#define KEY_SIPE_AUTH_SCHEME            @"SIPE:Authentication Scheme"
#define KEY_SIPE_AUTODISCOVER           @"SIPE:Autodiscover"
#define KEY_SIPE_BEAST_DISABLE          @"SIPE:BEAST Disable"

#define PURPLE_SSL_CDSA_BEAST_TLS_WORKAROUND "ssl_cdsa_beast_tls_workaround"


@interface ESPurpleSIPEAccount : CBPurpleAccount <AIAccount_Files> {
    NSDictionary *adium_to_sipe_status;
    NSDictionary *sipe_to_adium_status;
}
@end
