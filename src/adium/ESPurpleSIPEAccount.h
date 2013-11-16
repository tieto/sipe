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


// TODO: Remove when sipe_status_activity_to_token calls work
#define SIPE_ACTIVITY_NUM_TYPES 17
static struct
{
	const gchar *status_id;
	const gchar *desc;
} const sipe_activity_map[SIPE_ACTIVITY_NUM_TYPES] = {
    /* SIPE_ACTIVITY_UNSET       */ { "unset",                     NULL                            },
    /* SIPE_ACTIVITY_AVAILABLE   */ { "available",                 NULL                            },
    /* SIPE_ACTIVITY_ONLINE      */ { "online",                    NULL                            },
    /* SIPE_ACTIVITY_INACTIVE    */ { "idle",                      N_("Inactive")                  },
    /* SIPE_ACTIVITY_BUSY        */ { "busy",                      N_("Busy")                      },
    /* SIPE_ACTIVITY_BUSYIDLE    */ { "busyidle",                  N_("Busy-Idle")                 },
    /* SIPE_ACTIVITY_DND         */ { "do-not-disturb",            NULL                            },
    /* SIPE_ACTIVITY_BRB         */ { "be-right-back",             N_("Be right back")             },
    /* SIPE_ACTIVITY_AWAY        */ { "away",                      NULL                            },
    /* SIPE_ACTIVITY_LUNCH       */ { "out-to-lunch",              N_("Out to lunch")              },
    /* SIPE_ACTIVITY_INVISIBLE   */ { "invisible",                 NULL                            },
    /* SIPE_ACTIVITY_OFFLINE     */ { "offline",                   NULL                            },
    /* SIPE_ACTIVITY_ON_PHONE    */ { "on-the-phone",              N_("In a call")                 },
    /* SIPE_ACTIVITY_IN_CONF     */ { "in-a-conference",           N_("In a conference")           },
    /* SIPE_ACTIVITY_IN_MEETING  */ { "in-a-meeting",              N_("In a meeting")              },
    /* SIPE_ACTIVITY_OOF         */ { "out-of-office",             N_("Out of office")             },
    /* SIPE_ACTIVITY_URGENT_ONLY */ { "urgent-interruptions-only", N_("Urgent interruptions only") },
};


@interface ESPurpleSIPEAccount : CBPurpleAccount <AIAccount_Files> {

}
@end
