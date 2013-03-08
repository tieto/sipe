//
//  ESSIPELibpurpleServicePlugin.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import <libpurple/debug.h>
#import "ESSIPEService.h"
#import "ESSIPELibpurpleServicePlugin.h"

// C declarations  
extern BOOL AIDebugLoggingIsEnabled();
extern void purple_init_sipe_plugin(void);
extern void purple_debug_set_enabled(gboolean);

@implementation ESSIPELibpurpleServicePlugin

# pragma mark Plugin Load/Install 
- (void)installLibpurplePlugin {
}

- (void)loadLibpurplePlugin 
{
	purple_init_sipe_plugin();

    if(AIDebugLoggingIsEnabled()) {
        purple_debug_set_enabled(true);
        purple_debug_set_verbose(true);
    }
    
}

- (void)installPlugin
{
	[super installPlugin];
	
	[ESSIPEService registerService];
}

- (void)dealloc
{
	[ESSIPEService release];
	[super dealloc];
}

#pragma mark Plugin Metadata
- (NSString *)libpurplePluginPath
{
	return [[NSBundle bundleForClass:[self class]] resourcePath];
}

- (NSString*) pluginAuthor {
    return @"Harris Kauffman, Michael Lamb";
}

- (NSString*) pluginVersion {
    // TODO: Get this dynamically from sipe-core 
    return @"1.15.0";
}

- (NSString*) pluginDescription {
    return @"Allows Adium to connect to Office Communicator accounts";
}

- (NSString*) pluginWebsite {
    // TODO: Get this dynamically from sipe-core 
    return @"sipe.sf.net";
}

@end
