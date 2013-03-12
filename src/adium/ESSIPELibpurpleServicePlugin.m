//
//  ESSIPELibpurpleServicePlugin.m
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

//#import <libpurple/libpurple.h>
#import "ESSIPEService.h"
#import "ESSIPELibpurpleServicePlugin.h"

//#include "sipe-core.h"

extern void purple_init_sipe_plugin(void);

@implementation ESSIPELibpurpleServicePlugin

# pragma mark Plugin Load/Install 
- (void)installLibpurplePlugin {
}

- (void)loadLibpurplePlugin 
{
	purple_init_sipe_plugin();
    // TODO: Check that Adium is in debug mode rather than blindly enabling
    purple_debug_set_enabled(true);
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
    return @"Harris Kauffman/Michael Lamb";
}

- (NSString*) pluginVersion {
    // TODO: Get this dynamically from the sipe-core release version
    return @"1.13.3";
}

- (NSString*) pluginDescription {
    return @"Allows Adium to connect to Office Communicator accounts";
}

- (NSString*) pluginWebsite {
    return @"sipe.sf.net";
}

@end
