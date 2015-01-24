//
//  ESSIPELibpurpleServicePlugin.m
//  SIPEAdiumPlugin
//
//  Copyright (C) 2015 SIPE Project <http://sipe.sourceforge.net/>
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import "ESSIPEService.h"
#import "ESSIPELibpurpleServicePlugin.h"

// C declarations  
extern void purple_init_sipe_plugin(void);

@implementation ESSIPELibpurpleServicePlugin

# pragma mark Plugin Load/Install 
- (void)installLibpurplePlugin {
}

- (void)loadLibpurplePlugin 
{
}

- (void)installPlugin
{
	purple_init_sipe_plugin();
	[ESSIPEService registerService];
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
    return @PACKAGE_VERSION;
}

- (NSString*) pluginDescription {
    return @"Allows Adium to connect to Office Communicator accounts";
}

- (NSString*) pluginWebsite {
    return @PACKAGE_URL;
}

@end
