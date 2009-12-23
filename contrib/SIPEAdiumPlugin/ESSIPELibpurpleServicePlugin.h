//
//  ESSIPELibpurpleServicePlugin.h
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Copyright 2009 Matt Meissner. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Adium/AIPlugin.h>
#import <AdiumLibpurple/AILibpurplePlugin.h>

#import "ESSIPEService.h"

@interface ESSIPELibpurpleServicePlugin : AIPlugin <AILibpurplePlugin> {
	ESSIPEService *SIPEService;
}

@end
