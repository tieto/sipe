//
//  ESSIPELibpurpleServicePlugin.h
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//

#import <Adium/AIPlugin.h>
#import <AdiumLibpurple/AILibpurplePlugin.h>

#import "ESSIPEService.h"

@interface ESSIPELibpurpleServicePlugin : AIPlugin <AILibpurplePlugin> {
	ESSIPEService *SIPEService;
}

@end
