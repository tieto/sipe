//
//  ESSIPEAccountViewController.h
//  SIPEAdiumPlugin
//
//  Created by Matt Meissner on 10/30/09.
//  Modified by Michael Lamb on 2/27/13
//  Copyright 2013 Michael Lamb/Harris Kauffman. All rights reserved.
//


#import <Adium/AIAccountViewController.h>
#import <AdiumLibpurple/PurpleAccountViewController.h>

@interface ESSIPEAccountViewController : PurpleAccountViewController {

    IBOutlet    NSTextField     *textField_windowsLogin;
    IBOutlet    NSTextField     *textField_server;
    IBOutlet	NSTextField		*textField_userAgent;
	IBOutlet	NSTextField		*textField_emailURL;
	IBOutlet	NSTextField		*textField_email;
	IBOutlet	NSTextField		*textField_emailLogin;
	IBOutlet	NSTextField		*textField_emailPassword;
	IBOutlet	NSTextField		*textField_groupchatUser;
    
    IBOutlet	NSButton		*checkBox_autoDiscover;
    IBOutlet	NSButton		*checkBox_singleSignOn;
    IBOutlet	NSButton		*checkbox_dontPublish;
    IBOutlet	NSButton		*checkbox_beastDisable;
    
	IBOutlet	NSPopUpButton	*popup_connectionType;
   	IBOutlet	NSPopUpButton	*popup_authenticationScheme;
    
    NSDictionary *sipe_key_to_gui;
}


@end
