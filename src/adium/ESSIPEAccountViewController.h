//
//  ESSIPEAccountViewController.h
//  SIPEAdiumPlugin
//
//  Created by Matthew Duggan on 10/12/23.
//  Copyright 2010 Matthew Duggan. All rights reserved.
//

#import <Adium/AIAccountViewController.h>
#import "PurpleAccountViewController.h"

@interface ESSIPEAccountViewController : PurpleAccountViewController {
	IBOutlet NSPopUpButton	*popUp_conntype;
    
    IBOutlet NSMenu *menu_connectionType;
    
    IBOutlet NSTextField *textField_windowsLogin;
    
    IBOutlet NSTextField *textField_userAgent;
}


@end
