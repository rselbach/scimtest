//go:build desktop && darwin

#import <Cocoa/Cocoa.h>

void scimtest_install_application_menu(void) {
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    NSString *applicationName = @"scimtest";

    NSMenu *mainMenu = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    NSMenuItem *applicationMenuItem = [[[NSMenuItem alloc]
        initWithTitle:applicationName
               action:nil
        keyEquivalent:@""] autorelease];
    [mainMenu addItem:applicationMenuItem];

    NSMenu *applicationMenu = [[[NSMenu alloc]
        initWithTitle:applicationName] autorelease];
    NSString *quitTitle = [@"Quit " stringByAppendingString:applicationName];
    NSMenuItem *quitItem = [[[NSMenuItem alloc]
        initWithTitle:quitTitle
               action:@selector(terminate:)
        keyEquivalent:@"q"] autorelease];
    [quitItem setKeyEquivalentModifierMask:NSEventModifierFlagCommand];
    [applicationMenu addItem:quitItem];
    [applicationMenuItem setSubmenu:applicationMenu];
    [application setMainMenu:mainMenu];
  }
}

int scimtest_application_menu_has_quit_item(void) {
  @autoreleasepool {
    NSMenu *mainMenu = [[NSApplication sharedApplication] mainMenu];
    if (mainMenu.numberOfItems == 0) {
      return 0;
    }

    NSMenu *applicationMenu = [[mainMenu itemAtIndex:0] submenu];
    if (![[mainMenu itemAtIndex:0].title isEqualToString:@"scimtest"]) {
      return 0;
    }
    for (NSMenuItem *item in applicationMenu.itemArray) {
      BOOL isQuit = item.action == @selector(terminate:);
      BOOL hasQuitTitle = [item.title isEqualToString:@"Quit scimtest"];
      BOOL hasQShortcut = [item.keyEquivalent isEqualToString:@"q"];
      BOOL hasCommand = (item.keyEquivalentModifierMask &
                         NSEventModifierFlagCommand) != 0;
      if (isQuit && hasQuitTitle && hasQShortcut && hasCommand) {
        return 1;
      }
    }
    return 0;
  }
}
