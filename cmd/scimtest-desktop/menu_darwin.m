//go:build desktop && darwin

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface SCIMTestMenuController : NSObject <NSMenuDelegate>
- (void)reloadPage:(id)sender;
- (void)showHelp:(id)sender;
@end

@implementation SCIMTestMenuController
- (void)reloadPage:(id)sender {
  NSWindow *window = [NSApp keyWindow];
  if (window == nil) {
    window = [NSApp mainWindow];
  }
  NSView *contentView = [window contentView];
  if ([contentView isKindOfClass:[WKWebView class]]) {
    [(WKWebView *)contentView reload];
  }
}

- (void)showHelp:(id)sender {
  NSURL *helpURL = [NSURL URLWithString:
      @"https://github.com/rselbach/scimtest#readme"];
  [[NSWorkspace sharedWorkspace] openURL:helpURL];
}

- (void)menuWillOpen:(NSMenu *)menu {
  NSArray<NSMenuItem *> *items = [[menu itemArray] copy];
  for (NSMenuItem *item in items) {
    BOOL isApplicationHelp = [item target] == self &&
        [item action] == @selector(showHelp:);
    if (!isApplicationHelp) {
      [menu removeItem:item];
    }
  }
  [items release];
}
@end

static SCIMTestMenuController *scimtestMenuController;

static NSMenuItem *SCIMTestMenuItem(NSString *title,
                                    SEL action,
                                    NSString *keyEquivalent,
                                    NSEventModifierFlags modifiers) {
  NSMenuItem *item = [[[NSMenuItem alloc]
      initWithTitle:title
             action:action
      keyEquivalent:keyEquivalent] autorelease];
  if ([keyEquivalent length] > 0) {
    [item setKeyEquivalentModifierMask:modifiers];
  }
  return item;
}

static NSMenu *SCIMTestAddMenu(NSMenu *mainMenu, NSString *title) {
  NSMenuItem *menuItem = [[[NSMenuItem alloc]
      initWithTitle:title
             action:nil
      keyEquivalent:@""] autorelease];
  NSMenu *menu = [[[NSMenu alloc] initWithTitle:title] autorelease];
  [menuItem setSubmenu:menu];
  [mainMenu addItem:menuItem];
  return menu;
}

static BOOL SCIMTestMenuHasItem(NSMenu *menu,
                                NSString *title,
                                SEL action,
                                NSString *keyEquivalent,
                                NSEventModifierFlags modifiers) {
  for (NSMenuItem *item in [menu itemArray]) {
    BOOL hasTitle = [[item title] isEqualToString:title];
    BOOL hasAction = [item action] == action;
    BOOL hasKey = [[item keyEquivalent] isEqualToString:keyEquivalent];
    BOOL hasModifiers = [keyEquivalent length] == 0 ||
        [item keyEquivalentModifierMask] == modifiers;
    if (hasTitle && hasAction && hasKey && hasModifiers) {
      return YES;
    }
  }
  return NO;
}

static NSMenu *SCIMTestMenuNamed(NSMenu *mainMenu, NSString *title) {
  NSMenuItem *item = [mainMenu itemWithTitle:title];
  return [item submenu];
}

void scimtest_install_application_menu(void) {
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    NSString *applicationName = @"scimtest";
    NSEventModifierFlags command = NSEventModifierFlagCommand;

    NSMenu *mainMenu = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    NSMenu *applicationMenu = SCIMTestAddMenu(mainMenu, applicationName);
    [applicationMenu addItem:SCIMTestMenuItem(
        [@"About " stringByAppendingString:applicationName],
        @selector(orderFrontStandardAboutPanel:), @"", 0)];
    [applicationMenu addItem:[NSMenuItem separatorItem]];

    NSMenuItem *servicesItem = SCIMTestMenuItem(@"Services", nil, @"", 0);
    NSMenu *servicesMenu = [[[NSMenu alloc] initWithTitle:@"Services"]
        autorelease];
    [servicesItem setSubmenu:servicesMenu];
    [applicationMenu addItem:servicesItem];
    [application setServicesMenu:servicesMenu];
    [applicationMenu addItem:[NSMenuItem separatorItem]];

    [applicationMenu addItem:SCIMTestMenuItem(
        [@"Hide " stringByAppendingString:applicationName],
        @selector(hide:), @"h", command)];
    [applicationMenu addItem:SCIMTestMenuItem(
        @"Hide Others", @selector(hideOtherApplications:), @"h",
        command | NSEventModifierFlagOption)];
    [applicationMenu addItem:SCIMTestMenuItem(
        @"Show All", @selector(unhideAllApplications:), @"", 0)];
    [applicationMenu addItem:[NSMenuItem separatorItem]];

    NSString *quitTitle = [@"Quit " stringByAppendingString:applicationName];
    [applicationMenu addItem:SCIMTestMenuItem(
        quitTitle, @selector(terminate:), @"q", command)];

    NSMenu *fileMenu = SCIMTestAddMenu(mainMenu, @"File");
    [fileMenu addItem:SCIMTestMenuItem(
        @"Close Window", @selector(performClose:), @"w", command)];

    NSMenu *editMenu = SCIMTestAddMenu(mainMenu, @"Edit");
    [editMenu addItem:SCIMTestMenuItem(
        @"Undo", @selector(undo:), @"z", command)];
    [editMenu addItem:SCIMTestMenuItem(
        @"Redo", @selector(redo:), @"z",
        command | NSEventModifierFlagShift)];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItem:SCIMTestMenuItem(
        @"Cut", @selector(cut:), @"x", command)];
    [editMenu addItem:SCIMTestMenuItem(
        @"Copy", @selector(copy:), @"c", command)];
    [editMenu addItem:SCIMTestMenuItem(
        @"Paste", @selector(paste:), @"v", command)];
    [editMenu addItem:SCIMTestMenuItem(
        @"Delete", @selector(delete:), @"", 0)];
    [editMenu addItem:SCIMTestMenuItem(
        @"Select All", @selector(selectAll:), @"a", command)];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItem:SCIMTestMenuItem(
        @"Emoji & Symbols", @selector(orderFrontCharacterPalette:), @" ",
        command | NSEventModifierFlagControl)];

    if (scimtestMenuController == nil) {
      scimtestMenuController = [[SCIMTestMenuController alloc] init];
    }
    NSMenu *viewMenu = SCIMTestAddMenu(mainMenu, @"View");
    NSMenuItem *reloadItem = SCIMTestMenuItem(
        @"Reload Page", @selector(reloadPage:), @"r", command);
    [reloadItem setTarget:scimtestMenuController];
    [viewMenu addItem:reloadItem];
    [viewMenu addItem:[NSMenuItem separatorItem]];
    [viewMenu addItem:SCIMTestMenuItem(
        @"Enter Full Screen", @selector(toggleFullScreen:), @"f",
        command | NSEventModifierFlagControl)];

    NSMenu *windowMenu = SCIMTestAddMenu(mainMenu, @"Window");
    [windowMenu addItem:SCIMTestMenuItem(
        @"Minimize", @selector(performMiniaturize:), @"m", command)];
    [windowMenu addItem:SCIMTestMenuItem(
        @"Zoom", @selector(performZoom:), @"", 0)];
    [windowMenu addItem:[NSMenuItem separatorItem]];
    [windowMenu addItem:SCIMTestMenuItem(
        @"Bring All to Front", @selector(arrangeInFront:), @"", 0)];
    [application setWindowsMenu:windowMenu];

    NSMenu *helpMenu = SCIMTestAddMenu(mainMenu, @"Help");
    NSMenuItem *helpItem = SCIMTestMenuItem(
        @"scimtest Help", @selector(showHelp:), @"?", command);
    [helpItem setTarget:scimtestMenuController];
    [helpMenu addItem:helpItem];
    [helpMenu setDelegate:scimtestMenuController];

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

int scimtest_application_menu_is_standard(void) {
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    NSMenu *mainMenu = [application mainMenu];
    NSArray<NSString *> *titles = @[
      @"scimtest", @"File", @"Edit", @"View", @"Window", @"Help"
    ];
    if ([mainMenu numberOfItems] != [titles count]) {
      return 0;
    }
    for (NSUInteger index = 0; index < [titles count]; index++) {
      if (![[[mainMenu itemAtIndex:index] title]
          isEqualToString:[titles objectAtIndex:index]]) {
        return 0;
      }
    }

    NSEventModifierFlags command = NSEventModifierFlagCommand;
    NSMenu *applicationMenu = SCIMTestMenuNamed(mainMenu, @"scimtest");
    BOOL hasAbout = SCIMTestMenuHasItem(
        applicationMenu, @"About scimtest",
        @selector(orderFrontStandardAboutPanel:), @"", 0);
    BOOL hasHide = SCIMTestMenuHasItem(
        applicationMenu, @"Hide scimtest", @selector(hide:), @"h", command);
    BOOL hasHideOthers = SCIMTestMenuHasItem(
        applicationMenu, @"Hide Others", @selector(hideOtherApplications:),
        @"h", command | NSEventModifierFlagOption);
    BOOL hasShowAll = SCIMTestMenuHasItem(
        applicationMenu, @"Show All", @selector(unhideAllApplications:),
        @"", 0);
    NSMenuItem *servicesItem = [applicationMenu itemWithTitle:@"Services"];
    BOOL hasServices = [servicesItem submenu] == [application servicesMenu];

    NSMenu *fileMenu = SCIMTestMenuNamed(mainMenu, @"File");
    BOOL hasClose = SCIMTestMenuHasItem(
        fileMenu, @"Close Window", @selector(performClose:), @"w", command);

    NSMenu *editMenu = SCIMTestMenuNamed(mainMenu, @"Edit");
    BOOL hasEditing = SCIMTestMenuHasItem(
        editMenu, @"Undo", @selector(undo:), @"z", command) &&
        SCIMTestMenuHasItem(
            editMenu, @"Redo", @selector(redo:), @"z",
            command | NSEventModifierFlagShift) &&
        SCIMTestMenuHasItem(
            editMenu, @"Cut", @selector(cut:), @"x", command) &&
        SCIMTestMenuHasItem(
            editMenu, @"Copy", @selector(copy:), @"c", command) &&
        SCIMTestMenuHasItem(
            editMenu, @"Paste", @selector(paste:), @"v", command) &&
        SCIMTestMenuHasItem(
            editMenu, @"Select All", @selector(selectAll:), @"a", command);

    NSMenu *viewMenu = SCIMTestMenuNamed(mainMenu, @"View");
    BOOL hasView = SCIMTestMenuHasItem(
        viewMenu, @"Reload Page", @selector(reloadPage:), @"r", command) &&
        SCIMTestMenuHasItem(
            viewMenu, @"Enter Full Screen", @selector(toggleFullScreen:),
            @"f", command | NSEventModifierFlagControl);

    NSMenu *windowMenu = SCIMTestMenuNamed(mainMenu, @"Window");
    BOOL hasWindow = windowMenu == [application windowsMenu] &&
        SCIMTestMenuHasItem(
            windowMenu, @"Minimize", @selector(performMiniaturize:), @"m",
            command) &&
        SCIMTestMenuHasItem(
            windowMenu, @"Zoom", @selector(performZoom:), @"", 0) &&
        SCIMTestMenuHasItem(
            windowMenu, @"Bring All to Front", @selector(arrangeInFront:),
            @"", 0);

    NSMenu *helpMenu = SCIMTestMenuNamed(mainMenu, @"Help");
    [helpMenu insertItem:SCIMTestMenuItem(
        @"System Help Item", nil, @"", 0) atIndex:0];
    [[helpMenu delegate] menuWillOpen:helpMenu];
    BOOL hasHelp = [helpMenu numberOfItems] == 1 && SCIMTestMenuHasItem(
            helpMenu, @"scimtest Help", @selector(showHelp:), @"?", command);

    return hasAbout && hasHide && hasHideOthers && hasShowAll && hasServices &&
        hasClose && hasEditing && hasView && hasWindow && hasHelp;
  }
}
