//go:build desktop && darwin

#import <Cocoa/Cocoa.h>
#import <Sparkle/Sparkle.h>
#import <WebKit/WebKit.h>

@interface SCIMTestMenuController : NSObject <NSMenuDelegate>
- (void)reloadPage:(id)sender;
- (void)showReleaseNotes:(id)sender;
- (void)showHelp:(id)sender;
@end

static NSString *SCIMTestReleaseNotesPath(void) {
  return [[NSBundle mainBundle] pathForResource:@"ReleaseNotes" ofType:@"md"];
}

static NSString *SCIMTestReleaseNotesVersion(void) {
  NSString *version = [[NSBundle mainBundle]
      objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  return [version length] > 0 ? version : @"Development Preview";
}

static NSString *SCIMTestReleaseNotes(void) {
  NSString *path = SCIMTestReleaseNotesPath();
  if (path != nil) {
    NSError *error = nil;
    NSString *markdown = [NSString stringWithContentsOfFile:path
                                                    encoding:NSUTF8StringEncoding
                                                       error:&error];
    if (markdown == nil) {
      NSLog(@"Could not read release notes: %@", [error localizedDescription]);
    }
    return markdown;
  }

  NSString *bundleVersion = [[NSBundle mainBundle]
      objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  if ([bundleVersion length] > 0) {
    return nil;
  }

  return @"# A more native scimtest\n"
      "\n"
      "This development preview shows how release notes will appear after "
      "an update.\n"
      "\n"
      "## A proper Mac interface\n"
      "\n"
      "- Redesigned the application with native Mac spacing, controls, and "
      "translucent navigation.\n"
      "- Added automatic light and dark appearances that follow your system "
      "setting.\n"
      "- Replaced the generic sync mark with the scimtest application icon.\n"
      "\n"
      "## Release notes where you need them\n"
      "\n"
      "- What's New opens once when you launch a newly updated version.\n"
      "- You can return to these notes at any time from the Help menu.\n"
      "\n"
      "## Smaller fixes\n"
      "\n"
      "- Kept the toolbar height consistent when large user directories "
      "overflow the window.\n"
      "- Improved sheets, tables, status indicators, and code panes in both "
      "appearances.\n";
}

static NSAttributedString *SCIMTestRenderedReleaseNotes(NSString *markdown) {
  NSMutableAttributedString *result =
      [[[NSMutableAttributedString alloc] init] autorelease];
  NSColor *textColor = [NSColor labelColor];
  NSFont *bodyFont = [NSFont systemFontOfSize:13.0];

  for (NSString *rawLine in [markdown componentsSeparatedByCharactersInSet:
      [NSCharacterSet newlineCharacterSet]]) {
    NSString *line = rawLine;
    NSFont *font = bodyFont;
    NSMutableParagraphStyle *style =
        [[[NSMutableParagraphStyle alloc] init] autorelease];
    [style setParagraphSpacing:7.0];

    if ([line hasPrefix:@"## "]) {
      line = [line substringFromIndex:3];
      font = [NSFont boldSystemFontOfSize:16.0];
      [style setParagraphSpacingBefore:10.0];
      [style setParagraphSpacing:5.0];
    } else if ([line hasPrefix:@"# "]) {
      line = [line substringFromIndex:2];
      font = [NSFont boldSystemFontOfSize:20.0];
      [style setParagraphSpacing:8.0];
    } else if ([line hasPrefix:@"- "]) {
      line = [@"•  " stringByAppendingString:[line substringFromIndex:2]];
      [style setFirstLineHeadIndent:8.0];
      [style setHeadIndent:22.0];
      [style setParagraphSpacing:4.0];
    }

    line = [line stringByReplacingOccurrencesOfString:@"**" withString:@""];
    NSString *renderedLine = [line stringByAppendingString:@"\n"];
    NSDictionary *attributes = @{
      NSFontAttributeName: font,
      NSForegroundColorAttributeName: textColor,
      NSParagraphStyleAttributeName: style,
    };
    NSAttributedString *rendered = [[[NSAttributedString alloc]
        initWithString:renderedLine attributes:attributes] autorelease];
    [result appendAttributedString:rendered];
  }
  return result;
}

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

- (void)showReleaseNotes:(id)sender {
  NSString *markdown = SCIMTestReleaseNotes();
  if (markdown == nil) {
    return;
  }

  NSString *version = SCIMTestReleaseNotesVersion();
  NSString *title = [NSString stringWithFormat:@"What's New in scimtest %@",
                                             version ?: @""];
  NSAlert *alert = [[[NSAlert alloc] init] autorelease];
  [alert setAlertStyle:NSAlertStyleInformational];
  [alert setMessageText:title];
  [alert setInformativeText:@"Here's what changed in this update."];
  [alert addButtonWithTitle:@"Done"];

  NSScrollView *scrollView = [[[NSScrollView alloc]
      initWithFrame:NSMakeRect(0, 0, 560, 330)] autorelease];
  [scrollView setBorderType:NSNoBorder];
  [scrollView setHasVerticalScroller:YES];
  [scrollView setAutohidesScrollers:YES];

  NSTextView *textView = [[[NSTextView alloc]
      initWithFrame:[[scrollView contentView] bounds]] autorelease];
  [textView setEditable:NO];
  [textView setSelectable:YES];
  [textView setDrawsBackground:NO];
  [textView setTextContainerInset:NSMakeSize(4, 8)];
  [textView setMinSize:NSMakeSize(0, 330)];
  [textView setMaxSize:NSMakeSize(CGFLOAT_MAX, CGFLOAT_MAX)];
  [textView setVerticallyResizable:YES];
  [textView setHorizontallyResizable:NO];
  [textView setAutoresizingMask:NSViewWidthSizable];
  [[textView textContainer]
      setContainerSize:NSMakeSize(560, CGFLOAT_MAX)];
  [[textView textContainer] setWidthTracksTextView:YES];
  [[textView textStorage]
      setAttributedString:SCIMTestRenderedReleaseNotes(markdown)];
  [scrollView setDocumentView:textView];
  [alert setAccessoryView:scrollView];

  if ([version length] > 0) {
    [[NSUserDefaults standardUserDefaults]
        setObject:version
          forKey:@"SCIMTestLastPresentedReleaseNotesVersion"];
  }
  [alert runModal];
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
    BOOL isReleaseNotes = [item target] == self &&
        [item action] == @selector(showReleaseNotes:);
    if (!isApplicationHelp && !isReleaseNotes) {
      [menu removeItem:item];
    }
  }
  [items release];
}
@end

static SCIMTestMenuController *scimtestMenuController;
static SPUStandardUpdaterController *scimtestUpdaterController;

static void SCIMTestShowReleaseNotesAfterUpdate(void) {
  NSString *version = [[NSBundle mainBundle]
      objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  if (SCIMTestReleaseNotes() == nil) {
    return;
  }

  if ([version length] == 0) {
    [scimtestMenuController performSelector:@selector(showReleaseNotes:)
                                 withObject:nil
                                 afterDelay:0.75];
    return;
  }

  NSString *key = @"SCIMTestLastPresentedReleaseNotesVersion";
  NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
  if ([[defaults stringForKey:key] isEqualToString:version]) {
    return;
  }

  [scimtestMenuController performSelector:@selector(showReleaseNotes:)
                               withObject:nil
                               afterDelay:0.75];
}

static BOOL SCIMTestCanStartUpdater(void) {
  NSBundle *bundle = [NSBundle mainBundle];
  return [bundle bundleIdentifier] != nil &&
      [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] != nil &&
      [bundle objectForInfoDictionaryKey:@"SUFeedURL"] != nil &&
      [bundle objectForInfoDictionaryKey:@"SUPublicEDKey"] != nil;
}

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
    if (scimtestMenuController == nil) {
      scimtestMenuController = [[SCIMTestMenuController alloc] init];
    }
    [applicationMenu addItem:SCIMTestMenuItem(
        [@"About " stringByAppendingString:applicationName],
        @selector(orderFrontStandardAboutPanel:), @"", 0)];

    NSMenuItem *updateItem = SCIMTestMenuItem(
        @"Check for Updates…", @selector(checkForUpdates:), @"", 0);
    if (SCIMTestCanStartUpdater()) {
      if (scimtestUpdaterController == nil) {
        scimtestUpdaterController = [[SPUStandardUpdaterController alloc]
            initWithStartingUpdater:YES
                  updaterDelegate:nil
               userDriverDelegate:nil];
      }
      [updateItem setTarget:scimtestUpdaterController];
    } else {
      [updateItem setEnabled:NO];
    }
    [applicationMenu addItem:updateItem];
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
    NSMenuItem *releaseNotesItem = SCIMTestMenuItem(
        @"What's New in scimtest", @selector(showReleaseNotes:), @"", 0);
    [releaseNotesItem setTarget:scimtestMenuController];
    [releaseNotesItem setEnabled:SCIMTestReleaseNotes() != nil];
    [helpMenu addItem:releaseNotesItem];
    [helpMenu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *helpItem = SCIMTestMenuItem(
        @"scimtest Help", @selector(showHelp:), @"?", command);
    [helpItem setTarget:scimtestMenuController];
    [helpMenu addItem:helpItem];
    [helpMenu setDelegate:scimtestMenuController];

    [application setMainMenu:mainMenu];
    SCIMTestShowReleaseNotesAfterUpdate();
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

int scimtest_application_menu_has_update_item(void) {
  @autoreleasepool {
    NSMenu *mainMenu = [[NSApplication sharedApplication] mainMenu];
    if ([mainMenu numberOfItems] == 0) {
      return 0;
    }

    NSMenu *applicationMenu = [[mainMenu itemAtIndex:0] submenu];
    for (NSMenuItem *item in [applicationMenu itemArray]) {
      BOOL isUpdate = [item action] == @selector(checkForUpdates:);
      BOOL hasTitle = [[item title] isEqualToString:@"Check for Updates…"];
      if (isUpdate && hasTitle) {
        return 1;
      }
    }
    return 0;
  }
}

int scimtest_application_menu_has_release_notes_item(void) {
  @autoreleasepool {
    NSMenu *mainMenu = [[NSApplication sharedApplication] mainMenu];
    if ([mainMenu numberOfItems] == 0) {
      return 0;
    }

    NSMenu *helpMenu = SCIMTestMenuNamed(mainMenu, @"Help");
    for (NSMenuItem *item in [helpMenu itemArray]) {
      BOOL isReleaseNotes = [item action] == @selector(showReleaseNotes:);
      BOOL hasTitle = [[item title] isEqualToString:@"What's New in scimtest"];
      if (isReleaseNotes && hasTitle) {
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
    BOOL hasHelp = [helpMenu numberOfItems] == 2 &&
        SCIMTestMenuHasItem(
            helpMenu, @"What's New in scimtest",
            @selector(showReleaseNotes:), @"", 0) &&
        SCIMTestMenuHasItem(
            helpMenu, @"scimtest Help", @selector(showHelp:), @"?", command);

    return hasAbout && hasHide && hasHideOthers && hasShowAll && hasServices &&
        hasClose && hasEditing && hasView && hasWindow && hasHelp;
  }
}
