//go:build desktop && darwin

package main

/*
#cgo LDFLAGS: -framework Cocoa -framework WebKit

void scimtest_install_application_menu(void);
int scimtest_application_menu_has_quit_item(void);
int scimtest_application_menu_has_update_item(void);
int scimtest_application_menu_has_release_notes_item(void);
int scimtest_application_menu_is_standard(void);
int scimtest_application_delegate_installs_on_quit(void);
*/
import "C"

func installApplicationMenu() {
	C.scimtest_install_application_menu()
}

func applicationMenuHasQuitItem() bool {
	return C.scimtest_application_menu_has_quit_item() != 0
}

func applicationMenuHasUpdateItem() bool {
	return C.scimtest_application_menu_has_update_item() != 0
}

func applicationMenuHasReleaseNotesItem() bool {
	return C.scimtest_application_menu_has_release_notes_item() != 0
}

func applicationMenuIsStandard() bool {
	return C.scimtest_application_menu_is_standard() != 0
}

func applicationDelegateInstallsOnQuit() bool {
	return C.scimtest_application_delegate_installs_on_quit() != 0
}
