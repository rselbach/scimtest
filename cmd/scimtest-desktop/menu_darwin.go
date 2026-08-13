//go:build desktop && darwin

package main

/*
#cgo LDFLAGS: -framework Cocoa

void scimtest_install_application_menu(void);
int scimtest_application_menu_has_quit_item(void);
*/
import "C"

func installApplicationMenu() {
	C.scimtest_install_application_menu()
}

func applicationMenuHasQuitItem() bool {
	return C.scimtest_application_menu_has_quit_item() != 0
}
