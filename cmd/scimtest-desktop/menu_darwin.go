//go:build desktop && darwin

package main

/*
#cgo CFLAGS: -F${SRCDIR}/../../build/sparkle
#cgo LDFLAGS: -F${SRCDIR}/../../build/sparkle -framework Cocoa
#cgo LDFLAGS: -framework Sparkle -framework WebKit

void scimtest_install_application_menu(void);
int scimtest_application_menu_has_quit_item(void);
int scimtest_application_menu_has_update_item(void);
int scimtest_application_menu_is_standard(void);
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

func applicationMenuIsStandard() bool {
	return C.scimtest_application_menu_is_standard() != 0
}
