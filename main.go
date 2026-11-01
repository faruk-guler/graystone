package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"graystone/internal/sessionstore"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()
	// WebView2 stores localStorage in a folder named after the executable unless
	// told otherwise, so a rebuild under a different file name would silently drop
	// the saved theme, font size and pane width. Pin the profile to the app's own
	// config folder instead, which is named after the product.
	//
	// Creating that folder is still skipped when the Wails CLI runs this binary
	// merely to generate the JS bindings: a build must never touch the machine it
	// happens to run on, and no webview exists there to need the path.
	userData := ""
	if !runningForBindings() {
		if dir, err := sessionstore.DefaultDir(); err == nil {
			userData = dir
		}
	}
	err := wails.Run(&options.App{
		Title:            "Graystone",
		Width:            1280,
		Height:           800,
		MinWidth:         900,
		MinHeight:        600,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 17, G: 17, B: 17, A: 1},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		// Files may be dropped from Explorer onto the window: the file pane takes
		// them as an upload and the terminal takes them as a path to type. The
		// coordinates decide, so the handler lives in the frontend (OnFileDrop in
		// frontend/src/main.js), and the two drop targets are marked in style.css
		// with the default --wails-drop-target property. The webview's own drop is
		// switched off: without it, dropping a file would navigate the app to that
		// file and lose every open terminal. Dragging out of the window is not
		// offered - WebView2 has no native drag source - so a download still goes
		// through the row's download button and its save dialog.
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop:     true,
			DisableWebViewDrop: true,
		},
		// One window per machine, because two of them both write sessions.json and
		// known_hosts.json and the later save silently erases the other's servers
		// or trusted keys. The second process exits without a window of its own,
		// so raise the one that is already there - otherwise a double click looks
		// exactly like an app that failed to start. The id is shared by dev and
		// release builds, so close the running Graystone before `wails dev`.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "graystone",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				runtime.WindowUnminimise(app.ctx)
				runtime.WindowShow(app.ctx)
			},
		},
		// WebView2's built-in zoom stays off (IsZoomControlEnabled defaults to
		// false) and pinch zoom is switched off too: Wails exposes no
		// MinimumZoomFactor/MaximumZoomFactor, so the webview would zoom without
		// bounds. Graystone deliberately offers no zoom at all - resizing the
		// terminal widget without the remote acknowledging the new size garbles
		// line wrapping - see ZOOM_KEY in frontend/src/main.js.
		Windows: &windows.Options{
			DisablePinchZoom: true,
			// Empty would fall back to %APPDATA%\[BinaryName.exe], which is what
			// made the stored preferences disappear whenever the executable was
			// rebuilt under a new name.
			WebviewUserDataPath: userData,
		},
	})
	if err != nil {
		println("Graystone error:", err.Error())
	}
}
