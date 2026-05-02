package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var trayIcon []byte

func main() {
	if hasLaunchArg("--core") {
		if err := runCoreMain(); err != nil {
			log.Fatal(err)
		}
		return
	}

	recoverBrokenSingleInstance("com.novaproxy.desktop")

	app := NewApp()

	wailsApp := application.New(application.Options{
		Name:        "novaproxy",
		Description: "NovaProxy - Cloudflare IP Shaper",
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Services: []application.Service{
			application.NewService(app),
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "com.novaproxy.desktop",
			OnSecondInstanceLaunch: func(data application.SecondInstanceData) {
				app.RevealMainWindow()
			},
			ExitCode: 0,
		},
	})

	app.wailsApp = wailsApp

	// Create Tray
	tray := wailsApp.SystemTray.New()
	tray.SetIcon(trayIcon)
	tray.SetDarkModeIcon(trayIcon)
	tray.SetTooltip("NovaProxy")
	app.systemTray = tray

	// Define Tray Menu
	trayMenu := application.NewMenu()
	trayMenu.Add("داشبورد").OnClick(func(ctx *application.Context) {
		app.RevealMainWindow()
	})
	trayMenu.AddSeparator()

	proxyLabel := "پروکسی: خاموش"
	if app.IsProxyRunning() {
		proxyLabel = "پروکسی: روشن"
	}
	app.proxyItemV3 = trayMenu.AddCheckbox(proxyLabel, app.IsProxyRunning())
	app.proxyItemV3.OnClick(func(ctx *application.Context) {
		app.runSafeAsync("tray proxy toggle", func() {
			if app.IsProxyRunning() {
				_ = app.StopProxy()
			} else {
				_ = app.StartProxy()
			}
		})
	})

	systemProxyLabel := "پروکسی سیستم: خاموش"
	if app.GetSystemProxyStatus().Enabled {
		systemProxyLabel = "پروکسی سیستم: روشن"
	}
	app.systemProxyItemV3 = trayMenu.Add(systemProxyLabel)
	app.systemProxyItemV3.OnClick(func(ctx *application.Context) {
		app.runSafeAsync("tray system proxy toggle", func() {
			if app.GetSystemProxyStatus().Enabled {
				_ = app.DisableSystemProxy()
				return
			}
			if !app.IsProxyRunning() {
				if err := app.StartProxy(); err != nil {
					return
				}
			}
			_ = app.EnableSystemProxy()
		})
	})

	warpLabel := "Warp: خاموش"
	if app.GetWarpStatus().Running {
		warpLabel = "Warp: روشن"
	}
	app.warpItemV3 = trayMenu.AddCheckbox(warpLabel, app.GetWarpStatus().Running)
	app.warpItemV3.OnClick(func(ctx *application.Context) {
		app.runSafeAsync("tray warp toggle", func() {
			status := app.GetWarpStatus()
			if status.Running {
				_ = app.StopWarp()
			} else {
				_ = app.StartWarp()
			}
		})
	})

	trayMenu.AddSeparator()
	trayMenu.Add("خروج").OnClick(func(ctx *application.Context) {
		app.QuitApp()
	})

	tray.SetMenu(trayMenu)
	app.trayMenuV3 = trayMenu

	// Create Main Window
	app.mainWindow = wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "main",
		Title:            "NovaProxy",
		Width:            1024,
		Height:           768,
		URL:              "/",
		Frameless:        true,
		Hidden:           app.ShouldStartHidden(),
		BackgroundColour: application.NewRGB(27, 38, 54),
	})
	tray.OnClick(func() {
		app.RevealMainWindow()
	})

	err := wailsApp.Run()
	if err != nil {
		log.Fatal(err)
	}
}
