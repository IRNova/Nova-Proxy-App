package proxy

import _ "embed"

//go:embed icon.png
var AppIcon []byte

// FaviconMIME is the MIME type for the app icon
const FaviconMIME = "image/png"
