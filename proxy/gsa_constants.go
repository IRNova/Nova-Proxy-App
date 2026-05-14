package proxy

var gsaCandidateIPs = []string{
	"216.239.32.120",
	"216.239.34.120",
	"216.239.36.120",
	"216.239.38.120",
	"142.250.80.142",
	"142.250.80.138",
	"142.250.179.110",
	"142.250.185.110",
	"142.250.184.206",
	"142.250.190.238",
	"142.250.191.78",
	"172.217.1.206",
	"172.217.14.206",
	"172.217.16.142",
	"172.217.22.174",
	"172.217.164.110",
	"172.217.168.206",
	"172.217.169.206",
	"34.107.221.82",
	"142.251.32.110",
	"142.251.33.110",
	"142.251.46.206",
	"142.251.46.238",
	"142.250.80.170",
	"142.250.72.206",
	"142.250.64.206",
	"142.250.72.110",
}

var gsaGoogleDirectExactExclude = map[string]struct{}{
	"gemini.google.com":     {},
	"aistudio.google.com":   {},
	"notebooklm.google.com": {},
	"labs.google.com":       {},
	"meet.google.com":       {},
	"accounts.google.com":   {},
	"ogs.google.com":        {},
	"mail.google.com":       {},
	"calendar.google.com":   {},
	"drive.google.com":      {},
	"docs.google.com":       {},
	"chat.google.com":       {},
	"photos.google.com":    {},
	"maps.google.com":      {},
	"myaccount.google.com": {},
	"contacts.google.com":  {},
	"classroom.google.com": {},
	"keep.google.com":      {},
	"play.google.com":      {},
	"translate.google.com": {},
	"assistant.google.com": {},
	"lens.google.com":      {},
}

var gsaGoogleDirectSuffixExclude = []string{
	".meet.google.com",
}

var gsaGoogleDirectAllowExact = map[string]struct{}{
	"www.google.com":          {},
	"google.com":              {},
	"safebrowsing.google.com": {},
}

var gsaGoogleOwnedSuffixes = []string{
	".google.com", ".google.co",
	".googleapis.com", ".gstatic.com",
	".googleusercontent.com",
}

var gsaGoogleOwnedExact = map[string]struct{}{
	"google.com":     {},
	"gstatic.com":    {},
	"googleapis.com": {},
}

var gsaSNIRewriteSuffixes = []string{
	"youtube.com",
	"youtu.be",
	"youtube-nocookie.com",
	"ytimg.com",
	"ggpht.com",
	"gvt1.com",
	"gvt2.com",
	"doubleclick.net",
	"googlesyndication.com",
	"googleadservices.com",
	"google-analytics.com",
	"googletagmanager.com",
	"googletagservices.com",
	"fonts.googleapis.com",
	"script.google.com",
}

var gsaTraceHostSuffixes = []string{
	"chatgpt.com",
	"openai.com",
	"gemini.google.com",
	"google.com",
	"cloudflare.com",
	"challenges.cloudflare.com",
	"turnstile",
}

var gsaLargeFileExts = map[string]struct{}{
	".bin": {},
	".zip": {}, ".tar": {}, ".gz": {}, ".bz2": {}, ".xz": {}, ".7z": {}, ".rar": {},
	".exe": {}, ".msi": {}, ".dmg": {}, ".deb": {}, ".rpm": {}, ".apk": {},
	".iso": {}, ".img": {},
	".mp4": {}, ".mkv": {}, ".avi": {}, ".mov": {},
	".mp3": {}, ".flac": {}, ".wav": {}, ".aac": {},
	".pdf": {}, ".doc": {}, ".docx": {}, ".ppt": {}, ".pptx": {},
}

var gsaStatefulHeaderNames = []string{
	"cookie", "authorization", "proxy-authorization",
	"origin", "referer", "if-none-match", "if-modified-since",
	"cache-control", "pragma",
}

var gsaUncacheableHeaderNames = []string{
	"cookie", "authorization", "proxy-authorization", "range",
	"if-none-match", "if-modified-since", "cache-control", "pragma",
}

var gsaFrontSNIPoolDefault = []string{
	"www.google.com",
	"mail.google.com",
	"accounts.google.com",
}
