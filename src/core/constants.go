package core

var CandidateIPs = []string{
	"216.239.32.120", "216.239.34.120", "216.239.36.120", "216.239.38.120",
	"142.250.80.142", "142.250.80.138", "142.250.179.110", "142.250.185.110",
	"142.250.184.206", "142.250.190.238", "142.250.191.78", "172.217.1.206",
	"172.217.14.206", "172.217.16.142", "172.217.22.174", "172.217.164.110",
	"172.217.168.206", "172.217.169.206", "34.107.221.82", "142.251.32.110",
	"142.251.33.110", "142.251.46.206", "142.251.46.238", "142.250.80.170",
	"142.250.72.206", "142.250.64.206", "142.250.72.110",
}

var FRONT_SNI_POOL = []string{
	"mail.google.com", "accounts.google.com", "www.google.com",
}

var StaticExts = []string{
	".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".mp3", ".mp4", ".webm", ".wasm", ".avif",
}

var SNIRewriteSuffixes = []string{
	"youtube.com", "youtu.be", "youtube-nocookie.com",
	"ytimg.com", "ggpht.com", "gvt1.com", "gvt2.com",
	"doubleclick.net", "googlesyndication.com",
	"googleadservices.com", "google-analytics.com",
	"googletagmanager.com", "googletagservices.com",
	"fonts.googleapis.com", "script.google.com",
}

var GoogleOwnedSuffixes = []string{
	".google.com", ".google.co",
	".googleapis.com", ".gstatic.com",
	".googleusercontent.com",
}

var GoogleOwnedExact = map[string]struct{}{
	"google.com": {}, "gstatic.com": {}, "googleapis.com": {},
}

var TraceHostSuffixes = []string{
	"chatgpt.com", "openai.com", "gemini.google.com",
	"google.com", "cloudflare.com",
	"challenges.cloudflare.com", "turnstile",
}
