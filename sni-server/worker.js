/**
 * NovaProxy Universal Server Engine
 * 
 * This is a universal reverse proxy script (mainly adapted for Cloudflare Worker environment).
 * It receives HTTP requests encapsulated by NovaProxy client, strips the wrapper, and fetches the real target.
 */

// Default fallback password – it's recommended to set an environment variable named AUTH_SECRET in Cloudflare Dashboard
const DEFAULT_AUTH_SECRET = "CHANGE_ME_IN_PRODUCTION";

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        // path format: /{token}/{target_host}/{original_path...}
        // Example: /mysecret/www.google.com/search?q=hello
        const parts = url.pathname.split("/").filter(p => p !== "");

        if (parts.length < 2) {
            return new Response("Not Found", { status: 404 });
        }

        // 1. Authentication check
        const token = parts[0];
        const expectedAuth = (env && env.AUTH_SECRET) ? env.AUTH_SECRET : DEFAULT_AUTH_SECRET;

        if (token !== expectedAuth) {
            // Return 404 to camouflage as a regular missing page
            return new Response("Not Found", { status: 404 });
        }

        // 2. Extract and construct target URL
        const targetHost = parts[1];
        const restPath = parts.slice(2).join("/");
        const targetUrlStr = `https://${targetHost}/${restPath}${url.search}`;

        let targetUrl;
        try {
            targetUrl = new URL(targetUrlStr);
        } catch (e) {
            return new Response("Not Found", { status: 404 });
        }

        // 3. Build new request headers for the target website (remove specific edge-control headers)
        const newHeaders = new Headers(request.headers);
        // Overwrite Host header with real backend host to avoid errors due to SNI/Host mismatch
        newHeaders.set("Host", targetUrl.host);
        newHeaders.delete("connection");
        newHeaders.delete("x-forwarded-for");
        newHeaders.delete("x-forwarded-proto");
        newHeaders.delete("x-real-ip");

        let fetchOpts = {
            method: request.method,
            headers: newHeaders,
            redirect: "manual", // Let client handle redirects
            cf: {
                cacheEverything: false,
                cacheTtl: 0
            }
        };

        if (request.method !== "GET" && request.method !== "HEAD") {
            fetchOpts.body = request.body;
        }

        try {
            // 4. Execute the proxy request
            const response = await fetch(targetUrl.toString(), fetchOpts);

            // 5. Filter response headers to avoid security policy interference
            const responseHeaders = new Headers(response.headers);
            responseHeaders.delete('content-security-policy');
            responseHeaders.delete('content-security-policy-report-only');
            responseHeaders.delete('clear-site-data');

            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: responseHeaders
            });
        } catch (e) {
            return new Response("Not Found", { status: 502 });
        }
    }
};