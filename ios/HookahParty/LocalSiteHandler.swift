import WebKit
import UniformTypeIdentifiers

// Отдаёт файлы сайта из приложения по адресу hookah://app/…
// Свой адрес вместо file:// нужен, чтобы работали политика безопасности сайта (CSP 'self') и хранилище браузера.
final class LocalSiteHandler: NSObject, WKURLSchemeHandler {
    static let scheme = "hookah"
    static let startURL = URL(string: "hookah://app/index.html")!

    // Только эти файлы — никаких произвольных путей.
    private let allowed: Set<String> = ["index.html", "styles.css", "app.js", "art.js", "map-data.js", "admin.js"]
    private let root = Bundle.main.url(forResource: "web", withExtension: nil)

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        guard let url = task.request.url else { return }
        var name = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if name.isEmpty { name = "index.html" }
        guard allowed.contains(name), let file = root?.appendingPathComponent(name), let data = try? Data(contentsOf: file) else {
            // Например, /api/health: сервера внутри приложения нет — сайт поймёт это и включит демо-режим.
            let body = Data(#"{"error":"not_found"}"#.utf8)
            task.didReceive(HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!)
            task.didReceive(body)
            task.didFinish()
            return
        }
        let mime = UTType(filenameExtension: file.pathExtension)?.preferredMIMEType ?? "application/octet-stream"
        let type = mime.hasPrefix("text/") || mime.contains("javascript") ? "\(mime); charset=utf-8" : mime
        task.didReceive(HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": type, "Cache-Control": "no-cache"])!)
        task.didReceive(data)
        task.didFinish()
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {}
}
