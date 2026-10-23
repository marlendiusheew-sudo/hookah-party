import SwiftUI
import WebKit

// Экран с сайтом. Внешние ссылки (карты, Instagram) открываются в своих приложениях,
// файл календаря (.ics) — через системное меню «Поделиться».
struct WebScreen: UIViewRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(LocalSiteHandler(), forURLScheme: LocalSiteHandler.scheme)
        config.websiteDataStore = .default()            // данные демо-режима сохраняются между запусками
        config.allowsInlineMediaPlayback = true
        config.defaultWebpagePreferences.preferredContentMode = .mobile
        config.applicationNameForUserAgent = "HookahPartyApp/1.0"  // сайт понимает, что открыт в приложении

        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = context.coordinator
        web.uiDelegate = context.coordinator
        web.allowsBackForwardNavigationGestures = true   // свайп от края — назад, как в Safari
        web.isOpaque = false
        web.backgroundColor = UIColor(named: "LaunchBackground")
        web.scrollView.backgroundColor = web.backgroundColor
        web.scrollView.contentInsetAdjustmentBehavior = .never  // отступы под «чёлку» сайт ставит сам
        web.scrollView.keyboardDismissMode = .interactive
        #if DEBUG
        if #available(iOS 16.4, *) { web.isInspectable = true }  // отладка через Safari → Разработка
        #endif

        let refresh = UIRefreshControl()
        refresh.tintColor = UIColor(named: "AccentColor")
        refresh.addTarget(context.coordinator, action: #selector(Coordinator.reload(_:)), for: .valueChanged)
        web.scrollView.refreshControl = refresh
        context.coordinator.webView = web

        web.load(URLRequest(url: Self.startURL))
        return web
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    // Адрес сервера из Info.plist; если он не задан — сайт внутри приложения.
    static var serverURL: URL? {
        guard let s = Bundle.main.object(forInfoDictionaryKey: "HPServerURL") as? String, !s.isEmpty,
              let url = URL(string: s), url.scheme == "https" else { return nil }
        return url
    }
    static var startURL: URL {
        let base = serverURL ?? LocalSiteHandler.startURL
        #if DEBUG
        // Для отладки: xcrun simctl launch … app.hookahparty.ios -startHash /venues
        if let i = CommandLine.arguments.firstIndex(of: "-startHash"), i + 1 < CommandLine.arguments.count,
           let url = URL(string: base.absoluteString + "#" + CommandLine.arguments[i + 1]) { return url }
        #endif
        return base
    }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
        weak var webView: WKWebView?
        private var downloads: [WKDownload: URL] = [:]

        @objc func reload(_ sender: UIRefreshControl) {
            webView?.reload()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { sender.endRefreshing() }
        }

        private func isOwn(_ url: URL) -> Bool {
            if url.scheme == LocalSiteHandler.scheme || url.scheme == "blob" || url.scheme == "data" || url.scheme == "about" { return true }
            if let server = WebScreen.serverURL { return url.host == server.host }
            return false
        }

        // Ссылки наружу — в Safari или в приложениях карт; свои страницы — внутри.
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, preferences: WKWebpagePreferences,
                     decisionHandler: @escaping (WKNavigationActionPolicy, WKWebpagePreferences) -> Void) {
            if action.shouldPerformDownload { decisionHandler(.download, preferences); return }
            guard let url = action.request.url else { decisionHandler(.cancel, preferences); return }
            if isOwn(url) { decisionHandler(.allow, preferences); return }
            if ["http", "https", "tel", "mailto"].contains(url.scheme ?? "") { UIApplication.shared.open(url) }
            decisionHandler(.cancel, preferences)
        }

        // Ссылки с target="_blank" тоже открываем снаружи.
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            if let url = action.request.url, !isOwn(url) { UIApplication.shared.open(url) }
            return nil
        }

        // Если сайт не загрузился (нет сети при работе с сервером) — показываем понятный экран.
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            let html = """
            <meta name="viewport" content="width=device-width,initial-scale=1">
            <body style="margin:0;height:100vh;display:grid;place-items:center;background:#161114;color:#f2eae5;font:16px -apple-system,sans-serif;text-align:center">
            <div style="padding:24px"><div style="font-size:44px">💨</div><h2>Нет соединения</h2>
            <p style="color:#a8969c">Проверьте интернет и потяните экран вниз, чтобы обновить.</p></div></body>
            """
            webView.loadHTMLString(html, baseURL: nil)
        }

        // Загрузка файла календаря (.ics): сохраняем во временную папку и открываем «Поделиться».
        func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) { download.delegate = self }
        func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) { download.delegate = self }
        func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
            let safe = suggestedFilename.replacingOccurrences(of: "/", with: "_")
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(safe.isEmpty ? "hookah-party.ics" : safe)
            try? FileManager.default.removeItem(at: url)
            downloads[download] = url
            completionHandler(url)
        }
        func downloadDidFinish(_ download: WKDownload) {
            guard let url = downloads.removeValue(forKey: download), let web = webView,
                  let root = web.window?.rootViewController else { return }
            let share = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            share.popoverPresentationController?.sourceView = web
            root.present(share, animated: true)
        }
        func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) { downloads.removeValue(forKey: download) }
    }
}
