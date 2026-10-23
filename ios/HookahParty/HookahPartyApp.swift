import SwiftUI

// Hookah Party для iOS: тот же сайт внутри нативного приложения.
// Без адреса сервера (HPServerURL в Info.plist) приложение работает автономно, в демо-режиме:
// сайт лежит внутри приложения, данные — на телефоне. С адресом сервера — настоящие данные и вход по SMS.
@main
struct HookahPartyApp: App {
    var body: some Scene {
        WindowGroup {
            WebScreen()
                .ignoresSafeArea()
                .background(Color("LaunchBackground"))
        }
    }
}
