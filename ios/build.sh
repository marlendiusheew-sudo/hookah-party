#!/bin/sh
# Сборка Hookah Party для iOS.
#   ./build.sh sim            — собрать и запустить в симуляторе (подпись не нужна)
#   ./build.sh ipa TEAM_ID    — собрать подписанный .ipa для TestFlight (нужна программа Apple Developer)
set -e
cd "$(dirname "$0")"
case "$1" in
  sim)
    xcodebuild -project HookahParty.xcodeproj -scheme HookahParty -configuration Debug -sdk iphonesimulator \
      -destination 'platform=iOS Simulator,name=iPhone 18 Pro' -derivedDataPath build CODE_SIGNING_ALLOWED=NO build
    xcrun simctl boot "iPhone 18 Pro" 2>/dev/null || true
    open -a Simulator
    xcrun simctl install booted build/Build/Products/Debug-iphonesimulator/HookahParty.app
    xcrun simctl launch booted app.hookahparty.ios ;;
  ipa)
    [ -n "$2" ] || { echo "Укажите Team ID: ./build.sh ipa ABCDE12345"; exit 1; }
    sed "s/REPLACE_WITH_TEAM_ID/$2/" ExportOptions.plist > build-export.plist
    xcodebuild -project HookahParty.xcodeproj -scheme HookahParty -configuration Release -destination 'generic/platform=iOS' \
      -archivePath build/HookahParty.xcarchive DEVELOPMENT_TEAM="$2" -allowProvisioningUpdates archive
    xcodebuild -exportArchive -archivePath build/HookahParty.xcarchive -exportPath build/ipa -exportOptionsPlist build-export.plist -allowProvisioningUpdates
    rm -f build-export.plist
    echo "Готово: $(pwd)/build/ipa/HookahParty.ipa" ;;
  *) echo "Использование: ./build.sh sim | ./build.sh ipa TEAM_ID" ;;
esac
