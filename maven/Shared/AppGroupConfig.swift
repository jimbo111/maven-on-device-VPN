import Foundation
import os.log

private let appGroupLog = OSLog(subsystem: "com.jimmykim.maven", category: "AppGroupConfig")

enum AppGroupConfig {
    static let groupIdentifier = "group.com.jimmykim.maven"

    static var containerURL: URL {
        guard let url = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: groupIdentifier
        ) else {
            // DEBUG: crash so the developer notices immediately.
            // RELEASE: fall back to temp dir so the extension stays alive,
            // but log at .fault so the issue is visible in device logs.
            // WARNING: the temp dir is process-specific — the extension and
            // app will get separate empty databases. This is a degraded state,
            // not a working fallback.
            let msg = "App Group '\(groupIdentifier)' container URL unavailable — falling back to tmp. Database will be isolated per-process."
            assertionFailure(msg)
            os_log(.fault, log: appGroupLog, "%{public}@", msg)
            return URL(fileURLWithPath: NSTemporaryDirectory())
        }
        return url
    }

    static var databasePath: String {
        containerURL.appendingPathComponent("domains.sqlite").path
    }

    static var sharedDefaults: UserDefaults {
        guard let defaults = UserDefaults(suiteName: groupIdentifier) else {
            let msg = "UserDefaults suite '\(groupIdentifier)' unavailable — falling back to .standard. Settings will be isolated per-process."
            assertionFailure(msg)
            os_log(.fault, log: appGroupLog, "%{public}@", msg)
            return UserDefaults.standard
        }
        return defaults
    }

    static let newDomainsNotification = "com.jimmykim.maven.newdomains"
}
