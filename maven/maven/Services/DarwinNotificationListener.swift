import Foundation

/// Listens for Darwin (kernel-level) notifications posted via
/// `CFNotificationCenterGetDarwinNotifyCenter`.
///
/// Darwin notifications cross process boundaries without any payload, making
/// them the canonical way for a Network Extension to wake the host app.
/// Use `startListening(handler:)` to register and `stopListening()` to
/// deregister.
///
/// Example:
/// ```swift
/// let listener = DarwinNotificationListener(name: AppGroupConfig.newDomainsNotification)
/// listener.startListening {
///     // Refresh UI from shared database
/// }
/// ```
final class DarwinNotificationListener {

    // MARK: Properties

    /// The Darwin notification name this listener is registered for.
    let name: String

    private var handler: (() -> Void)?

    /// Tracks whether this listener is currently registered with the CF
    /// notification center.
    private var isRegistered = false

    // MARK: Init

    /// Creates a listener for the given Darwin notification name.
    ///
    /// - Parameter name: The notification name, e.g.
    ///   `AppGroupConfig.newDomainsNotification`.
    init(name: String) {
        self.name = name
    }

    deinit {
        stopListening()
    }

    // MARK: Public API

    /// Registers the listener and invokes `handler` on the main queue whenever
    /// the named Darwin notification fires.
    ///
    /// Calling this method when already listening replaces the previous handler.
    ///
    /// The observer pointer is passed unretained: retaining `self` here would
    /// keep the listener alive forever (deinit could never run, so the balancing
    /// release in `stopListening` would be unreachable). Safety comes from
    /// `deinit` calling `stopListening()`, which removes the observer before
    /// the instance is deallocated.
    ///
    /// - Parameter handler: Closure called each time the notification fires.
    func startListening(handler: @escaping () -> Void) {
        if isRegistered {
            stopListening()
        }

        self.handler = handler

        let rawSelf = Unmanaged.passUnretained(self).toOpaque()
        isRegistered = true

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(
            center,
            rawSelf,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let listener = Unmanaged<DarwinNotificationListener>
                    .fromOpaque(observer)
                    .takeUnretainedValue()
                DispatchQueue.main.async {
                    listener.handler?()
                }
            },
            name as CFString,
            nil,
            .deliverImmediately
        )
    }

    /// Deregisters the listener from the Darwin notification center.
    func stopListening() {
        guard isRegistered else { return }

        let rawSelf = Unmanaged.passUnretained(self).toOpaque()
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveObserver(center, rawSelf, CFNotificationName(name as CFString), nil)

        isRegistered = false
        handler = nil
    }
}
