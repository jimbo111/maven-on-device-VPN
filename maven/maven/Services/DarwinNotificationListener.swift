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

    /// Tracks whether a retained reference is currently held by the CF
    /// notification center, so `stopListening` can release it exactly once
    /// (C3 — prevents use-after-free from `passUnretained`).
    private var isRetained = false

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
    /// Uses `passRetained` so the CF notification center holds a strong reference
    /// that keeps `self` alive until `stopListening()` releases it.
    ///
    /// - Parameter handler: Closure called each time the notification fires.
    func startListening(handler: @escaping () -> Void) {
        // Remove any previous registration and release the old retain before
        // taking a fresh one.
        if isRetained {
            stopListening()
        }

        self.handler = handler

        // `passRetained` increments the Swift retain count, ensuring `self`
        // cannot be deallocated while the CF center holds this pointer.
        let rawSelf = Unmanaged.passRetained(self).toOpaque()
        isRetained = true

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(
            center,
            rawSelf,
            { _, observer, _, _, _ in
                guard let observer else { return }
                // `takeUnretainedValue` — we do NOT consume the retain here;
                // the retain is balanced in `stopListening`.
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

    /// Deregisters the listener from the Darwin notification center and
    /// releases the retained reference taken in `startListening`.
    func stopListening() {
        guard isRetained else { return }

        // Reconstruct the same retained Unmanaged reference so we can both
        // pass the correct observer pointer to CF *and* release our retain.
        let unmanaged = Unmanaged.passUnretained(self)
        let rawSelf = unmanaged.toOpaque()

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterRemoveObserver(center, rawSelf, CFNotificationName(name as CFString), nil)

        // Balance the `passRetained` from `startListening`.
        Unmanaged<DarwinNotificationListener>.fromOpaque(rawSelf).release()
        isRetained = false
        handler = nil
    }
}
