import AppKit
import Foundation
import ServiceManagement

enum HelperError: LocalizedError {
    case connectionFailed
    case operationFailed(String)
    case installFailed(String)
    /// SMJobBless returned kSMErrorJobMustBeEnabled (8): helper is installed but disabled.
    /// The user must approve it in System Settings → Privacy & Security → Login Items.
    case mustBeEnabled

    var errorDescription: String? {
        switch self {
        case .connectionFailed:
            return L("error.helper.connection_failed")
        case .operationFailed(let msg):
            return msg.isEmpty ? L("error.helper.operation_failed") : msg
        case .installFailed(let msg):
            return "\(L("error.helper.install_failed_prefix")): \(msg)"
        case .mustBeEnabled:
            return L("alert.helper_setup.message")
        }
    }
}

/// Manages the XPC connection to WiredServerHelper and installs it via SMJobBless when needed.
///
/// Requires Developer ID signing: both the app (SMPrivilegedExecutables in Info.plist) and
/// the helper (SMAuthorizedClients in its embedded Info.plist) must satisfy each other's
/// code-signing requirements. See Sources/WiredServerHelper/Info.plist for the requirement strings.
final class HelperConnection {
    static let shared = HelperConnection()
    private init() {}

    private var _connection: NSXPCConnection?

    private var connection: NSXPCConnection {
        if let c = _connection { return c }
        let c = NSXPCConnection(machServiceName: kHelperMachServiceName, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: WiredHelperProtocol.self)
        c.invalidationHandler = { [weak self] in self?._connection = nil }
        c.resume()
        _connection = c
        return c
    }

    // MARK: - Installation

    /// Ensures the privileged helper is installed and running in launchd's system domain.
    ///
    /// Uses SMAppService.daemon (macOS 13+ replacement for SMJobBless). The daemon plist
    /// bundled in Contents/Library/LaunchDaemons/ is registered with the system. On first
    /// registration a notification prompts the user to approve in System Settings → General →
    /// Login Items. After approval launchd demand-starts the helper on first XPC connection.
    /// Also checks the running helper's version and restarts it if the binary was updated.
    func installIfNeeded() async throws {
        try registerIfNeeded()
        await restartIfOutdated()
    }

    /// Pure SMAppService registration — synchronous, no XPC calls.
    /// macOS posts a system notification automatically when register() requires approval;
    /// we don't open System Settings manually so the notification stays in focus.
    private func registerIfNeeded() throws {
        let service = SMAppService.daemon(plistName: "\(kHelperMachServiceName).plist")
        switch service.status {
        case .enabled:
            // SMAppService thinks it's enabled. Verify launchd actually has it.
            // If not (e.g. $APP_BUNDLE not resolved in old registration, or manual bootout),
            // force a fresh registration so BTM picks up the current plist with the absolute path.
            if !isHelperRegistered() {
                try? service.unregister()
                do {
                    try service.register()
                } catch {
                    if service.status == .requiresApproval {
                        throw HelperError.mustBeEnabled
                    }
                    throw HelperError.installFailed(error.localizedDescription)
                }
                if service.status == .requiresApproval {
                    throw HelperError.mustBeEnabled
                }
            }
            return
        case .requiresApproval:
            throw HelperError.mustBeEnabled
        case .notRegistered, .notFound:
            do {
                try service.register()
            } catch {
                // On macOS 14+, register() can throw "Operation not permitted" while
                // simultaneously posting the system approval notification. The throw
                // does NOT mean registration failed — it means the user hasn't approved
                // yet. Check the actual status before reporting a hard failure.
                if service.status == .requiresApproval {
                    throw HelperError.mustBeEnabled
                }
                throw HelperError.installFailed(error.localizedDescription)
            }
            if service.status == .requiresApproval {
                throw HelperError.mustBeEnabled
            }
        @unknown default:
            break
        }
    }

    /// If the running helper has an outdated protocol version, bootout and re-register so
    /// launchd starts the new binary on the next XPC connection.
    private func restartIfOutdated() async {
        let version = (try? await getVersion()) ?? ""
        guard version != kHelperVersion else { return }
        NSLog("[HelperConnection] Helper version '%@' ≠ expected '%@', restarting…", version, kHelperVersion)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["bootout", "system/\(kHelperMachServiceName)"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        _connection?.invalidate()
        _connection = nil
        // Re-register so launchd will start the new binary on the next connection attempt.
        try? registerIfNeeded()
    }


    /// Returns true if the helper mach service is registered in launchd's system domain.
    /// Uses `launchctl print system/<label>` which works without root and correctly
    /// distinguishes "registered but idle" from "not registered at all".
    func isHelperRegistered() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = ["print", "system/\(kHelperMachServiceName)"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    // MARK: - Version

    func getVersion() async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            guard let p = xpcProxy(onError: { cont.resume(throwing: $0) }) else { return }
            p.getVersion { version in cont.resume(returning: version) }
        }
    }

    // MARK: - Operations

    func createSystemDirectory(path: String, owner: String) async throws {
        try await boolReply { p, cont in
            p.createSystemDirectory(path: path, owner: owner, withReply: cont)
        }
    }

    func runFDACheck(filesPath: String, daemonUser: String) async throws -> Bool {
        try await withCheckedThrowingContinuation { cont in
            guard let p = xpcProxy(onError: { cont.resume(throwing: $0) }) else { return }
            p.runFDACheck(filesPath: filesPath, daemonUser: daemonUser) { granted, message in
                if message.isEmpty {
                    cont.resume(returning: granted)
                } else {
                    cont.resume(throwing: HelperError.operationFailed(message))
                }
            }
        }
    }

    /// Returns fdaGranted flag.
    func startDaemon(plistPath: String, label: String, filesPath: String, daemonUser: String) async throws -> Bool {
        try await withCheckedThrowingContinuation { cont in
            guard let p = xpcProxy(onError: { cont.resume(throwing: $0) }) else { return }
            p.startDaemon(plistPath: plistPath, label: label, filesPath: filesPath, daemonUser: daemonUser) { success, fdaGranted, message in
                if success {
                    cont.resume(returning: fdaGranted)
                } else {
                    cont.resume(throwing: HelperError.operationFailed(message))
                }
            }
        }
    }

    func stopDaemon(label: String) async throws {
        try await boolReply { p, cont in
            p.stopDaemon(label: label, withReply: cont)
        }
    }

    func activateDaemon(config: NSDictionary, filesPath: String, runAtLoad: Bool) async throws {
        try await boolReply { p, cont in
            p.activateDaemon(config: config, filesPath: filesPath, runAtLoad: runAtLoad, withReply: cont)
        }
    }

    func deactivateDaemon(config: NSDictionary) async throws {
        try await boolReply { p, cont in
            p.deactivateDaemon(config: config, withReply: cont)
        }
    }

    func installDaemonPlist(daemonUser: String, dataPath: String, filesPath: String,
                            runAtLoad: Bool, plistPath: String) async throws {
        try await boolReply { p, cont in
            p.installDaemonPlist(daemonUser: daemonUser, dataPath: dataPath, filesPath: filesPath,
                                  runAtLoad: runAtLoad, plistPath: plistPath, withReply: cont)
        }
    }

    func copyBinary(sourcePath: String) async throws {
        try await boolReply { p, cont in
            p.copyBinary(sourcePath: sourcePath, withReply: cont)
        }
    }

    // MARK: - Private

    /// Returns a typed XPC proxy whose connection errors are forwarded to `onError` instead of
    /// being silently dropped. If the cast fails, `onError` is called and nil is returned so the
    /// caller can simply guard-return without leaving the continuation dangling.
    private func xpcProxy(onError: @escaping (Error) -> Void) -> WiredHelperProtocol? {
        let raw = connection.remoteObjectProxyWithErrorHandler { error in
            NSLog("[HelperConnection] XPC error: %@", error as NSError)
            onError(HelperError.operationFailed("XPC: \(error.localizedDescription)"))
        }
        guard let p = raw as? WiredHelperProtocol else {
            onError(HelperError.connectionFailed)
            return nil
        }
        return p
    }

    private func boolReply(
        _ body: @escaping (WiredHelperProtocol, @escaping (Bool, String) -> Void) -> Void
    ) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            guard let p = xpcProxy(onError: { cont.resume(throwing: $0) }) else { return }
            body(p) { success, message in
                if success { cont.resume() }
                else { cont.resume(throwing: HelperError.operationFailed(message)) }
            }
        }
    }
}
