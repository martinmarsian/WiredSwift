import Foundation

let kHelperMachServiceName = "fr.read-write.WiredServer3.Helper"
let kHelperVersion = "2"

/// XPC protocol between WiredServerApp and WiredServerHelper.
/// All parameters are typed and validated; the helper never executes arbitrary code.
@objc protocol WiredHelperProtocol: NSObjectProtocol {

    /// Create /Library/Wired3 (or similar system path) owned by the given user.
    func createSystemDirectory(
        path: String,
        owner: String,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Check whether filesPath is accessible to the wired3 binary using its TCC grant.
    func runFDACheck(
        filesPath: String,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Bootstrap and kickstart the LaunchDaemon. If filesPath is non-empty, also runs a typed
    /// FDA check via the wired3 binary. Reply: (success, fdaGranted, errorMessage)
    func startDaemon(
        plistPath: String,
        label: String,
        filesPath: String,
        withReply reply: @escaping (Bool, Bool, String) -> Void
    )

    /// Bootout the LaunchDaemon.
    func stopDaemon(
        label: String,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Create daemon user/group, set ownership, build and install LaunchDaemon plist.
    /// config keys: user, group, uid, gid, createUser, createGroup, dataPath, plistPath
    func activateDaemon(
        config: NSDictionary,
        filesPath: String,
        runAtLoad: Bool,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Bootout daemon, restore ownership, remove plist, optionally delete user/group.
    /// config keys: user, group, label, plistPath, restoreUser, dataPath, deleteUser, deleteGroup
    func deactivateDaemon(
        config: NSDictionary,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Build and install the LaunchDaemon plist from typed parameters.
    func installDaemonPlist(
        daemonUser: String,
        dataPath: String,
        filesPath: String,
        runAtLoad: Bool,
        plistPath: String,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Copy a binary from sourcePath to /Library/Wired3/bin/wired3 and set it executable.
    func copyBinary(
        sourcePath: String,
        withReply reply: @escaping (Bool, String) -> Void
    )

    /// Returns kHelperVersion — used to detect when the helper needs updating.
    func getVersion(withReply reply: @escaping (String) -> Void)
}
