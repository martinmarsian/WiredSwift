import Darwin
import Foundation

final class HelperDelegate: NSObject, WiredHelperProtocol {

    // MARK: - Version

    func getVersion(withReply reply: @escaping (String) -> Void) {
        reply(kHelperVersion)
    }

    // MARK: - System directory

    func createSystemDirectory(path: String, owner: String,
                               withReply reply: @escaping (Bool, String) -> Void) {
        guard path.hasPrefix("/Library/"), !path.contains(".."), isValidAccount(owner) else {
            return reply(false, "Invalid parameters")
        }
        do {
            try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
            run("/bin/chmod", ["755", path])
            run("/usr/sbin/chown", ["\(owner):staff", path])
            reply(true, "")
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    // MARK: - FDA check

    func runFDACheck(filesPath: String, daemonUser: String,
                     withReply reply: @escaping (Bool, String) -> Void) {
        guard isAbsolutePath(filesPath), isValidAccount(daemonUser) else {
            return reply(false, "Invalid parameters")
        }
        let wired3 = "/Library/Wired3/bin/wired3"
        guard FileManager.default.isExecutableFile(atPath: wired3) else {
            return reply(false, "wired3 binary not found at \(wired3)")
        }
        // Run wired3 as the daemon user so TCC evaluates the grant for wired3's
        // code signature under the daemon identity — not as root which bypasses TCC.
        let status = run("/usr/bin/sudo", ["-n", "-u", daemonUser, wired3, "--check-access", filesPath])
        reply(status == 0, "")
    }

    // MARK: - Daemon lifecycle

    func startDaemon(plistPath: String, label: String, filesPath: String, daemonUser: String,
                     withReply reply: @escaping (Bool, Bool, String) -> Void) {
        guard plistPath.hasPrefix("/Library/LaunchDaemons/"), isValidLabel(label) else {
            return reply(false, false, "Invalid parameters")
        }
        run("/bin/launchctl", ["bootstrap", "system", plistPath])
        let kickStatus = run("/bin/launchctl", ["kickstart", "system/\(label)"])

        var fdaGranted = false
        if !filesPath.isEmpty {
            guard isAbsolutePath(filesPath), isValidAccount(daemonUser) else {
                return reply(false, false, "Invalid filesPath or daemonUser")
            }
            let wired3 = "/Library/Wired3/bin/wired3"
            if FileManager.default.isExecutableFile(atPath: wired3) {
                fdaGranted = run("/usr/bin/sudo", ["-n", "-u", daemonUser, wired3, "--check-access", filesPath]) == 0
            }
        }

        if kickStatus == 0 {
            reply(true, fdaGranted, "")
        } else {
            reply(false, false, "launchctl kickstart exited \(kickStatus)")
        }
    }

    func stopDaemon(label: String, withReply reply: @escaping (Bool, String) -> Void) {
        guard isValidLabel(label) else { return reply(false, "Invalid label") }
        let status = run("/bin/launchctl", ["bootout", "system/\(label)"])
        // ESRCH (errno 3) or 36 means the service label wasn't found in the system domain.
        // Also kill any wired3 process that was started outside launchd (e.g. directly by the app).
        run("/usr/bin/pkill", ["-x", "wired3"])
        if status == 0 || status == 3 || status == 36 {
            reply(true, "")
        } else {
            reply(false, "launchctl bootout exited \(status)")
        }
    }

    // MARK: - Daemon activation / deactivation

    func activateDaemon(config: NSDictionary, filesPath: String, runAtLoad: Bool,
                        withReply reply: @escaping (Bool, String) -> Void) {
        guard
            let user      = config["user"]        as? String, isValidAccount(user),
            let group     = config["group"]       as? String, isValidAccount(group),
            let uid       = config["uid"]         as? Int,
            let gid       = config["gid"]         as? Int,
            let createUser  = config["createUser"]  as? Bool,
            let createGroup = config["createGroup"] as? Bool,
            let dataPath  = config["dataPath"]    as? String, dataPath.hasPrefix("/Library/"), !dataPath.contains(".."),
            let plistPath = config["plistPath"]   as? String, plistPath.hasPrefix("/Library/LaunchDaemons/"),
            isAbsolutePath(filesPath) || filesPath.isEmpty
        else { return reply(false, "Invalid configuration") }

        if createGroup {
            guard
                run("/usr/bin/dscl", [".", "-create", "/Groups/\(group)"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Groups/\(group)", "PrimaryGroupID", "\(gid)"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Groups/\(group)", "Password", "*"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Groups/\(group)", "RealName", "Wired Server"]) == 0
            else { return reply(false, "Failed to create group \(group)") }
        }

        if createUser {
            guard
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "UserShell", "/usr/bin/false"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "RealName", "Wired Server"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "UniqueID", "\(uid)"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "PrimaryGroupID", "\(gid)"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "NFSHomeDirectory", "/var/empty"]) == 0,
                run("/usr/bin/dscl", [".", "-create", "/Users/\(user)", "IsHidden", "1"]) == 0
            else { return reply(false, "Failed to create user \(user)") }
        }

        // Ownership & permissions
        run("/usr/sbin/chown", ["-R", "\(user):\(group)", dataPath])
        run("/usr/sbin/chown", ["\(user):staff", "\(dataPath)/bin"])
        run("/bin/chmod", ["775", "\(dataPath)/bin"])
        run("/bin/rm", ["-rf", "\(dataPath)/bin/.updates"])
        run("/bin/chmod", ["755", "\(dataPath)/bin/wired3"])
        run("/usr/sbin/chown", ["\(user):staff", "\(dataPath)/etc"])
        run("/bin/chmod", ["775", "\(dataPath)/etc"])
        run("/usr/sbin/chown", ["\(user):staff", "\(dataPath)/etc/config.ini"])
        run("/bin/chmod", ["664", "\(dataPath)/etc/config.ini"])

        // Build and install plist
        guard let plistData = buildDaemonPlistData(daemonUser: user, dataPath: dataPath,
                                                    filesPath: filesPath, runAtLoad: runAtLoad),
              writePlist(plistData, to: plistPath) else {
            return reply(false, "Failed to install LaunchDaemon plist")
        }

        reply(true, "")
    }

    func deactivateDaemon(config: NSDictionary,
                          withReply reply: @escaping (Bool, String) -> Void) {
        guard
            let user        = config["user"]        as? String, isValidAccount(user),
            let group       = config["group"]       as? String, isValidAccount(group),
            let label       = config["label"]       as? String, isValidLabel(label),
            let plistPath   = config["plistPath"]   as? String, plistPath.hasPrefix("/Library/LaunchDaemons/"),
            let restoreUser = config["restoreUser"] as? String, isValidAccount(restoreUser),
            let dataPath    = config["dataPath"]    as? String, dataPath.hasPrefix("/Library/"),
            let deleteUser  = config["deleteUser"]  as? Bool,
            let deleteGroup = config["deleteGroup"] as? Bool
        else { return reply(false, "Invalid configuration") }

        run("/bin/launchctl", ["bootout", "system/\(label)"])
        Thread.sleep(forTimeInterval: 1.0)    // let daemon flush WAL before chown
        try? FileManager.default.removeItem(atPath: plistPath)
        run("/usr/sbin/chown", ["-R", "\(restoreUser):staff", dataPath])
        run("/bin/chmod", ["755", "\(dataPath)/bin"])
        run("/bin/chmod", ["755", "\(dataPath)/etc"])
        run("/bin/chmod", ["644", "\(dataPath)/etc/config.ini"])

        if deleteUser {
            run("/usr/bin/pkill", ["-u", user])
            Thread.sleep(forTimeInterval: 0.3)
            run("/usr/bin/dscl", [".", "-delete", "/Users/\(user)"])
        }
        if deleteGroup {
            run("/usr/bin/dscl", [".", "-delete", "/Groups/\(group)"])
        }

        reply(true, "")
    }

    // MARK: - Signal

    func triggerSnapshot(pidPath: String, withReply reply: @escaping (Bool, String) -> Void) {
        guard pidPath.hasPrefix("/Library/"), !pidPath.contains("..") else {
            return reply(false, "Invalid pidPath")
        }
        guard let pidString = try? String(contentsOfFile: pidPath, encoding: .utf8) else {
            return reply(false, "PID file not found at \(pidPath)")
        }
        let trimmed = pidString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let pid = pid_t(trimmed) else {
            return reply(false, "Invalid PID in file")
        }
        guard kill(pid, SIGUSR2) == 0 else {
            return reply(false, "kill(\(pid), SIGUSR2) failed: \(String(cString: strerror(errno)))")
        }
        reply(true, "")
    }

    // MARK: - Plist / binary install

    func installDaemonPlist(daemonUser: String, dataPath: String, filesPath: String,
                            runAtLoad: Bool, plistPath: String,
                            withReply reply: @escaping (Bool, String) -> Void) {
        guard isValidAccount(daemonUser),
              dataPath.hasPrefix("/Library/"), !dataPath.contains(".."),
              isAbsolutePath(filesPath) || filesPath.isEmpty,
              plistPath.hasPrefix("/Library/LaunchDaemons/") else {
            return reply(false, "Invalid parameters")
        }
        guard let data = buildDaemonPlistData(daemonUser: daemonUser, dataPath: dataPath,
                                               filesPath: filesPath, runAtLoad: runAtLoad),
              writePlist(data, to: plistPath) else {
            return reply(false, "Failed to build or install plist")
        }
        reply(true, "")
    }

    func copyBinary(sourcePath: String,
                    withReply reply: @escaping (Bool, String) -> Void) {
        let destinationPath = "/Library/Wired3/bin/wired3"
        guard isAbsolutePath(sourcePath), !sourcePath.contains("..") else {
            return reply(false, "Invalid source path")
        }
        do {
            if FileManager.default.fileExists(atPath: destinationPath) {
                try FileManager.default.removeItem(atPath: destinationPath)
            }
            try FileManager.default.copyItem(atPath: sourcePath, toPath: destinationPath)
            run("/bin/chmod", ["755", destinationPath])
            reply(true, "")
        } catch {
            reply(false, error.localizedDescription)
        }
    }

    // MARK: - Helpers

    @discardableResult
    private func run(_ path: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        let errPipe = Pipe()
        p.standardError = errPipe
        try? p.run()
        p.waitUntilExit()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        if let msg = String(data: errData, encoding: .utf8),
           !msg.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            diagLog("\(URL(fileURLWithPath: path).lastPathComponent) stderr: \(msg.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return p.terminationStatus
    }

    private func buildDaemonPlistData(daemonUser: String, dataPath: String,
                                       filesPath: String, runAtLoad: Bool) -> Data? {
        let binary = (dataPath as NSString).appendingPathComponent("bin/wired3")
        let db     = (dataPath as NSString).appendingPathComponent("wired3.db")
        let config = (dataPath as NSString).appendingPathComponent("etc/config.ini")
        let log    = (dataPath as NSString).appendingPathComponent("wired.log")
        let root   = filesPath.isEmpty ? (dataPath as NSString).appendingPathComponent("files") : filesPath
        let plist: [String: Any] = [
            "Label": "fr.read-write.wired3.server",
            "ProgramArguments": [binary, "--working-directory", dataPath,
                                  "--db", db, "--config", config, "--root", root],
            "UserName": daemonUser,
            "WorkingDirectory": dataPath,
            "RunAtLoad": runAtLoad,
            "KeepAlive": false,
            "StandardOutPath": log,
            "StandardErrorPath": log
        ]
        return try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }

    private func writePlist(_ data: Data, to path: String) -> Bool {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("wired3-helper-\(UUID().uuidString).plist")
        do {
            try data.write(to: tmp)
            if FileManager.default.fileExists(atPath: path) {
                try FileManager.default.removeItem(atPath: path)
            }
            try FileManager.default.copyItem(at: tmp, to: URL(fileURLWithPath: path))
            try FileManager.default.removeItem(at: tmp)
            run("/bin/chmod", ["644", path])
            run("/usr/sbin/chown", ["root:wheel", path])
            return true
        } catch {
            return false
        }
    }

    private func isValidAccount(_ name: String) -> Bool {
        guard !name.isEmpty, name.count <= 32 else { return false }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_-"))
        return name.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private func isValidLabel(_ label: String) -> Bool {
        guard !label.isEmpty, label.count <= 128 else { return false }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-_"))
        return label.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private func isAbsolutePath(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.contains("..")
    }
}
