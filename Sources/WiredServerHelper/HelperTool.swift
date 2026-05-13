import Foundation

final class HelperTool: NSObject, NSXPCListenerDelegate {

    let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: kHelperMachServiceName)
        super.init()
        listener.delegate = self
    }

    func run() {
        diagLog("listener.resume() calling…")
        listener.resume()
        diagLog("listener.resume() done — entering RunLoop.main.run()")
        RunLoop.main.run()
        diagLog("RunLoop.main.run() RETURNED — no input sources remain")
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let requirement = "anchor apple generic and identifier \"fr.read-write.WiredServer3\" and certificate leaf[subject.OU] = \"VGB467J8DZ\""
        do {
            try connection.setCodeSigningRequirement(requirement)
        } catch {
            diagLog("setCodeSigningRequirement failed: \(error)")
            return false
        }
        connection.exportedInterface = NSXPCInterface(with: WiredHelperProtocol.self)
        connection.exportedObject = HelperDelegate()
        connection.resume()
        return true
    }
}
