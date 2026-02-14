import SwiftUI
import Security
import Foundation

// ========================================================================
// 🛠️ 核心修复：手动声明系统隐藏的底层安全函数 (C-API Bridge)
// 只有加上这段，Swift 才能调用那些大厂用来检测真实身份的“隐藏接口”
// ========================================================================

// 定义 opaque 类型来代表 SecTask
typealias SecTaskRef = AnyObject

// 手动映射 C 语言的 SecTaskCreateFromSelf
@_silgen_name("SecTaskCreateFromSelf")
func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> SecTaskRef?

// 手动映射 C 语言的 SecTaskCopySigningIdentifier
@_silgen_name("SecTaskCopySigningIdentifier")
func SecTaskCopySigningIdentifier(_ task: SecTaskRef, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> CFString?

// ========================================================================

@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @State private var results: [ResultItem] = []

    struct ResultItem: Hashable {
        let title: String
        let value: String
        let isSuspicious: Bool
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("BundleID 攻防检测")
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity, alignment: .center)
                .background(Color(.systemGray6))
            
            List {
                ForEach(results, id: \.self) { item in
                    VStack(alignment: .leading, spacing: 5) {
                        Text(item.title)
                            .font(.caption)
                            .foregroundColor(.gray)
                            .bold()
                        Text(item.value)
                            .font(.system(size: 13, design: .monospaced))
                            .foregroundColor(item.isSuspicious ? .red : .primary)
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 4)
                }
            }
            .listStyle(.plain)
        }
        .onAppear {
            performDeepChecks()
        }
    }

    func performDeepChecks() {
        var items: [ResultItem] = []
        
        // 1. 基准值 (API层，最容易被 Hook 篡改)
        let standardID = Bundle.main.bundleIdentifier ?? "Unknown"
        items.append(ResultItem(title: "【API层】Bundle.main (易被篡改)", value: standardID, isSuspicious: false))
        
        // 2. 内核层 SecTask (通过手动映射调用隐藏 API)
        let secID = getSecTaskSigningIdentifier()
        items.append(ResultItem(title: "【内核层】SecTask (权威真实)", value: secID, isSuspicious: secID != standardID))
        
        // 3. IO层 fopen (绕过 Runtime Hook)
        let cPlistID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(title: "【IO层】fopen读取 Info.plist", value: cPlistID, isSuspicious: cPlistID != standardID))
        
        // 4. 证书层 mobileprovision (签名指纹)
        let provisionID = getMobileProvisionID()
        let isProvSuspicious = !provisionID.contains(standardID) && provisionID != "未找到或模拟器"
        items.append(ResultItem(title: "【证书层】embedded.mobileprovision", value: provisionID, isSuspicious: isProvSuspicious))
        
        self.results = items
    }
    
    // --- 核心实现 1: 调用隐藏的 SecTask ---
    func getSecTaskSigningIdentifier() -> String {
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else {
            return "SecTask 创建失败"
        }
        
        // 这里的 nil 之前报错，现在因为有明确的函数定义，Swift 知道它是 pointer 类型
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "获取失败 (无签名或权限不足)"
    }
    
    // --- 核心实现 2: 使用 C 标准库 fopen ---
    func getBundleIDFromPlistUsingFopen() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else {
            return "Info.plist 路径未找到"
        }
        
        // 打开文件
        guard let file = fopen(path, "r") else {
            return "fopen 打开失败"
        }
        defer { fclose(file) }
        
        // 获取文件大小
        fseek(file, 0, SEEK_END)
        let fileSize = ftell(file)
        fseek(file, 0, SEEK_SET)
        
        if fileSize <= 0 { return "文件为空" }
        
        // 读取内容
        var buffer = [CChar](repeating: 0, count: Int(fileSize) + 1)
        fread(&buffer, 1, Int(fileSize), file)
        
        // 暴力转字符串搜索
        let content = String(cString: buffer)
        
        // 简单解析 XML
        if let keyRange = content.range(of: "CFBundleIdentifier") {
            let sub = content[keyRange.upperBound...]
            if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                return String(sub[start.upperBound..<end.lowerBound])
            }
        }
        
        return "解析失败"
    }
    
    // --- 核心实现 3: 描述文件扫描 ---
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到 (可能是模拟器)"
        }
        
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let content = String(data: data, encoding: .isoLatin1) ?? ""
            
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    return String(sub[start.upperBound..<end.lowerBound])
                }
            }
        } catch {
            return "读取错误"
        }
        return "未找到 ID 字段"
    }
}
