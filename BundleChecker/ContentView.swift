import SwiftUI
import Security
import Foundation

// --- 程序入口 ---
@main
struct BundleCheckerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

// --- 界面逻辑 ---
struct ContentView: View {
    @State private var results: [ResultItem] = []

    struct ResultItem: Hashable {
        let title: String
        let value: String
        let isSuspicious: Bool // 如果检测结果和API层不一致，标红
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("BundleID 终极风控检测")
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
                            .textSelection(.enabled) // 允许长按复制
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
        
        // 1. 基准值 (会被 Hook 的值)
        let standardID = Bundle.main.bundleIdentifier ?? "Unknown"
        items.append(ResultItem(title: "【API层】Bundle.main (易被篡改)", value: standardID, isSuspicious: false))
        
        // 2. Security 框架 (SecTask) - 核心防御手段
        // 你的 Hook 代码无法拦截这个，因为它是基于内核授权信息的 C API
        let secID = getSecTaskSigningIdentifier()
        items.append(ResultItem(title: "【内核层】SecTask (权威真实)", value: secID, isSuspicious: secID != standardID))
        
        // 3. C语言底层文件流读取 Info.plist
        // 绕过 [NSDictionary dictionaryWithContentsOfFile:] 的 Hook
        let cPlistID = getBundleIDFromPlistUsingFopen()
        items.append(ResultItem(title: "【IO层】fopen读取 Info.plist", value: cPlistID, isSuspicious: cPlistID != standardID))
        
        // 4. 描述文件解析 embedded.mobileprovision
        // 这是重签名的铁证
        let provisionID = getMobileProvisionID()
        // 注意：描述文件里的 ID 通常带 TeamID 前缀 (例如 A1B2C3D4.com.xxx)，需要包含性判断
        let isProvSuspicious = !provisionID.contains(standardID) && provisionID != "未找到或模拟器"
        items.append(ResultItem(title: "【证书层】embedded.mobileprovision", value: provisionID, isSuspicious: isProvSuspicious))
        
        self.results = items
    }
    
    // --- 核心对抗函数 1: SecTask ---
    func getSecTaskSigningIdentifier() -> String {
        // 创建自身的 SecTask 引用
        guard let secTask = SecTaskCreateFromSelf(kCFAllocatorDefault) else {
            return "SecTask 创建失败"
        }
        // 直接从代码签名Entitlements中提取 application-identifier
        // 这是一个 CFString，Swift 会自动桥接，但通常很难被 OC Runtime Hook 影响
        if let idRef = SecTaskCopySigningIdentifier(secTask, nil) {
            return idRef as String
        }
        return "获取失败 (可能无签名)"
    }
    
    // --- 核心对抗函数 2: fopen (C Standard IO) ---
    func getBundleIDFromPlistUsingFopen() -> String {
        guard let path = Bundle.main.path(forResource: "Info", ofType: "plist") else {
            return "Info.plist 路径未找到"
        }
        
        // 使用 C 语言标准库打开文件，完全无视 OC/Cocoa 的 Swizzling
        guard let file = fopen(path, "r") else {
            return "fopen 打开失败"
        }
        defer { fclose(file) }
        
        // 读取文件内容到缓冲区
        fseek(file, 0, SEEK_END)
        let fileSize = ftell(file)
        fseek(file, 0, SEEK_SET)
        
        var buffer = [CChar](repeating: 0, count: Int(fileSize) + 1)
        fread(&buffer, 1, Int(fileSize), file)
        
        // 转为字符串进行暴力搜索
        let content = String(cString: buffer)
        
        // 手动解析 XML (很简陋，但足以对抗 Hook)
        // 寻找 <key>CFBundleIdentifier</key> 下面的 <string>...</string>
        if let keyRange = content.range(of: "CFBundleIdentifier") {
            let sub = content[keyRange.upperBound...]
            if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                let foundID = String(sub[start.upperBound..<end.lowerBound])
                return foundID
            }
        }
        
        return "解析失败"
    }
    
    // --- 核心对抗函数 3: 描述文件扫描 ---
    func getMobileProvisionID() -> String {
        guard let path = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            return "未找到 (可能是模拟器)"
        }
        
        // 同样使用 Data 读取，虽然 Data 可能被 Hook，但这里我们用 Latin1 编码扫描二进制
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            // 强制 Latin1 解码，防止二进制乱码导致解析中断
            let content = String(data: data, encoding: .isoLatin1) ?? ""
            
            if let range = content.range(of: "<key>application-identifier</key>") {
                let sub = content[range.upperBound...]
                if let start = sub.range(of: "<string>"), let end = sub.range(of: "</string>") {
                    let fullID = String(sub[start.upperBound..<end.lowerBound])
                    return fullID
                }
            }
        } catch {
            return "读取错误"
        }
        return "未找到 ID 字段"
    }
}
