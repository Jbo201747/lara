//
//  RemoteView.swift
//  lara
//
//  Created by ruter on 17.04.26.
//

import SwiftUI
import UIKit
import Darwin
import UniformTypeIdentifiers

struct RemoteView: View {
    @ObservedObject var mgr: laramgr
    @State private var statusBarTimeFormat: String = "HH:mm"
    @State private var running: Bool = false
    @State private var columns: Int = 5
    @State private var performanceHUD: Int = -1
    @AppStorage("rcdockunlimited") private var rcdockunlimited: Bool = false
    @State private var customProcessName: String = "SpringBoard"
    @State private var customFunctionName: String = "getpid"
    @State private var customArgsText: String = ""
    @State private var customTimeoutMs: Int = 100
    @State private var customMigBypass: Bool = false
    @State private var customLastResult: String = ""
    @State private var rwxSentinel: String = "0xC0FFEE"
    @State private var rwxProcess: String = "SpringBoard"
    @State private var rwxLastResult: String = ""
    @State private var rwxPersisted: String = UserDefaults.standard.string(forKey: "rwxLastRunResult") ?? ""
    @State private var rwxProcesses: [ProcEntry] = []
    @State private var procFilter: String = ""
    @State private var procLoading: Bool = false
    @State private var showProcPicker: Bool = false
    @State private var showSignImport: Bool = false
    @State private var signSourcePath: String? = nil
    @State private var signSourceName: String? = nil
    @State private var signResult: String = ""
    @State private var dylibTestResult: String = ""
    @State private var dylibTestRunning: Bool = false

    struct ProcEntry: Identifiable {
        let name: String
        let pid: Int
        let uid: Int
        var id: String { "\(pid)-\(name)" }
    }

    private static let rwxStoreKey = "rwxLastRunResult"

    private func importDylib(_ url: URL) {
        let needsStop = url.startAccessingSecurityScopedResource()
        defer { if needsStop { url.stopAccessingSecurityScopedResource() } }
        do {
            let fm = FileManager.default
            let dest = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("sign-\(UUID().uuidString)-\(url.lastPathComponent)")
            if fm.fileExists(atPath: dest.path) {
                try fm.removeItem(at: dest)
            }
            try fm.copyItem(at: url, to: dest)
            signSourcePath = dest.path
            signSourceName = url.lastPathComponent
            signResult = ""
        } catch {
            signResult = "import failed: \(error.localizedDescription)"
        }
    }

    private func runSign() {
        guard let input = signSourcePath else { return }
        let outPath = (input as NSString).deletingPathExtension + ".signed.dylib"
        DispatchQueue.global(qos: .userInitiated).async {
            let r = lara_sign_dylib(input, outPath, "com.roooot.lara.tweak", nil, nil)
            let msg = (r == nil)
                ? "sign: returned nil"
                : "\(r!.ok ? "OK" : "FAILED") cdhash=\(r!.cdhash) \(r!.diag)"
            DispatchQueue.main.async {
                self.signResult = msg
            }
        }
    }

    // proclist() walks the kernel proc list, so it is a little slow. Keep the
    // results on a background queue and hop back for the UI.
    //
    // The kernel truncates p_name to MAXCOMLEN (16 bytes on Darwin), so a long
    // process name arrives already clipped. Fetch the whole list unfiltered and
    // narrow it here instead, which also lets the search box match on pid as
    // well as name.
    private func refreshProcesses() {
        procLoading = true
        let filter = procFilter.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async {
            guard let raw = lara_list_processes("") else {
                DispatchQueue.main.async { self.procLoading = false }
                return
            }
            var entries: [ProcEntry] = raw.compactMap { dict -> ProcEntry? in
                guard let name = dict["name"] as? String, !name.isEmpty else { return nil }
                let pid = (dict["pid"] as? NSNumber)?.intValue ?? 0
                let uid = (dict["uid"] as? NSNumber)?.intValue ?? 0
                return ProcEntry(name: name, pid: pid, uid: uid)
            }
            if !filter.isEmpty {
                entries = entries.filter {
                    $0.name.localizedCaseInsensitiveContains(filter)
                        || String($0.pid) == filter
                }
            }
            entries.sort { lhs, rhs in
                let c = lhs.name.localizedCaseInsensitiveCompare(rhs.name)
                return c == .orderedSame ? lhs.pid < rhs.pid : c == .orderedAscending
            }
            DispatchQueue.main.async {
                self.rwxProcesses = entries
                self.procLoading = false
            }
        }
    }

    private func persistRwxResult(_ msg: String) {
        rwxLastResult = msg
        let stamp = DateFormatter.localizedString(from: Date(), dateStyle: .short, timeStyle: .medium)
        let record = "[\(stamp)] \(msg)"
        UserDefaults.standard.set(record, forKey: Self.rwxStoreKey)
        rwxPersisted = record
    }

    // Split out of `body` on purpose: the inline version pushed the whole
    // List past the type-checker's expression complexity limit.
    private func describeRwxStage(_ stage: Int) -> String {
        let names = [
            "no-proc",
            "mmap failed in target",
            "target memset write failed",
            "unused",
            "unused",
            "call to stub failed (harness error)",
            "call faulted or returned 0",
            "write did not land (memcmp mismatch)",
            "stub ran, wrong value",
        ]
        return stage < names.count ? names[stage] : "unknown stage \(stage)"
    }

    private func runRwxStub(probeOnly: Bool = false) -> String {
        let process = rwxProcess.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !process.isEmpty else { return "rwx: missing process name" }

        // rc_exec_rwx treats 0xDEADBEEF as "map, write, verify, report the
        // kernel's protection bits, and return without ever calling the stub".
        // That is the only way to get the pmap reading without risking the
        // target, so it gets a button of its own instead of being reachable
        // only by typing a magic number into the sentinel field -- which is
        // how Geode ended up crashed.
        let sentinel: UInt64 = probeOnly
            ? 0xDEADBEEF
            : (parseUInt64OrInt64BitPattern(rwxSentinel) ?? 0xC0FFEE)

        guard let proc = RemoteCall(process: process, useMigFilterBypass: false) else {
            return "rwx: RemoteCall init failed for \(process)"
        }
        defer { proc.destroy() }

        var execAddr: UInt64 = 0
        var diagBuf = [CChar](repeating: 0, count: 1024)
        let ret = diagBuf.withUnsafeMutableBufferPointer { bufPtr -> UInt64 in
            rc_exec_rwx(proc, sentinel, &execAddr, bufPtr.baseAddress, 1024)
        }
        let diag = String(cString: diagBuf)

        // rc_exec_rwx returns 0xF0000000|stage on failure so the stages are
        // distinguishable; 0 is a valid stub result.
        if (ret & 0xF0000000) == 0xF0000000 {
            let stage = Int(ret & 0xFFFF)
            return "rwx FAILED stage \(stage): \(describeRwxStage(stage))\nDIAG: \(diag)"
        }

        let ok = (ret & 0xFFFFFFFF) == (sentinel & 0xFFFFFFFF)
        if probeOnly {
            let addrHex = String(execAddr, radix: 16)
            return "rwx PROBE ONLY on \(process): mapped 0x\(addrHex), stub NOT called, target untouched.\nDIAG: \(diag)"
        }
        let addrHex = String(execAddr, radix: 16)
        let retHex = String(ret, radix: 16)
        let wantHex = String(sentinel, radix: 16)
        return "rwx: \(process) stub@0x\(addrHex) -> 0x\(retHex) (wanted 0x\(wantHex)) \(ok ? "OK" : "MISMATCH")\nDIAG: \(diag)"
    }

    private var rwxSection: some View {
        Section {
            TextField("RWX sentinel (hex or dec)", text: $rwxSentinel)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)

            // Tapping the field or the row opens the full scrollable list.
            // Kept as a NavigationLink-free button so it works inside a List
            // section without pushing a whole new view onto the nav stack.
            Button {
                procFilter = ""
                showProcPicker = true
                refreshProcesses()
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Target process")
                            .font(.subheadline)
                            .foregroundColor(.primary)
                        Text(rwxProcess.isEmpty ? "Tap to choose…" : rwxProcess)
                            .font(.system(.footnote, design: .monospaced))
                            .foregroundColor(rwxProcess.isEmpty ? .secondary : .blue)
                    }
                    Spacer()
                    if procLoading {
                        ProgressView()
                    }
                    Image(systemName: "chevron.right")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }

            HStack {
                Button {
                    run("RWX Exec") { self.runRwxStub() } onComplete: { msg in
                        self.persistRwxResult(msg)
                    }
                } label: {
                    Text("Execute RWX Stub")
                }

                Button {
                    run("RWX Probe") { self.runRwxStub(probeOnly: true) } onComplete: { msg in
                        self.persistRwxResult(msg)
                    }
                } label: {
                    Text("Probe Only (safe)")
                }
            }
            // Only the execution itself needs RemoteCall to be live. The whole
            // section used to be gated on rcready, which left the picker
            // inert and made it look like Geode was missing.
            .disabled(!mgr.rcready || running)

            if !rwxLastResult.isEmpty {
                Text(rwxLastResult)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        } header: {
            Text("RWX Stub Execution")
        } footer: {
            Text("Maps a RWX page in the target, writes a movz/movk/ret stub, and calls it. Proves arbitrary code execution in that process.")
        }
    }

    // Full-height scrollable process list, in the style of StikDebug: a search
    // field pinned at the top, one tappable row per process, and the selected
    // one marked. Presented as a sheet so it can be scrolled with a real
    // scroll wheel instead of being crammed inline in the form.
    private var procPickerSheet: some View {
        NavigationView {
            VStack(spacing: 0) {
                // An explicit field rather than .searchable: on iOS 16 inside a
                // sheet the modifier hides the field in the nav bar until you
                // pull down, which is easy to miss when you are hunting for one
                // specific process.
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)
                    TextField("Filter by name or pid", text: $procFilter)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.default)
                        .onChange(of: procFilter) { _ in
                            refreshProcesses()
                        }
                    if !procFilter.isEmpty {
                        Button {
                            procFilter = ""
                            refreshProcesses()
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color(.secondarySystemBackground))

                Divider()

                procListBody
            }
            .navigationTitle("Processes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showProcPicker = false }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        refreshProcesses()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
        }
        .navigationViewStyle(.stack)
    }

    private var procListBody: some View {
        List {
            if !rwxProcesses.isEmpty {
                ForEach(rwxProcesses) { entry in
                    Button {
                        rwxProcess = entry.name
                        showProcPicker = false
                    } label: {
                        procRow(entry)
                    }
                    .buttonStyle(.plain)
                }
            } else if procLoading {
                HStack {
                    Spacer()
                    ProgressView()
                    Spacer()
                }
                .padding(.vertical, 40)
            } else {
                VStack(spacing: 8) {
                    Text(emptyTitle)
                        .font(.headline)
                    Text(emptyDetail)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 40)
            }
        }
        .listStyle(.plain)
    }

    // proclist() walks the kernel proc list, which needs the darksword
    // primitives to be initialised. That is a separate step from RemoteCall,
    // and it is the usual reason the list comes back empty.
    private var dsReady: Bool { mgr.dsready }

    private var emptyTitle: String {
        if procFilter.isEmpty { return "No processes" }
        return "No processes matched"
    }

    private var emptyDetail: String {
        if !procFilter.isEmpty {
            return "Nothing matches “\(procFilter)”. Only running processes appear here, and the kernel truncates names to 15 characters — try a shorter fragment, or the pid."
        }
        if mgr.dsrunning {
            return "Darksword is still starting up. Wait for it to finish, then refresh."
        }
        if mgr.dsfailed {
            return "Darksword failed to initialise, so the kernel process list cannot be read. Run the DarkSword exploit first."
        }
        if !dsReady {
            return "The kernel process list is unavailable until DarkSword is initialised. Run the DarkSword exploit, then reopen this list."
        }
        return "The process list came back empty. Make sure RemoteCall is running."
    }

    private func procRow(_ entry: ProcEntry) -> some View {
        HStack(spacing: 10) {
            Text(entry.name)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1)
            Spacer(minLength: 8)
            Text("\(entry.pid)")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
            if entry.uid != 501 {
                Text("uid \(entry.uid)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundColor(.orange)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.15))
                    .cornerRadius(4)
            }
            if rwxProcess == entry.name {
                Image(systemName: "checkmark")
                    .foregroundColor(.green)
            }
        }
        .contentShape(Rectangle())
        .padding(.vertical, 2)
    }

    private var signSection: some View {
        Section {
            Button("Choose dylib to sign") {
                showSignImport = true
            }

            if let signSrc = signSourceName {
                HStack {
                    Text("Source")
                    Spacer()
                    Text(signSrc)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Button {
                runSign()
            } label: {
                Text("Sign (ad-hoc)")
            }
            .disabled(signSourcePath == nil)

            if !signResult.isEmpty {
                Text(signResult)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        } header: {
            Text("Ad-hoc dylib signing")
        } footer: {
            Text("choma builds a hash-based CodeDirectory with no CMS signature. Raw RWX is blocked by the pmap check on iOS 26; a signed dylib is the remaining route.")
        }
        .fileImporter(
            isPresented: $showSignImport,
            // A Mach-O dylib has no dedicated UTType; .data is the honest one.
            allowedContentTypes: [UTType.data],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                importDylib(url)
            }
        }
    }

    // The whole point of the choma harness, reduced to one button: build a dylib
    // in memory, sign it, write it where the target can open it, dlopen it, and
    // report whether the load was accepted. A non-NULL handle means cs_validate
    // took the ad-hoc signature with no trust-cache entry, which is the question
    // the whole RWX detour was circling.
    private var dylibTestSection: some View {
        Section {
            HStack {
                Text("Target")
                Spacer()
                Text(rwxProcess.isEmpty ? "(none)" : rwxProcess)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Button {
                runDylibTest()
            } label: {
                HStack {
                    Text("Build, Sign, and dlopen")
                    Spacer()
                    if dylibTestRunning {
                        ProgressView()
                    }
                }
            }
            .disabled(dylibTestRunning || rwxProcess.isEmpty)

            if !dylibTestResult.isEmpty {
                Text(dylibTestResult)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        } header: {
            Text("Dylib load test")
        } footer: {
            Text("Answers the open question: does cs_validate accept an ad-hoc signature with no trust-cache entry? Needs DarkSword, RemoteCall, and VFS initialised. A sandboxed target may not be able to open the file, which is reported separately from a signature rejection.")
        }
    }

    private func runDylibTest() {
        let process = rwxProcess.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !process.isEmpty else { return }
        dylibTestRunning = true
        dylibTestResult = "working…"
        DispatchQueue.global(qos: .userInitiated).async {
            var buf = [CChar](repeating: 0, count: 2048)
            lara_dylib_load_test(process, 0, &buf, 2048)
            let report = String(cString: buf)
            DispatchQueue.main.async {
                self.dylibTestResult = report
                self.dylibTestRunning = false
            }
        }
    }

    // SpringBoard dying takes this app down with it, so the in-memory result is
    // gone by the time you can read it. Persist to disk and restore on next
    // appearance.
    private var lastRunSection: some View {
        Section {
            Text(rwxPersisted.isEmpty ? "No run recorded yet." : rwxPersisted)
                .font(.system(.footnote, design: .monospaced))
                .foregroundColor(rwxPersisted.isEmpty ? .secondary : .primary)
                .textSelection(.enabled)

            HStack {
                Button("Copy") {
                    UIPasteboard.general.string = rwxPersisted
                }
                .disabled(rwxPersisted.isEmpty)

                Button("Clear") {
                    UserDefaults.standard.removeObject(forKey: Self.rwxStoreKey)
                    rwxPersisted = ""
                }
                .disabled(rwxPersisted.isEmpty)
            }
        } header: {
            Text("Last Run (survives crash)")
        }
        .disabled(!mgr.rcready || running)
    }
    @State private var hsRows: Int = 6
    @State private var hsColumns: Int = 4
    @State private var freakyrunning: Bool = false
    @State private var freakyseq: Int = 0

    private var dockMaxColumns: Int { rcdockunlimited ? 50 : 10 }

    private var euProgressFraction: Double { (mgr.eu1progress + mgr.eu2progress) / 2 }

    var body: some View {
        List {
            Section {
                TextField("Date format (e.g. HH:mm)", text: $statusBarTimeFormat)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)

                Button {
                    run("Status Bar Time Format") {
                        status_bar_time_format(mgr.sbProc, statusBarTimeFormat)
                        return "status_bar_time_format() done"
                    }
                } label: {
                    Text("Apply")
                }
            } header: {
                Text("Status Bar Time Format")
            } footer: {
                Text("The text automatically updates every MINUTE")
            }

            Section {
                Button {
                    run("Hide Icon Labels") {
                        let hidden = hide_icon_labels(mgr.sbProc)
                        return "hide_icon_labels() -> \(hidden)"
                    }
                } label: {
                    Text("Hide Icon Labels")
                }
            } header: {
                Text("SpringBoard")
            }

            Section {
                Stepper(value: $hsColumns, in: 1...10) {
                    HStack {
                        Text("Home screen columns")
                        Spacer()
                        Text("\(hsColumns)")
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                }
                
                Stepper(value: $hsRows, in: 1...10) {
                    HStack {
                        Text("Home screen rows")
                        Spacer()
                        Text("\(hsRows)")
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                }

                Button {
                    run("Patch Home Screen Grid \(hsColumns)x\(hsRows)") {
                        return patch_homescreen_grid(mgr.sbProc, Int32(hsColumns), Int32(hsRows))
                            ? "patch_homescreen_grid(\(hsColumns), \(hsRows)) -> ok"
                            : "patch_homescreen_grid(\(hsColumns), \(hsRows)) -> failed"
                    }
                } label: {
                    Text("Apply Home Screen Grid")
                }
            }

            Section {
                Stepper(value: $columns, in: 1...dockMaxColumns) {
                    HStack {
                        Text("Dock columns")
                        Spacer()
                        Text("\(columns)")
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                }
                .onChange(of: rcdockunlimited) { _ in
                    if !rcdockunlimited, columns > 10 {
                        columns = 10
                    }
                }

                Button {
                    run("Apply Dock Columns=\(columns)") {
                        let result = set_dock_icon_count(mgr.sbProc, Int32(columns))
                        return result == 0
                            ? "set_dock_icon_count(\(columns)) -> ok"
                            : "set_dock_icon_count(\(columns)) -> failed (\(result))"
                    }
                } label: {
                    Text("Apply Dock Columns")
                }
            }

            Section {
                Button {
                    run("Enable Upside Down") {
                        let result = enable_upside_down(mgr.sbProc)
                        return result == 0
                            ? "enable_upside_down() -> ok"
                            : "enable_upside_down() -> failed (\(result))"
                    }
                } label: {
                    Text("Enable Upside Down")
                }
            }

            Section {
                Button {
                    run("Enable Floating Dock") {
                        let result = enable_floating_dock(mgr.sbProc)
                        return result == 0
                            ? "enable_floating_dock() -> ok"
                            : "enable_floating_dock() -> failed (\(result))"
                    }
                } label: {
                    Text("Enable Floating Dock")
                }
                
                Button {
                    run("Enable Grid App Switcher") {
                        let result = enable_grid_app_switcher(mgr.sbProc)
                        return result == 0
                            ? "enable_grid_app_switcher() -> ok"
                            : "enable_grid_app_switcher() -> failed (\(result))"
                    }
                } label: {
                    Text("Enable Grid App Switcher (Broken animation)")
                }
                
                Button {
                    run("Enable UIKit Debug Overlay") {
                        let result = enable_debug_overlay(mgr.sbProc)
                        return result == 0
                            ? "enable_debug_overlay() -> ok"
                            : "enable_debug_overlay() -> failed (\(result))"
                    }
                } label: {
                    Text("Enable UIKit Debug Overlay")
                }

                /*
                Button {
                    togglefreakydog()
                } label: {
                    Text(freakyrunning ? "Stop Freaky Dog Overlay" : "Start Freaky Dog Overlay")
                }
                */
            } footer: {
                Text("To use UIKit Debug Overlay, double tap the status bar.")
            }
            
            Section {
                Picker("Performance HUD", selection: $performanceHUD) {
                    Text("Off").tag(-1)
                    Text("Basic").tag(0)
                    Text("Backdrops").tag(1)
                    Text("Particles").tag(2)
                    Text("Full").tag(3)
                    Text("Power").tag(5)
                    Text("EDR").tag(7)
                    Text("Glitches").tag(8)
                    Text("GPU Time").tag(9)
                    Text("Memory Bandwidth").tag(10)
                }
                .onChange(of: performanceHUD) { newValue in
                    set_performance_hud(mgr.sbProc, Int32(newValue))
                }
                .onAppear {
                    if mgr.rcrunning {
                        performanceHUD = Int(get_performance_hud(mgr.sbProc))
                    }
                }
            } footer: {
                Text("These call into SpringBoard via RemoteCall. Keep RemoteCall initialized while running them.")
                
                if !mgr.rcready {
                    Text("RemoteCall is not initialized. How are you here?")
                }
            }
            .disabled(!mgr.rcready || running)
            
            if #available(iOS 17.4, *) {
                Section {
                    Button {
                        mgr.rcinitDaemon(serviceName: "com.apple.xpc.amsaccountsd", process: "amsaccountsd", migbypass: false) { proc in
                            guard let proc else {
                                mgr.logmsg("rc init failed")
                                return
                            }
                            mgr.logmsg("rc init succeeded!")
                            mgr.eligibilitystate = euenabler_overwrite_eligibility(proc) == 0
                            mgr.logmsg("overwrite_eligibility() returned: \(mgr.eligibilitystate! ? "success" : "failure")")
                            proc.destroy()
                        }
                    } label: {
                        HStack {
                            Text("Overwrite eligibility (one time setup)")
                            if let state = mgr.eligibilitystate {
                                Spacer()
                                if state {
                                    Image(systemName: "checkmark.circle")
                                        .foregroundColor(.green)
                                } else {
                                    Image(systemName: "xmark.circle")
                                        .foregroundColor(.red)
                                }
                            }
                        }
                    }
                    .disabled(mgr.eligibilitystate ?? false)
                    
                    Button {
                        mgr.eu1progress = 0.0
                        mgr.eu2progress = 0.0
                        mgr.eu1running = true
                        mgr.eu2running = true
                        mgr.rcinitDaemon(serviceName: "com.apple.managedappdistributiond.xpc", process: "managedappdistributiond", migbypass: false) { proc in
                            guard let proc else {
                                mgr.logmsg("rc init failed")
                                mgr.eu1running = false
                                return
                            }
                            mgr.logmsg("rc init succeeded!")
                            euenabler_override_country_code(proc) { progress in
                                DispatchQueue.main.async {
                                    self.mgr.eu1progress = progress
                                }
                            }
                            proc.destroy()
                            DispatchQueue.main.async {
                                mgr.eu1running = false
                            }
                        }
                        // fix unable to load app info
                        mgr.rcinitDaemon(serviceName: "com.apple.appstorecomponentsd.xpc", process: "appstorecomponentsd", migbypass: false) { proc in
                            guard let proc else {
                                mgr.logmsg("rc init failed")
                                mgr.eu2running = false
                                return
                            }
                            mgr.logmsg("rc init succeeded!")
                            euenabler_override_country_code(proc) { progress in
                                DispatchQueue.main.async {
                                    self.mgr.eu2progress = progress
                                }
                            }
                            proc.destroy()
                            DispatchQueue.main.async {
                                mgr.eu2running = false
                            }
                        }
                    } label: {
                        HStack {
                            if mgr.eu1running || mgr.eu2running {
                                ProgressView(value: euProgressFraction)
                                    .progressViewStyle(.circular)
                                    .frame(width: 18, height: 18)
                                Text("Running...")
                                Spacer()
                                Text("\(Int(euProgressFraction * 100))%")
                            } else {
                                Text("Enable Spoof EU Region")
                                Spacer()
                                if mgr.eu1progress + mgr.eu2progress == 2 {
                                    Image(systemName: "checkmark.circle")
                                        .foregroundColor(.green)
                                } else if mgr.dsattempted && mgr.dsfailed {
                                    Image(systemName: "xmark.circle")
                                        .foregroundColor(.red)
                                }
                            }
                        }
                    }
                    .disabled(mgr.eu1running || mgr.eu2running || mgr.eu1progress+mgr.eu2progress == 2)
                } footer: {
                    Text("Enables installing of EU/Japan Marketplace apps.")
                }
                .disabled(isdebugged() || mgr.rcrunning || !mgr.rcready)
            }
            
            Section {
                Button {
                    youtube_tweak(mgr.ytProc)
                } label: {
                    Text("Generic Youtube Tweaks")
                }
            }
            
            Section {
                Button {
                    _ = mgr.rccall(name: "exit", args: [0], timeout: 100)
                } label: {
                    Text("Respring")
                }
            } header: {
                Text("Tools")
            }
            
            rwxSection
            signSection
            dylibTestSection
            lastRunSection

            Section {
                TextField("Process name", text: $customProcessName)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()

                HStack {
                    TextField("Function (symbol or 0xaddr)", text: $customFunctionName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .lineLimit(1)
                    
                    TextEditor(text: $customArgsText)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }

                Stepper(value: $customTimeoutMs, in: 10...5000, step: 10) {
                    HStack {
                        Text("Timeout")
                        Spacer()
                        Text("\(customTimeoutMs) ms")
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }
                }

                Toggle("MIG filter bypass", isOn: $customMigBypass)

                Button {
                    run("Custom RemoteCall \(customProcessName):\(customFunctionName)") {
                        let process = customProcessName.trimmingCharacters(in: .whitespacesAndNewlines)
                        let function = customFunctionName.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !process.isEmpty else { return "custom: missing process name" }
                        guard !function.isEmpty else { return "custom: missing function name" }

                        let (args, parseError) = parseRemoteCallArgs(customArgsText)
                        if let parseError {
                            return "custom: args parse error: \(parseError)"
                        }

                        let ptr: UnsafeMutableRawPointer?
                        if let addr = parseAddress(function) {
                            ptr = UnsafeMutableRawPointer(bitPattern: UInt(addr))
                        } else {
                            let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
                            ptr = function.withCString { dlsym(RTLD_DEFAULT, $0) }
                        }

                        guard let ptr else {
                            return "custom: failed to resolve \(function)"
                        }

                        guard let proc = RemoteCall(process: process, useMigFilterBypass: customMigBypass) else {
                            return "custom: RemoteCall init failed for \(process)"
                        }
                        defer { proc.destroy() }

                        var argsCopy = args
                        let ret = function.withCString { (cName: UnsafePointer<CChar>) -> UInt64 in
                            UInt64(argsCopy.withUnsafeMutableBufferPointer { buffer in
                                proc.doStable(
                                    withTimeout: Int32(customTimeoutMs),
                                    functionName: UnsafeMutablePointer(mutating: cName),
                                    functionPointer: ptr,
                                    args: buffer.baseAddress,
                                    argCount: UInt(args.count)
                                )
                            })
                        }

                        let err = proc.lastError ?? ""
                        let suffix = err.isEmpty ? "" : " (err: \(err))"
                        return "custom: \(process) \(function)(\(args.count) args) -> 0x\(String(ret, radix: 16)) / \(ret)\(suffix)"
                    } onComplete: { msg in
                        self.customLastResult = msg
                    }
                } label: {
                    Text("Call")
                }

                if !customLastResult.isEmpty {
                    Text(customLastResult)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundColor(.secondary)
                        .textSelection(.enabled)
                }
            } header: {
                Text("Custom RemoteCall")
            } footer: {
                Text("Calls a symbol (via dlsym) or an absolute address. Numeric args are passed as x0-x7 then stack.")
            }
            .disabled(!mgr.rcready || running)

            Section {
                HStack(alignment: .top) {
                    AsyncImage(url: URL(string: "https://github.com/khanhduytran0.png")) { image in
                        image
                            .resizable()
                            .scaledToFill()
                    } placeholder: {
                        ProgressView()
                    }
                    .frame(width: 40, height: 40)
                    .clipShape(Circle())
                    
                    VStack(alignment: .leading) {
                        Text("Duy Tran")
                            .font(.headline)
                        
                        Text("Responsible for most things related to remotecall.")
                            .font(.subheadline)
                            .foregroundColor(Color.secondary)
                    }
                    
                    Spacer()
                }
                .onTapGesture {
                    if let url = URL(string: "https://github.com/khanhduytran0"),
                       UIApplication.shared.canOpenURL(url) {
                        UIApplication.shared.open(url)
                    }
                }
                
                HStack(alignment: .top) {
                    AsyncImage(url: URL(string: "https://github.com/zeroxjf.png")) { image in
                        image
                            .resizable()
                            .scaledToFill()
                    } placeholder: {
                        ProgressView()
                    }
                    .frame(width: 40, height: 40)
                    .clipShape(Circle())
                    
                    VStack(alignment: .leading) {
                        Text("0xjf")
                            .font(.headline)
                        
                        Text("Powercuff and SBCustomizer")
                            .font(.subheadline)
                            .foregroundColor(Color.secondary)
                    }
                    
                    Spacer()
                }
                .onTapGesture {
                    if let url = URL(string: "https://github.com/zeroxjf"),
                       UIApplication.shared.canOpenURL(url) {
                        UIApplication.shared.open(url)
                    }
                }
                
                HStack(alignment: .top) {
                    AsyncImage(url: URL(string: "https://github.com/Scr-eam.png")) { image in
                        image
                            .resizable()
                            .scaledToFill()
                    } placeholder: {
                        ProgressView()
                    }
                    .frame(width: 40, height: 40)
                    .clipShape(Circle())
                    
                    VStack(alignment: .leading) {
                        Text("Scream")
                            .font(.headline)
                        
                        Text("Fixed Hide Icon Labels")
                            .font(.subheadline)
                            .foregroundColor(Color.secondary)
                    }
                    
                    Spacer()
                }
                .onTapGesture {
                    if let url = URL(string: "https://github.com/Scr-eam"),
                       UIApplication.shared.canOpenURL(url) {
                        UIApplication.shared.open(url)
                    }
                }
            } header: {
                Text("Credits")
            }
        }
        .navigationTitle(Text("Tweaks"))
        .onAppear {
            rwxPersisted = UserDefaults.standard.string(forKey: Self.rwxStoreKey) ?? ""
            refreshProcesses()
        }
        .sheet(isPresented: $showProcPicker) {
            procPickerSheet
        }
        .onDisappear {
            if freakyrunning, let proc = mgr.sbProc {
                stopfreakydog(proc)
            }
        }
    }

    private func run(_ name: String, _ work: @escaping () -> String, onComplete: ((String) -> Void)? = nil) {
        guard mgr.rcready, !running else { return }
        running = true
        mgr.logmsg("(rc) \(name)...")

        DispatchQueue.global(qos: .userInitiated).async {
            let result = work()
            DispatchQueue.main.async {
                self.mgr.logmsg("(rc) \(result)")
                onComplete?(result)
                if self.isRemoteCallFailure(result) {
                    Alertinator.shared.alert(title: "\(name) Failed", body: result)
                }
                self.running = false
            }
        }
    }

    private func isRemoteCallFailure(_ result: String) -> Bool {
        let lowercased = result.lowercased()
        return lowercased.contains("-> -1") ||
            lowercased.contains("-> failed") ||
            lowercased.contains(": failed") ||
            lowercased.contains("failed to")
    }

    private func togglefreakydog() {
        guard mgr.rcready, let proc = mgr.sbProc else { return }

        if freakyrunning {
            stopfreakydog(proc)
            return
        }

        let view = enable_freaky_dog_overlay(proc)
        guard view != 0 else {
            mgr.logmsg("(rc) enable_freaky_dog_overlay() failed")
            return
        }

        let seq = freakyseq + 1
        freakyseq = seq
        freakyrunning = true
        mgr.logmsg("(rc) enable_freaky_dog_overlay() -> 0x\(String(view, radix: 16))")

        let screen = UIScreen.main.bounds
        let maxw = max(Int(screen.width), 200)
        let maxh = max(Int(screen.height), 300)

        DispatchQueue.global(qos: .userInitiated).async {
            while true {
                let shouldcontinue = DispatchQueue.main.sync { () -> Bool in
                    self.freakyrunning && self.freakyseq == seq && self.mgr.rcready && self.mgr.sbProc != nil
                }
                if !shouldcontinue {
                    break
                }

                let size = Int.random(in: 110...220)
                let x = Int.random(in: 0...max(maxw - size, 0))
                let y = Int.random(in: 40...max(maxh - size, 40))
                let result = move_freaky_dog_overlay(proc, view, Int32(x), Int32(y), Int32(size), Int32(size))
                if result != 0 {
                    DispatchQueue.main.async {
                        self.mgr.logmsg("(rc) move_freaky_dog_overlay() failed: \(result)")
                        self.stopfreakydog(proc)
                    }
                    break
                }

                usleep(UInt32.random(in: 25000...90000))
            }
        }
    }

    private func stopfreakydog(_ proc: RemoteCall) {
        freakyrunning = false
        freakyseq += 1
        let result = disable_freaky_dog_overlay(proc)
        mgr.logmsg("(rc) disable_freaky_dog_overlay() -> \(result)")
    }

    private func parseRemoteCallArgs(_ text: String) -> (args: [UInt64], error: String?) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return ([], nil) }

        let separators = CharacterSet(charactersIn: ", \t\r\n")
        let tokens = trimmed
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        var out: [UInt64] = []
        out.reserveCapacity(tokens.count)

        for token in tokens {
            if let value = parseUInt64OrInt64BitPattern(token) {
                out.append(value)
            } else {
                return ([], "bad token '\(token)'")
            }
        }

        return (out, nil)
    }

    private func parseUInt64OrInt64BitPattern(_ token: String) -> UInt64? {
        if token.hasPrefix("-") {
            let rest = String(token.dropFirst())
            if rest.lowercased().hasPrefix("0x") {
                let hex = String(rest.dropFirst(2))
                guard let magnitude = UInt64(hex, radix: 16) else { return nil }
                let signed = -Int64(bitPattern: magnitude)
                return UInt64(bitPattern: signed)
            } else {
                guard let signed = Int64(rest) else { return nil }
                return UInt64(bitPattern: -signed)
            }
        }

        if token.lowercased().hasPrefix("0x") {
            return UInt64(token.dropFirst(2), radix: 16)
        }

        return UInt64(token)
    }

    private func parseAddress(_ functionField: String) -> UInt64? {
        let s = functionField.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.lowercased().hasPrefix("0x") else { return nil }
        guard let value = UInt64(s.dropFirst(2), radix: 16) else { return nil }
        guard value <= UInt64(UInt.max) else { return nil }
        return value
    }
}
