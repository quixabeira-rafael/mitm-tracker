import SwiftUI

struct ContentView: View {
    @StateObject private var model = DemoModel()

    var body: some View {
        NavigationStack {
            List {
                Section("Server") {
                    TextField("Base URL", text: $model.baseURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.footnote.monospaced())
                        .accessibilityIdentifier("baseURL")
                    Button {
                        Task { await model.run() }
                    } label: {
                        HStack {
                            Text(model.isRunning ? "Running…" : "Run A, B and C")
                            Spacer()
                            if model.isRunning { ProgressView() }
                        }
                    }
                    .disabled(model.isRunning)
                    .accessibilityIdentifier("run")
                    Text("Runs: \(model.runCount)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("runCount")
                }
                Section("Endpoints (in request order)") {
                    ForEach(model.results) { result in
                        EndpointRow(result: result)
                    }
                }
            }
            .navigationTitle("mitm-tracker demo")
        }
    }
}

private struct EndpointRow: View {
    let result: EndpointResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("/\(result.name)")
                    .font(.headline.monospaced())
                Spacer()
                if let arrival = result.arrival {
                    Text("arrived #\(arrival)")
                        .font(.caption.bold())
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(Color.blue.opacity(0.15)))
                }
                statusBadge
            }
            if let elapsed = result.elapsedMs {
                Text("\(elapsed) ms")
                    .font(.subheadline.monospacedDigit())
            }
            if let label = result.testLabel {
                Text("\(label) · \(result.testAction ?? "-")")
                    .font(.caption.monospaced())
                    .foregroundStyle(.purple)
            }
            if let error = result.error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            } else if let body = result.body {
                Text(body)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(3)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("endpoint-\(result.name)")
    }

    @ViewBuilder
    private var statusBadge: some View {
        if let status = result.status {
            Text("\(status)")
                .font(.caption.bold().monospacedDigit())
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(Capsule().fill(color(for: status)))
        } else if result.error != nil {
            Text("ERR")
                .font(.caption.bold())
                .foregroundStyle(.white)
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(Capsule().fill(Color.red))
        }
    }

    private func color(for status: Int) -> Color {
        switch status {
        case 200..<300: return .green
        case 400..<500: return .orange
        default: return .red
        }
    }
}
