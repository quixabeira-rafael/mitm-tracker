import Foundation

struct EndpointResult: Identifiable {
    let name: String
    var status: Int?
    var elapsedMs: Int?
    var arrival: Int?
    var testLabel: String?
    var testAction: String?
    var body: String?
    var error: String?

    var id: String { name }
}

@MainActor
final class DemoModel: ObservableObject {
    static let endpoints = ["a", "b", "c"]

    @Published var baseURL: String
    @Published var results: [EndpointResult]
    @Published var isRunning = false
    @Published var runCount = 0

    private var arrivals = 0
    private let session: URLSession

    init() {
        baseURL = UserDefaults.standard.string(forKey: "baseURL") ?? "http://localhost:18080"
        results = Self.endpoints.map { EndpointResult(name: $0) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 15
        session = URLSession(configuration: configuration)
    }

    func run() async {
        isRunning = true
        arrivals = 0
        results = Self.endpoints.map { EndpointResult(name: $0) }
        let base = baseURL.trimmingCharacters(in: .whitespaces)
        await withTaskGroup(of: Void.self) { group in
            for name in Self.endpoints {
                group.addTask { await self.fetch(name: name, base: base) }
            }
        }
        runCount += 1
        isRunning = false
    }

    private func fetch(name: String, base: String) async {
        let start = Date()
        var result = EndpointResult(name: name)
        do {
            guard let url = URL(string: "\(base)/\(name)") else {
                throw URLError(.badURL)
            }
            let (data, response) = try await session.data(from: url)
            if let http = response as? HTTPURLResponse {
                result.status = http.statusCode
                result.testLabel = http.value(forHTTPHeaderField: "X-Mitm-Test")
                result.testAction = http.value(forHTTPHeaderField: "X-Mitm-Test-Action")
            }
            result.body = String(decoding: data.prefix(160), as: UTF8.self)
        } catch {
            result.error = (error as? URLError).map { "URLError \($0.code.rawValue)" } ?? error.localizedDescription
        }
        result.elapsedMs = Int(Date().timeIntervalSince(start) * 1000)
        record(result)
    }

    private func record(_ result: EndpointResult) {
        arrivals += 1
        var updated = result
        updated.arrival = arrivals
        if let index = results.firstIndex(where: { $0.name == result.name }) {
            results[index] = updated
        }
    }
}
