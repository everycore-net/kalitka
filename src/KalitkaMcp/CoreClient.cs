using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace KalitkaMcp;

/// <summary>
/// The MCP server's client onto Kalitka Core's signed <c>/agent/*</c> API. The MCP server is
/// deliberately just another agent: it raises requests and polls them, exactly like the SSH or
/// DB connector, so the control plane needs no MCP-specific endpoint. Every call is signed with
/// the platform-less P-256 key; no reusable secret is sent. Enrollment happens once.
/// </summary>
public sealed class CoreClient
{
    private readonly HttpClient _http;
    private readonly SigningKey _key;
    private readonly McpConfig _cfg;
    private string _agentId = "";

    public CoreClient(HttpClient http, SigningKey key, IOptions<McpConfig> cfg)
    {
        _http = http;
        _key = key;
        _cfg = cfg.Value;
    }

    public sealed record RequestState(int Status, string? Id, string? State, string? Grant = null);

    /// <summary>Resolve the agent id, enrolling once with the configured one-time token if this
    /// is the first run. Throws a clear error if not enrolled and no token is set.</summary>
    public async Task EnsureEnrolledAsync(CancellationToken ct)
    {
        if (_agentId.Length > 0) return;
        var state = McpState.Load(_cfg.StatePath);
        if (state.AgentId.Length > 0) { _agentId = state.AgentId; return; }
        if (_cfg.EnrollmentToken.Length == 0)
            throw new InvalidOperationException(
                "Not enrolled and Kalitka:EnrollmentToken is empty. Create an agent with capability "
                + "access.request in the Kalitka admin console, mint a one-time enrollment token, and set it.");

        var form = new Dictionary<string, string>
        {
            ["token"] = _cfg.EnrollmentToken,
            ["public_key"] = _key.PublicKeySpkiBase64(),
            ["provider_hint"] = _key.ProviderHint,
            ["hostname"] = Environment.MachineName,
            ["metadata"] = "mcp-server",
        };
        using var resp = await _http.PostAsync("/agent/v1/enroll", new FormUrlEncodedContent(form), ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        if (!resp.IsSuccessStatusCode || !doc.RootElement.TryGetProperty("agent_id", out var idEl))
        {
            var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : resp.StatusCode.ToString();
            throw new InvalidOperationException($"enrollment failed: {err}");
        }
        _agentId = idEl.GetString()!;
        new McpState { AgentId = _agentId }.Save(_cfg.StatePath);
    }

    /// <summary>Raise an access request. Returns the request id and its state — almost always
    /// <c>waiting</c>: a human must approve. Never approves anything.</summary>
    public async Task<RequestState> RequestAccessAsync(string resource, string? profile, string? subjectIdentity, CancellationToken ct)
    {
        await EnsureEnrolledAsync(ct);
        // The request needs a beneficiary (`user`). When the AI names the human it acts for
        // (subject_identity), that human is the beneficiary; otherwise the workload acts for
        // itself. subject_identity additionally routes the approval and stays claimed.
        var fields = new Dictionary<string, string>
        {
            ["resource"] = resource,
            ["user"] = BeneficiaryOf(subjectIdentity),
        };
        if (!string.IsNullOrWhiteSpace(profile)) fields["profile"] = profile;
        if (!string.IsNullOrWhiteSpace(subjectIdentity)) fields["subject_identity"] = subjectIdentity;
        using var resp = await SendSigned(HttpMethod.Post, "/agent/v1/requests", fields, ct);
        return await ReadState(resp, ct);
    }

    /// <summary>Poll a request by id. When approved, <see cref="RequestState.Grant"/> carries the
    /// one-time grant token.</summary>
    public async Task<RequestState> GetRequestAsync(string id, CancellationToken ct)
    {
        await EnsureEnrolledAsync(ct);
        using var resp = await SendSigned(HttpMethod.Get, "/agent/v1/requests/" + Uri.EscapeDataString(id), null, ct);
        return await ReadState(resp, ct);
    }

    /// <summary>End an active session early.</summary>
    public async Task<bool> EndSessionAsync(string sessionId, string outcome, CancellationToken ct)
    {
        await EnsureEnrolledAsync(ct);
        var fields = new Dictionary<string, string> { ["session_id"] = sessionId, ["outcome"] = outcome };
        using var resp = await SendSigned(HttpMethod.Post, "/agent/v1/sessions/end", fields, ct);
        return resp.IsSuccessStatusCode;
    }

    // Sign and send one request. The body bytes signed are exactly the bytes sent, so the body
    // hash cannot drift from the wire.
    private async Task<HttpResponseMessage> SendSigned(
        HttpMethod method, string path, IDictionary<string, string>? fields, CancellationToken ct)
    {
        byte[] body = fields is null ? Array.Empty<byte>()
            : await new FormUrlEncodedContent(fields).ReadAsByteArrayAsync(ct);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var canonical = Wire.CanonicalString(method.Method, path, Wire.Sha256Hex(body), ts, nonce);
        var sig = _key.SignBase64(canonical);

        var req = new HttpRequestMessage(method, path);
        if (fields is not null)
        {
            req.Content = new ByteArrayContent(body);
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
        }
        req.Headers.TryAddWithoutValidation("X-Kalitka-Agent-Id", _agentId);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Key-Id", _key.KeyId());
        req.Headers.TryAddWithoutValidation("X-Kalitka-Timestamp", ts);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Signature", sig);
        return await _http.SendAsync(req, ct);
    }

    // The beneficiary tail of a subject identity (after the last '\' or ':'), matching Core's
    // beneficiary check; "mcp-agent" when the AI acts for itself rather than a named human.
    private static string BeneficiaryOf(string? subjectIdentity)
    {
        if (string.IsNullOrWhiteSpace(subjectIdentity)) return "mcp-agent";
        var s = subjectIdentity.Trim();
        var cut = Math.Max(s.LastIndexOf('\\'), s.LastIndexOf(':'));
        return cut >= 0 && cut < s.Length - 1 ? s[(cut + 1)..] : s;
    }

    private static async Task<RequestState> ReadState(HttpResponseMessage resp, CancellationToken ct)
    {
        var body = await resp.Content.ReadAsStringAsync(ct);
        string? id = null, state = null, grant = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("id", out var i)) id = i.GetString();
            if (root.TryGetProperty("state", out var s)) state = s.GetString();
            if (root.TryGetProperty("grant", out var g) && g.ValueKind == JsonValueKind.String) grant = g.GetString();
        }
        catch (JsonException) { /* non-JSON (e.g. 403) — status carries it */ }
        return new RequestState((int)resp.StatusCode, id, state, grant);
    }
}
