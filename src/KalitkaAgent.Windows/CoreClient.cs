using System.Security.Cryptography;
using System.Text.Json;

namespace KalitkaAgent;

/// <summary>
/// Talks to Kalitka Core over the signed <c>/agent/*</c> API: enroll once (register the CNG
/// public key), raise a request (with the OS-asserted subject), poll it, and redeem the grant.
/// Every call is signed with the platform key; no reusable secret is ever sent.
/// </summary>
public sealed class CoreClient
{
    private readonly HttpClient _http;
    private readonly PlatformKey _key;

    public CoreClient(HttpClient http, PlatformKey key)
    {
        _http = http;
        _key = key;
    }

    public sealed record RaiseResult(int Status, string? Id, string? State);
    public sealed record PollResult(int Status, string? State, string? Grant);
    public sealed record RedeemResult(int Status, string? SessionId, string? Subject, DateTimeOffset? ExpiresAt);

    /// <summary>Register this agent's public key with a one-time token; returns the agent id.</summary>
    public async Task<string> EnrollAsync(string token, string hostname, CancellationToken ct)
    {
        var form = new Dictionary<string, string>
        {
            ["token"] = token,
            ["public_key"] = _key.PublicKeySpkiBase64(),
            ["provider_hint"] = _key.ProviderHint,
            ["hostname"] = hostname,
            ["metadata"] = "windows-agent",
        };
        using var resp = await _http.PostAsync("/agent/v1/enroll", new FormUrlEncodedContent(form), ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(body);
        if (resp.IsSuccessStatusCode && doc.RootElement.TryGetProperty("agent_id", out var idEl))
            return idEl.GetString()!;
        var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : resp.StatusCode.ToString();
        throw new InvalidOperationException($"enrollment failed: {err}");
    }

    /// <summary>Raise an access request with the OS-asserted subject. The subject/user come from
    /// <paramref name="caller"/> (the pipe token), never the caller's own input.</summary>
    public async Task<RaiseResult> RaiseAsync(string agentId, CallerSubject caller, string resource, string? command, CancellationToken ct)
    {
        var fields = new Dictionary<string, string>
        {
            ["resource"] = resource,
            ["user"] = caller.User,
            ["subject_identity"] = caller.SubjectIdentity,
        };
        if (!string.IsNullOrEmpty(command)) fields["command"] = command;
        using var resp = await SendSigned(agentId, HttpMethod.Post, "/agent/v1/requests", fields, ct);
        var (id, state, _) = await ReadFields(resp, ct);
        return new RaiseResult((int)resp.StatusCode, id, state);
    }

    /// <summary>Poll a request; on approval the response carries the one-time grant token.</summary>
    public async Task<PollResult> PollAsync(string agentId, string requestId, CancellationToken ct)
    {
        using var resp = await SendSigned(agentId, HttpMethod.Get, "/agent/v1/requests/" + Uri.EscapeDataString(requestId), null, ct);
        var (_, state, grant) = await ReadFields(resp, ct);
        return new PollResult((int)resp.StatusCode, state, grant);
    }

    /// <summary>Redeem the grant exactly once, starting a session. Returns the Core-approved
    /// subject and the exact expiry — the enforcer trusts these, not any local input.</summary>
    public async Task<RedeemResult> RedeemAsync(string agentId, string grant, CancellationToken ct)
    {
        var fields = new Dictionary<string, string> { ["grant"] = grant, ["agent"] = Environment.MachineName };
        using var resp = await SendSigned(agentId, HttpMethod.Post, "/agent/v1/grants/redeem", fields, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        string? session = null, subject = null; DateTimeOffset? expiry = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("session_id", out var s)) session = s.GetString();
            if (root.TryGetProperty("subject", out var su)) subject = su.GetString();
            if (root.TryGetProperty("expires_at", out var e) && e.ValueKind == JsonValueKind.Number)
                expiry = DateTimeOffset.FromUnixTimeSeconds(e.GetInt64());
        }
        catch (JsonException) { }
        return new RedeemResult((int)resp.StatusCode, session, subject, expiry);
    }

    /// <summary>Report that a session ended, so Core closes it and audits <c>session.ended</c> —
    /// the human logged off, freeing the grant before its TTL. Returns the HTTP status.</summary>
    public async Task<int> EndSessionAsync(string agentId, string sessionId, string outcome, CancellationToken ct)
    {
        var fields = new Dictionary<string, string> { ["session_id"] = sessionId, ["outcome"] = outcome };
        using var resp = await SendSigned(agentId, HttpMethod.Post, "/agent/v1/sessions/end", fields, ct);
        return (int)resp.StatusCode;
    }

    // Sign and send one request; the body bytes signed are exactly the bytes sent.
    private async Task<HttpResponseMessage> SendSigned(
        string agentId, HttpMethod method, string path, IDictionary<string, string>? fields, CancellationToken ct)
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
        req.Headers.TryAddWithoutValidation("X-Kalitka-Agent-Id", agentId);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Key-Id", _key.KeyId());
        req.Headers.TryAddWithoutValidation("X-Kalitka-Timestamp", ts);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Signature", sig);
        return await _http.SendAsync(req, ct);
    }

    private static async Task<(string? id, string? state, string? grant)> ReadFields(HttpResponseMessage resp, CancellationToken ct)
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
        return (id, state, grant);
    }
}
