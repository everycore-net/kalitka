using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KalitkaMcpGateway;

/// <summary>
/// The real authority: Kalitka Core. The gateway raises an <c>mcp:&lt;alias&gt;/&lt;tool&gt;</c>
/// request (carrying the Call ID the approver sees) and Core owns the human notification, the
/// principals, subject rules, quorum and TTL — the gateway does not re-implement any of that. The
/// once-only execution claim is Core's <b>redeem-once grant</b>: even if two gateway instances both
/// see the approval, only one redeem succeeds, so the claim is durable and shared across instances
/// and restarts. A signed <c>/agent/*</c> client like every other Kalitka agent — no MCP SDK, no
/// shared secret; the agent must be enrolled with <c>access.request</c> + <c>grant.redeem</c> scoped
/// to <c>mcp:*</c>.
/// </summary>
public sealed class CoreAuthority : IApprovalAuthority
{
    private const string Scheme = "kalitka-agent-sig-v1";

    private sealed class Entry { public string? RequestId; public string? Grant; public string? SessionId; }

    private readonly HttpClient _http;
    private readonly ECDsa _key;
    private readonly string _agentId;
    private readonly ConcurrentDictionary<string, Entry> _calls = new(StringComparer.Ordinal);

    public CoreAuthority(HttpClient http, ECDsa signingKey, string agentId)
    {
        _http = http;
        _key = signingKey;
        _agentId = agentId;
    }

    /// <summary>The Core request id raised for a fingerprint (so an operator/console/audit can find
    /// it). Exposed for tests and diagnostics; it is not secret.</summary>
    public bool TryPendingRequest(string fingerprint, out string requestId)
    {
        if (_calls.TryGetValue(fingerprint, out var e) && e.RequestId is { } id) { requestId = id; return true; }
        requestId = "";
        return false;
    }

    public async Task<AuthorityDecision> EvaluateAsync(Call call, ToolClass cls, CancellationToken ct)
    {
        // No approval: the gateway allows it without troubling Core. (Every such call runs; the
        // once-guard is unnecessary because there is no approval to protect.)
        if (cls.Kind == ClassKind.NoApproval)
            return new AuthorityDecision(AuthorityOutcome.Approved, CallState.Approved);

        var entry = _calls.GetOrAdd(call.Fingerprint, _ => new Entry());

        if (entry.Grant is not null)
            return new AuthorityDecision(AuthorityOutcome.Approved, CallState.Approved);

        if (entry.RequestId is null)
        {
            entry.RequestId = await Raise(call, ct);
            return new AuthorityDecision(AuthorityOutcome.Pending, CallState.Pending);
        }

        var (state, grant) = await Poll(entry.RequestId, ct);
        switch (state)
        {
            case "approved":
                entry.Grant = grant;
                return new AuthorityDecision(AuthorityOutcome.Approved, CallState.Approved);
            case "denied" or "refused":
                return new AuthorityDecision(AuthorityOutcome.Denied, CallState.Denied, "denied");
            case "gone" or null:
                return new AuthorityDecision(AuthorityOutcome.Denied, CallState.Expired, "expired");
            default:
                return new AuthorityDecision(AuthorityOutcome.Pending, CallState.Pending);
        }
    }

    public async Task<ClaimOutcome> ClaimAsync(Call call, CancellationToken ct)
    {
        if (!_calls.TryGetValue(call.Fingerprint, out var entry))
            return ClaimOutcome.Claimed;   // no-approval call: nothing recorded, allowed
        if (entry.Grant is null) return ClaimOutcome.NotApproved;

        // Redeem the grant exactly once. Core enforces once-only durably, so a second attempt
        // (this or another instance) gets "used" — the at-most-once dispatch guarantee.
        var fields = new Dictionary<string, string> { ["grant"] = entry.Grant, ["agent"] = "mcp-gateway" };
        using var resp = await Send(HttpMethod.Post, "/agent/v1/grants/redeem", fields, ct);
        if (!resp.IsSuccessStatusCode) return ClaimOutcome.AlreadyClaimed;   // 409 used / 403
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        entry.SessionId = doc.RootElement.TryGetProperty("session_id", out var s) ? s.GetString() : null;
        return ClaimOutcome.Claimed;
    }

    public async Task<CallState> CompleteAsync(Call call, ExecutionOutcome outcome, CancellationToken ct)
    {
        if (_calls.TryGetValue(call.Fingerprint, out var entry) && entry.SessionId is { } sid)
        {
            var fields = new Dictionary<string, string> { ["session_id"] = sid, ["outcome"] = outcome.ToString().ToLowerInvariant() };
            try { using var _ = await Send(HttpMethod.Post, "/agent/v1/sessions/end", fields, ct); }
            catch { /* the outcome record is best-effort; the grant is already spent */ }
        }
        return outcome switch
        {
            ExecutionOutcome.Executed => CallState.Executed,
            ExecutionOutcome.Failed => CallState.Failed,
            _ => CallState.OutcomeUnknown,
        };
    }

    private async Task<string> Raise(Call call, CancellationToken ct)
    {
        var fields = new Dictionary<string, string>
        {
            ["resource"] = $"mcp:{call.UpstreamAlias}/{call.Tool}",
            ["user"] = string.IsNullOrWhiteSpace(call.Subject) ? "mcp-gateway" : call.Subject,
            ["command"] = call.CallId,   // the approver sees the Call ID
        };
        using var resp = await Send(HttpMethod.Post, "/agent/v1/requests", fields, ct);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        if (!resp.IsSuccessStatusCode || !doc.RootElement.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"raising mcp request failed ({(int)resp.StatusCode})");
        return id.GetString()!;
    }

    private async Task<(string? state, string? grant)> Poll(string requestId, CancellationToken ct)
    {
        using var resp = await Send(HttpMethod.Get, "/agent/v1/requests/" + Uri.EscapeDataString(requestId), null, ct);
        if (!resp.IsSuccessStatusCode) return ("gone", null);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var state = doc.RootElement.TryGetProperty("state", out var s) ? s.GetString() : null;
        var grant = doc.RootElement.TryGetProperty("grant", out var g) && g.ValueKind == JsonValueKind.String ? g.GetString() : null;
        return (state, grant);
    }

    private async Task<HttpResponseMessage> Send(HttpMethod method, string path, IDictionary<string, string>? fields, CancellationToken ct)
    {
        byte[] body = fields is null ? Array.Empty<byte>() : await new FormUrlEncodedContent(fields).ReadAsByteArrayAsync(ct);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        var canonical = Encoding.UTF8.GetBytes(string.Join('\n', Scheme, method.Method.ToUpperInvariant(), path, bodyHash, ts, nonce));
        var sig = Convert.ToBase64String(_key.SignData(canonical, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var req = new HttpRequestMessage(method, path);
        if (fields is not null)
        {
            req.Content = new ByteArrayContent(body);
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
        }
        req.Headers.TryAddWithoutValidation("X-Kalitka-Agent-Id", _agentId);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Timestamp", ts);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Signature", sig);
        return await _http.SendAsync(req, ct);
    }
}
