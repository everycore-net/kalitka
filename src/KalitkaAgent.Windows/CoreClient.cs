using System.Security.Cryptography;
using System.Text.Json;

namespace KalitkaAgent;

/// <summary>
/// Talks to Kalitka Core over the signed <c>/agent/*</c> API. Two operations for the thin
/// slice: enroll once (register the CNG public key, receive an agent id) and raise a request
/// (signed, with the OS-asserted subject). Every request is signed with the platform key; no
/// reusable secret is ever sent.
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

    /// <summary>Raise an access request with the OS-asserted subject. The subject/user come
    /// from <paramref name="caller"/> (the pipe token), never from the caller's own input; the
    /// caller only chooses the resource (and optionally a command).</summary>
    public async Task<RaiseResult> RaiseAsync(string agentId, CallerSubject caller, string resource, string? command, CancellationToken ct)
    {
        var fields = new Dictionary<string, string>
        {
            ["resource"] = resource,
            ["user"] = caller.User,
            ["subject_identity"] = caller.SubjectIdentity,
        };
        if (!string.IsNullOrEmpty(command)) fields["command"] = command;

        // The exact body bytes are what we both hash and send — building ByteArrayContent from
        // the same buffer avoids any re-encoding drift between the hash and the wire.
        var bytes = await new FormUrlEncodedContent(fields).ReadAsByteArrayAsync(ct);
        const string path = "/agent/v1/requests";
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var canonical = Wire.CanonicalString("POST", path, Wire.Sha256Hex(bytes), ts, nonce);
        var sig = _key.SignBase64(canonical);

        using var req = new HttpRequestMessage(HttpMethod.Post, path);
        req.Content = new ByteArrayContent(bytes);
        req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/x-www-form-urlencoded");
        req.Headers.TryAddWithoutValidation("X-Kalitka-Agent-Id", agentId);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Key-Id", _key.KeyId());
        req.Headers.TryAddWithoutValidation("X-Kalitka-Timestamp", ts);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Kalitka-Signature", sig);

        using var resp = await _http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        string? id = null, state = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("id", out var i)) id = i.GetString();
            if (doc.RootElement.TryGetProperty("state", out var s)) state = s.GetString();
        }
        catch (JsonException) { /* non-JSON (e.g. 403) — leave id/state null, status carries it */ }
        return new RaiseResult((int)resp.StatusCode, id, state);
    }
}
