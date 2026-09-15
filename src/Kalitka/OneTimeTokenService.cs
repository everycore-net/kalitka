using System.Security.Cryptography;
using System.Text.Json;

namespace Kalitka;

/// <summary>
/// A one-time capability: signed, self-contained, single-use (the single-use part
/// is <see cref="IReplayStore"/>). It does not carry the decision — it points at
/// a request and a <c>permitted_action_id</c> that is opaque within that request;
/// what the action means is resolved server-side at redemption (see
/// <see cref="VerbFor"/>), so a policy change between issuance and click applies.
/// </summary>
public sealed record Capability(
    int V, string Jti, string Purpose, string Resource, string RequestId,
    string Action, string Subject, string GrantId, long Exp)
{
    public DateTimeOffset ExpiresAt => DateTimeOffset.FromUnixTimeSeconds(Exp);
}

public sealed class OneTimeTokenService
{
    private const string KeyId = "one-time:v1";

    private readonly TokenSigner _signer;
    private readonly TimeProvider _clock;

    public OneTimeTokenService(TokenSigner signer, TimeProvider? clock = null)
    {
        _signer = signer;
        _clock = clock ?? TimeProvider.System;
    }

    public string Mint(string purpose, string resource, string requestId, string action, int minutes)
    {
        var exp = _clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds();
        var cap = new Capability(1, NewJti(), purpose, resource, requestId, action, "", "", exp);
        return _signer.Sign(JsonSerializer.Serialize(cap), KeyId);
    }

    /// <summary>
    /// A short-lived, single-use SSH grant: the bridge between "an admin approved"
    /// and "the access was used". Bound to a request, subject and resource; carries
    /// its own grant id. It grants no rights of its own — what it permits is
    /// resolved server-side at redemption.
    /// </summary>
    public string MintGrant(string resource, string requestId, string subject, int minutes)
    {
        var exp = _clock.GetUtcNow().AddMinutes(minutes).ToUnixTimeSeconds();
        var cap = new Capability(1, NewJti(), "ssh-grant", resource, requestId,
            "", subject, NewJti(), exp);
        return _signer.Sign(JsonSerializer.Serialize(cap), KeyId);
    }

    /// <summary>Why a token was rejected, so a caller can report a precise reason instead of a blanket
    /// "invalid". <see cref="Malformed"/> is the crypto/shape failure — the string does not verify as one
    /// of our signed tokens at all (a secret pasted where a token belongs, or tampering); <see cref="Expired"/>
    /// is a genuine token past its lifetime.</summary>
    public enum ReadStatus { Ok, Malformed, Expired }

    public readonly record struct ReadResult(ReadStatus Status, Capability? Capability)
    {
        public bool Ok => Status == ReadStatus.Ok;
    }

    /// <summary>Verifies signature and expiry and returns the claims — does NOT
    /// consume. Consuming is a separate, deliberate step (a POST, never a GET).</summary>
    public Capability? Read(string token) => ReadDetailed(token) is { Ok: true } r ? r.Capability : null;

    /// <summary>Like <see cref="Read"/>, but distinguishes <i>why</i> a token was rejected (see
    /// <see cref="ReadStatus"/>). An expired token still returns its claims, so a caller can, for
    /// instance, name the resource it was for; a malformed one carries none.</summary>
    public ReadResult ReadDetailed(string token)
    {
        if (!_signer.Verify(token, KeyId, out var payload)) return new(ReadStatus.Malformed, null);

        Capability? cap;
        try { cap = JsonSerializer.Deserialize<Capability>(payload); }
        catch { return new(ReadStatus.Malformed, null); }

        if (cap is null || cap.V != 1) return new(ReadStatus.Malformed, null);
        if (_clock.GetUtcNow().ToUnixTimeSeconds() > cap.Exp) return new(ReadStatus.Expired, cap);
        return new(ReadStatus.Ok, cap);
    }

    /// <summary>
    /// Resolves an opaque action id to an engine verb at redemption. Today the
    /// only purpose is "approve" with two actions; a policy catalogue slots in
    /// here later without changing the token shape.
    /// </summary>
    public static string? VerbFor(string purpose, string action) =>
        purpose == "approve"
            ? action switch { "a" => "ok", "d" => "no", _ => null }
            : null;

    private static string NewJti() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}
