using System.Text.Json;

namespace Kalitka;

/// <summary>
/// A visitor's remembered device — a passkey that lets them past the gate for a scope they were once
/// approved for, without ringing the bell again. This is the cryptographic version of the allow list:
/// where "remember this IP / name" (the <c>aip</c>/<c>ain</c> verbs) trusts a weak identifier, a
/// passkey trusts a key the device proves possession of. It is <b>not</b> an identity provider — it
/// recognises credentials we ourselves registered after an approval, an allowlist that happens to be
/// cryptographic. A separate population from operator passkeys (approvers) and from agents
/// (requesters): a visitor credential only lets its holder <i>in</i>, and can raise nothing.
/// </summary>
public sealed record VisitorPasskey(
    string CredentialId,     // base64url
    string PublicKeySpki,    // base64 SubjectPublicKeyInfo
    int Alg,                 // COSE alg: -7 ES256, -8 EdDSA
    long SignCount,
    string Scope,            // web:&lt;host&gt; (one host) or web:* (every guarded host), like the session scope
    string Label,            // what the visitor typed when approved — for the admin list
    bool BackupEligible,     // cloud-synced (not device-bound); policy may refuse it
    bool Revoked,            // a revoked key is blocked — it can no longer pass the gate
    string CreatedAt,
    string LastUsedAt)
{
    public string Fingerprint => Kalitka.Fingerprint.OfBase64(PublicKeySpki);

    /// <summary>Does this credential's scope cover a request for <paramref name="host"/>? Exact host,
    /// or the domain wildcard <c>web:*</c>.</summary>
    public bool Covers(string host) =>
        string.Equals(Scope, "web:*", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Scope, "web:" + host, StringComparison.OrdinalIgnoreCase);
}

/// <summary>Where remembered visitor passkeys live — one JSON blob in the shared config store, like
/// the allow/block lists they extend. Keyed by credential id.</summary>
public sealed class VisitorPasskeyStore
{
    private const string Key = "visitor-passkeys";
    private readonly IConfigStore _config;

    public VisitorPasskeyStore(IConfigStore config) => _config = config;

    public IReadOnlyList<VisitorPasskey> All() => Parse(_config.Get(Key));

    public VisitorPasskey? ByCredentialId(string credentialId) =>
        All().FirstOrDefault(c => string.Equals(c.CredentialId, credentialId, StringComparison.Ordinal));

    public void Add(VisitorPasskey cred)
    {
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur).Where(c => c.CredentialId != cred.CredentialId).ToList();
            list.Add(cred);
            return JsonSerializer.Serialize(list);
        });
    }

    public void RecordUse(string credentialId, long newSignCount, string usedAt)
    {
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            for (var i = 0; i < list.Count; i++)
                if (list[i].CredentialId == credentialId)
                    list[i] = list[i] with { SignCount = newSignCount, LastUsedAt = usedAt };
            return JsonSerializer.Serialize(list);
        });
    }

    /// <summary>Revoke a remembered device — it stays in the list (visible) but can no longer pass the
    /// gate. A revoked key is blocked.</summary>
    public bool Revoke(string credentialId)
    {
        var revoked = false;
        _config.Mutate(Key, cur =>
        {
            var list = Parse(cur);
            for (var i = 0; i < list.Count; i++)
                if (list[i].CredentialId == credentialId && !list[i].Revoked)
                {
                    list[i] = list[i] with { Revoked = true };
                    revoked = true;
                }
            return JsonSerializer.Serialize(list);
        });
        return revoked;
    }

    private static List<VisitorPasskey> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<VisitorPasskey>>(blob) ?? new());
}
