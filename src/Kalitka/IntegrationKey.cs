using System.Text.Json;

namespace Kalitka;

/// <summary>
/// A runtime-managed integration key: a ticket system (Jira, Freshdesk, ServiceNow) that raises
/// requests through the REST API, created and rotated from the admin console instead of only via
/// static config (<see cref="GateOptions.IntegrationClients"/>). Stored as a config entity with
/// append-only revisions and audited CRUD — the same shape as the catalogue and principals. The bearer
/// token is never stored; only its PBKDF2 hash (<see cref="AgentSecrets"/>), and the plaintext is shown
/// exactly once at creation or rotation.
/// </summary>
public sealed record IntegrationKey(string Id, string TokenHash, string[] Scope, int MaxRequestsPerMinute)
{
    public int Revision { get; init; }

    public bool SameContent(IntegrationKey other) =>
        string.Equals(TokenHash, other.TokenHash, StringComparison.Ordinal)
        && MaxRequestsPerMinute == other.MaxRequestsPerMinute
        && (Scope ?? Array.Empty<string>()).SequenceEqual(other.Scope ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// The runtime integration-key registry as a config-backed entity (one JSON blob in
/// <see cref="IConfigStore"/>, append-only revisions, audited CRUD). Mints and hashes bearer tokens
/// (never storing the plaintext), and hands the current keys to <see cref="IntegrationRegistry"/> so
/// they authenticate alongside any config-defined clients.
/// </summary>
public sealed class IntegrationKeyService
{
    private const string Key = "integration-keys";

    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public IntegrationKeyService(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>The current keys (latest revision per id). Carries the token hash for the registry to
    /// verify against; the admin UI renders only id/scope/rate, never the hash.</summary>
    public IReadOnlyList<IntegrationKey> All() =>
        History().GroupBy(k => k.Id, StringComparer.OrdinalIgnoreCase)
                 .Select(g => g.OrderByDescending(k => k.Revision).First())
                 .Where(k => k.TokenHash.Length > 0)
                 .OrderBy(k => k.Id, StringComparer.OrdinalIgnoreCase).ToList();

    public IntegrationKey? Get(string id) =>
        History().Where(k => Eq(k.Id, id)).OrderByDescending(k => k.Revision).FirstOrDefault();

    /// <summary>Create a new key — minting a bearer token returned <b>once</b> — or update an existing
    /// key's scope/rate in place (keeping its token). Returns <c>(token, error)</c>: <c>token</c> is
    /// non-null only when a key was created.</summary>
    public async Task<(string? token, string? error)> Save(string id, IEnumerable<string> scope, int maxPerMinute, string actor, CancellationToken ct)
    {
        id = (id ?? "").Trim();
        if (id.Length == 0) return (null, "id required");
        if (id.Any(c => !(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))) return (null, "id: letters, digits, - _ . only");
        var scopes = (scope ?? Enumerable.Empty<string>())
            .Select(s => (s ?? "").Trim()).Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (scopes.Length == 0) return (null, "at least one scope required");
        var rpm = maxPerMinute <= 0 ? 60 : maxPerMinute;

        string? token = null, outcome = null;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latest = hist.Where(k => Eq(k.Id, id)).OrderByDescending(k => k.Revision).FirstOrDefault();
            string hash;
            if (latest is null || latest.TokenHash.Length == 0)
            {
                token = AgentSecrets.NewSecret();       // minted, shown once
                hash = AgentSecrets.Hash(token);
                outcome = "created";
            }
            else
            {
                hash = latest.TokenHash;                 // update keeps the existing token
            }
            var next = new IntegrationKey(id, hash, scopes, rpm) { Revision = (latest?.Revision ?? 0) + 1 };
            if (latest is not null && latest.SameContent(next)) { token = null; outcome = null; return JsonSerializer.Serialize(hist); }
            if (outcome is null) outcome = "updated";
            hist.Add(next);
            return JsonSerializer.Serialize(hist);
        });
        if (outcome == "created") await _audit.Append(Ev(AuditEvents.IntegrationCreated, actor, id), ct);
        else if (outcome == "updated") await _audit.Append(Ev(AuditEvents.IntegrationUpdated, actor, id), ct);
        return (token, null);
    }

    /// <summary>Rotate a key's token: mint a new one (returned once), invalidating the old immediately.
    /// Null if the key does not exist.</summary>
    public async Task<string?> Rotate(string id, string actor, CancellationToken ct)
    {
        id = (id ?? "").Trim();
        string? token = null;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latest = hist.Where(k => Eq(k.Id, id)).OrderByDescending(k => k.Revision).FirstOrDefault();
            if (latest is null || latest.TokenHash.Length == 0) return JsonSerializer.Serialize(hist);
            token = AgentSecrets.NewSecret();
            hist.Add(latest with { TokenHash = AgentSecrets.Hash(token), Revision = latest.Revision + 1 });
            return JsonSerializer.Serialize(hist);
        });
        if (token is not null) await _audit.Append(Ev(AuditEvents.IntegrationRotated, actor, id), ct);
        return token;
    }

    public async Task<bool> Delete(string id, string actor, CancellationToken ct)
    {
        id = (id ?? "").Trim();
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            removed = hist.RemoveAll(k => Eq(k.Id, id)) > 0;
            return JsonSerializer.Serialize(hist);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.IntegrationDeleted, actor, id), ct);
        return removed;
    }

    private List<IntegrationKey> History() => Parse(_config.Get(Key));
    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static List<IntegrationKey> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<IntegrationKey>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string id) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: id, Resource: "", RequestId: "", GrantId: "", Channel: "admin", Metadata: "");
}
