using System.Text.Json;

namespace Kalitka;

/// <summary>
/// A human operator, independent of the channel they answer from. Approvals arrive as
/// channel identities — <c>google:&lt;sub&gt;</c>, <c>telegram:&lt;user_id&gt;</c>, later
/// <c>slack:&lt;team&gt;:&lt;user&gt;</c>, <c>teams:&lt;tenant&gt;:&lt;oid&gt;</c>,
/// <c>app:&lt;id&gt;</c> — and a principal binds several of them to one person. That is what
/// lets a Telegram tap count in a quorum, and the same person on two channels count once.
///
/// Channels are transports of one control plane, not identity models: a new channel is just
/// a new identity scheme to link here — nothing in the quorum logic changes.
/// </summary>
public sealed record OperatorPrincipal(string Id, string DisplayName, string[] Identities)
{
    /// <summary>Bumped on each content change (append-only history in the store).</summary>
    public int Revision { get; init; }

    public bool SameContent(OperatorPrincipal other) =>
        string.Equals(DisplayName, other.DisplayName, StringComparison.Ordinal)
        && Identities.SequenceEqual(other.Identities, StringComparer.OrdinalIgnoreCase);

    /// <summary>Normalise an actor identity for comparison: trimmed, lower-cased. Identities
    /// are opaque typed strings (<c>scheme:value</c>); we never parse the value.</summary>
    public static string Normalize(string identity) => (identity ?? "").Trim().ToLowerInvariant();

    public bool Owns(string identity) =>
        Identities.Any(i => string.Equals(i, Normalize(identity), StringComparison.Ordinal));
}

/// <summary>
/// Where operator principals live — one JSON blob in the shared <see cref="IConfigStore"/>,
/// durable and cluster-wide, with the same append-only revision history and audited CRUD as
/// policies and profiles. An identity belongs to at most one principal (enforced on save),
/// so <see cref="Resolve"/> is unambiguous.
/// </summary>
public sealed class PrincipalService
{
    private const string Key = "operator-principals";

    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public PrincipalService(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    public IReadOnlyList<OperatorPrincipal> All() =>
        History().GroupBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                 .Select(g => g.OrderByDescending(p => p.Revision).First())
                 .Where(p => p.Identities.Length > 0 || p.DisplayName.Length > 0)
                 .OrderBy(p => p.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();

    public OperatorPrincipal? Get(string id) =>
        History().Where(p => Eq(p.Id, id)).OrderByDescending(p => p.Revision).FirstOrDefault();

    /// <summary>The id of the operator principal that owns <paramref name="actor"/>, or null
    /// if the identity is not linked to anyone. Channel-agnostic — it just matches the
    /// normalized identity string.</summary>
    public string? Resolve(string actor)
    {
        if (string.IsNullOrWhiteSpace(actor)) return null;
        var norm = OperatorPrincipal.Normalize(actor);
        foreach (var p in All())
            if (p.Identities.Any(i => string.Equals(i, norm, StringComparison.Ordinal)))
                return p.Id;
        return null;
    }

    /// <summary>The reverse of <see cref="Resolve"/>: the identities of an operator, so a
    /// resolved person can be turned back into channel targets (0.30). Optionally filter by
    /// scheme prefix (e.g. <c>telegram:</c>). Empty if the operator is unknown.</summary>
    public IReadOnlyList<string> IdentitiesOf(string principalId, string schemePrefix = "")
    {
        var p = Get(principalId);
        if (p is null) return Array.Empty<string>();
        return schemePrefix.Length == 0
            ? p.Identities
            : p.Identities.Where(i => i.StartsWith(schemePrefix, StringComparison.Ordinal)).ToArray();
    }

    /// <summary>Create or replace a principal. Returns an error string (identity already
    /// owned by another principal, or nothing to save) or null on success.</summary>
    public async Task<string?> Save(string id, string displayName, IEnumerable<string> identities, string actor, CancellationToken ct)
    {
        id = (id ?? "").Trim();
        if (id.Length == 0) return "id required";
        displayName = string.IsNullOrWhiteSpace(displayName) ? id : displayName.Trim();
        var idents = identities.Select(OperatorPrincipal.Normalize)
            .Where(i => i.Length > 0 && i.Contains(':')).Distinct().OrderBy(i => i, StringComparer.Ordinal).ToArray();

        string? error = null, outcome = null;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latestByOthers = hist.GroupBy(p => p.Id, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.OrderByDescending(p => p.Revision).First())
                .Where(p => !Eq(p.Id, id));
            // An identity may belong to at most one principal.
            var clash = idents.FirstOrDefault(i => latestByOthers.Any(o => o.Identities.Contains(i, StringComparer.Ordinal)));
            if (clash is not null) { error = $"identity {clash} is already linked to another operator"; return JsonSerializer.Serialize(hist); }

            var latest = hist.Where(p => Eq(p.Id, id)).OrderByDescending(p => p.Revision).FirstOrDefault();
            var next = new OperatorPrincipal(id, displayName, idents) { Revision = (latest?.Revision ?? 0) + 1 };
            if (latest is not null && latest.SameContent(next)) return JsonSerializer.Serialize(hist);
            hist.Add(next);
            outcome = latest is null ? "created" : "updated";
            return JsonSerializer.Serialize(hist);
        });
        if (error is not null) return error;
        if (outcome == "created") await _audit.Append(Ev(AuditEvents.PrincipalCreated, actor, id, string.Join(" ", idents)), ct);
        else if (outcome == "updated") await _audit.Append(Ev(AuditEvents.PrincipalUpdated, actor, id, string.Join(" ", idents)), ct);
        return null;
    }

    public async Task<bool> Delete(string id, string actor, CancellationToken ct)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            removed = hist.RemoveAll(p => Eq(p.Id, id)) > 0;
            return JsonSerializer.Serialize(hist);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.PrincipalDeleted, actor, id, ""), ct);
        return removed;
    }

    private List<OperatorPrincipal> History() => Parse(_config.Get(Key));
    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static List<OperatorPrincipal> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<OperatorPrincipal>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string principalId, string metadata) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: principalId, Resource: "", RequestId: "", GrantId: "", Channel: "admin", Metadata: metadata);
}
