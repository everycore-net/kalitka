using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kalitka;

/// <summary>
/// How much of the catalogue a person may see — a disclosure control, because "what can I ask for"
/// turns easily into "here is every server in the company". Ordered least-to-most open, so a person
/// in several groups gets the most open of their groups' modes. The default is the most closed.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CatalogVisibility
{
    /// <summary>Only what the person already holds — nothing requestable is disclosed.</summary>
    ApprovedOnly = 0,
    /// <summary>Category names only ("file shares", "dev servers") — no concrete resources.</summary>
    Categories = 1,
    /// <summary>The concrete units the person is entitled to ask for.</summary>
    Full = 2,
}

/// <summary>
/// One requestable unit in the self-service catalogue: the <b>unit</b> a person asks for (a share, a
/// host, a database role — not an individual file), curated rather than an inventory dump. Offered to
/// the principal groups in <see cref="Groups"/>; a unit offered to no group is requestable by no one
/// (closed by default). Stored as a config entity with append-only revisions, like policies and
/// principals.
/// </summary>
public sealed record CatalogItem(string Id, string Resource, string Category, string DisplayName, string[] Groups)
{
    public int Revision { get; init; }

    public bool SameContent(CatalogItem other) =>
        string.Equals(Resource, other.Resource, StringComparison.Ordinal)
        && string.Equals(Category, other.Category, StringComparison.Ordinal)
        && string.Equals(DisplayName, other.DisplayName, StringComparison.Ordinal)
        && (Groups ?? Array.Empty<string>()).SequenceEqual(other.Groups ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
}

/// <summary>What a given person may see, already projected for their visibility mode: the concrete
/// items (Full only), the category names (Categories and Full), and the mode that produced it.</summary>
public sealed record CatalogView(CatalogVisibility Mode, IReadOnlyList<CatalogItem> Items, IReadOnlyList<string> Categories);

/// <summary>
/// The requestable catalogue: a config-backed entity (one JSON blob in <see cref="IConfigStore"/>,
/// append-only revisions, audited CRUD — the same shape as policies and principals). Resolves, for a
/// person, what they may see and ask for under their visibility mode, defaulting to the most closed.
/// Resource ownership ("Finance owns this share") is deliberately not modelled here — it belongs to
/// the commercial approval-routing suite.
/// </summary>
public sealed class CatalogService
{
    private const string Key = "request-catalog";

    private readonly IConfigStore _config;
    private readonly IAuditStore _audit;
    private readonly TimeProvider _clock;

    public CatalogService(IConfigStore config, IAuditStore audit, TimeProvider? clock = null)
    {
        _config = config;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    public IReadOnlyList<CatalogItem> All() =>
        History().GroupBy(i => i.Id, StringComparer.OrdinalIgnoreCase)
                 .Select(g => g.OrderByDescending(i => i.Revision).First())
                 .Where(i => i.Resource.Length > 0)
                 .OrderBy(i => i.Category, StringComparer.OrdinalIgnoreCase)
                 .ThenBy(i => i.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();

    public CatalogItem? Get(string id) =>
        History().Where(i => Eq(i.Id, id)).OrderByDescending(i => i.Revision).FirstOrDefault();

    /// <summary>
    /// What <paramref name="principal"/> may see under <paramref name="mode"/> (default: the most
    /// closed). Entitlement is by group overlap: a unit is offered only to principals sharing one of
    /// its groups. The mode then decides how much of that entitled set is disclosed. A caller that
    /// does not know the person's mode gets the safe, closed answer.
    /// </summary>
    public CatalogView VisibleTo(OperatorPrincipal principal, CatalogVisibility mode = CatalogVisibility.ApprovedOnly)
    {
        var groups = principal.Groups ?? Array.Empty<string>();
        var entitled = All()
            .Where(i => (i.Groups ?? Array.Empty<string>()).Intersect(groups, StringComparer.OrdinalIgnoreCase).Any())
            .ToList();
        var categories = entitled.Select(i => i.Category)
            .Where(c => c.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList();

        return mode switch
        {
            CatalogVisibility.Full => new CatalogView(mode, entitled, categories),
            CatalogVisibility.Categories => new CatalogView(mode, Array.Empty<CatalogItem>(), categories),
            _ => new CatalogView(CatalogVisibility.ApprovedOnly, Array.Empty<CatalogItem>(), Array.Empty<string>()),
        };
    }

    /// <summary>Create or replace a catalogue item. Returns an error string, or null on success.</summary>
    public async Task<string?> Save(string id, string resource, string category, string displayName,
        IEnumerable<string> groups, string actor, CancellationToken ct)
    {
        id = (id ?? "").Trim();
        if (id.Length == 0) return "id required";
        resource = (resource ?? "").Trim();
        if (resource.Length == 0) return "resource required";
        category = (category ?? "").Trim();
        displayName = string.IsNullOrWhiteSpace(displayName) ? resource : displayName.Trim();
        var grps = (groups ?? Enumerable.Empty<string>())
            .Select(g => (g ?? "").Trim()).Where(g => g.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(g => g, StringComparer.OrdinalIgnoreCase).ToArray();

        string? outcome = null;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            var latest = hist.Where(i => Eq(i.Id, id)).OrderByDescending(i => i.Revision).FirstOrDefault();
            var next = new CatalogItem(id, resource, category, displayName, grps) { Revision = (latest?.Revision ?? 0) + 1 };
            if (latest is not null && latest.SameContent(next)) return JsonSerializer.Serialize(hist);
            hist.Add(next);
            outcome = latest is null ? "created" : "updated";
            return JsonSerializer.Serialize(hist);
        });
        if (outcome == "created") await _audit.Append(Ev(AuditEvents.CatalogItemCreated, actor, id, resource), ct);
        else if (outcome == "updated") await _audit.Append(Ev(AuditEvents.CatalogItemUpdated, actor, id, resource), ct);
        return null;
    }

    public async Task<bool> Delete(string id, string actor, CancellationToken ct)
    {
        var removed = false;
        _config.Mutate(Key, cur =>
        {
            var hist = Parse(cur);
            removed = hist.RemoveAll(i => Eq(i.Id, id)) > 0;
            return JsonSerializer.Serialize(hist);
        });
        if (removed) await _audit.Append(Ev(AuditEvents.CatalogItemDeleted, actor, id, ""), ct);
        return removed;
    }

    private List<CatalogItem> History() => Parse(_config.Get(Key));
    private static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static List<CatalogItem> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<List<CatalogItem>>(blob) ?? new());

    private AuditEvent Ev(string type, string actor, string id, string metadata) =>
        new(Guid.NewGuid().ToString("N"), _clock.GetUtcNow(), type, actor,
            Subject: id, Resource: metadata, RequestId: "", GrantId: "", Channel: "admin", Metadata: metadata);
}
