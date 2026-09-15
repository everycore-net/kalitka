namespace Kalitka;

/// <summary>
/// Whether one approved <b>scope</b> covers a concrete resource — the heart of covering grants
/// (see docs/design/covering-grant.md). A perimeter approval (e.g. a RADIUS gateway) may be
/// configured to cover a family of hosts, so a person approved once at the perimeter does not face
/// a second approval on each host behind it. The matcher is deliberately tiny and same-kind only:
/// a valid perimeter session must never be a blank cheque across resource kinds.
/// </summary>
public static class Coverage
{
    /// <summary>
    /// True iff <paramref name="scope"/> covers <paramref name="resource"/>. A scope is either an
    /// exact resource (<c>rdp:host</c> covers only itself) or a single trailing <c>*</c> wildcard on
    /// a prefix that already names a resource kind (<c>rdp:*</c> covers any <c>rdp:…</c>;
    /// <c>rdp:site-a/*</c> covers <c>rdp:site-a/…</c>). No regex, no set arithmetic, and never across
    /// kinds — a bare <c>*</c> or a wildcard before the kind's <c>:</c> covers nothing, so an
    /// <c>rdp:</c> scope can never reach a <c>db:</c> resource.
    /// </summary>
    public static bool Covers(string? scope, string? resource)
    {
        if (string.IsNullOrEmpty(scope) || string.IsNullOrEmpty(resource)) return false;
        if (!scope.Contains(':')) return false;   // a scope must name a resource kind

        if (scope.EndsWith('*'))
        {
            var prefix = scope[..^1];
            // The wildcard must sit after the kind boundary, so it can only widen within one kind.
            if (!prefix.Contains(':')) return false;
            return resource.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(scope, resource, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>How many of the known resources a scope covers — the "17 hosts" shown next to the
    /// scope at approval time, so the blast radius of <c>rdp:site-a/*</c> is visible in the moment of
    /// the decision, not just the glob. Distinct, case-insensitive.</summary>
    public static int Cardinality(string? scope, IEnumerable<string> knownResources)
    {
        if (string.IsNullOrEmpty(scope)) return 0;
        return knownResources
            .Where(r => Covers(scope, r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
    }
}
