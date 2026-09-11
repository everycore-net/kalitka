using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Two persistent lists: <c>block</c> (never bother me again) and <c>allow</c>
/// (let this one straight through). Every entry is **scoped to a resource**, so a
/// decision made for one thing cannot leak to another — remembering the name
/// <c>root</c> for an SSH host must not wave a web visitor named <c>root</c> in,
/// and vice versa. An entry matches when its resource covers the request's and
/// its value matches the client IP, the subject, or — block list only — country.
///
/// Resource scope is <c>web:*</c>, <c>web:host</c>, <c>ssh:*</c>, <c>ssh:host</c>,
/// … A trailing <c>:*</c> covers every host in that scheme, but never crosses
/// schemes. Legacy entries without a resource are read as <c>web:*</c> — the old
/// web behaviour is preserved, but old allow-lists do not silently become PAM
/// policy.
///
/// The lists live behind an <see cref="IConfigStore"/> (files, SQLite or Postgres).
/// Reads use a short-lived in-memory cache; writes are an atomic read-modify-write
/// on the store, so several instances editing at once do not lose each other's
/// entries. Config therefore propagates across a cluster with a bounded lag (the
/// cache TTL), not instantly — fine for allow/block lists.
///
/// Country is deliberately not allowed on the allow list: "everyone from this
/// country walks in" is too coarse to ever be right.
/// </summary>
public sealed class AccessLists
{
    public sealed class Entry
    {
        /// <summary>block | allow</summary>
        public string List { get; set; } = "block";
        /// <summary>web:* | web:host | ssh:* | ssh:host | …</summary>
        public string Resource { get; set; } = "web:*";
        /// <summary>ip | subject | country</summary>
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
        public string Added { get; set; } = "";
    }

    private const string Key = "lists";
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(10);

    private readonly IConfigStore _store;
    private readonly TimeProvider _clock;
    private readonly ILogger<AccessLists> _log;
    private readonly object _lock = new();
    private List<Entry> _entries = new();
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;

    public AccessLists(IOptions<GateOptions> options, ILogger<AccessLists> log,
        IConfigStore? store = null, TimeProvider? clock = null)
    {
        _log = log;
        _clock = clock ?? TimeProvider.System;
        _store = store ?? new JsonFileConfigStore(options.Value, log);
        lock (_lock) Reload();
    }

    // Deserialise the stored blob and migrate pre-0.8.1 entries: no resource meant
    // the web behaviour they were created for, not a domain-wide policy; "input" is
    // now "subject". A broken blob is read as empty — "ask me about everyone" is the
    // safe direction and must never keep the gate from starting.
    private (List<Entry> entries, bool migrated) Parse(string? blob)
    {
        if (string.IsNullOrWhiteSpace(blob)) return (new(), false);
        List<Entry> list;
        try { list = JsonSerializer.Deserialize<List<Entry>>(blob) ?? new(); }
        catch (Exception e) { _log.LogWarning("Could not parse access lists: {Message}", e.Message); return (new(), false); }

        var migrated = false;
        foreach (var e in list)
        {
            if (string.IsNullOrEmpty(e.Resource)) { e.Resource = "web:*"; migrated = true; }
            if (e.Type == "input") { e.Type = "subject"; migrated = true; }
        }
        return (list, migrated);
    }

    // Caller holds _lock.
    private void Reload()
    {
        string? blob;
        try { blob = _store.Get(Key); }
        catch (Exception e) { _log.LogWarning("Could not read access lists: {Message}", e.Message); blob = null; }

        var (list, migrated) = Parse(blob);
        _entries = list;
        _loadedAt = _clock.GetUtcNow();

        // Persist the migration once, atomically (another instance may have already).
        if (migrated)
            try { _store.Mutate(Key, cur => JsonSerializer.Serialize(Parse(cur).entries)); }
            catch (Exception e) { _log.LogWarning("Could not persist migrated lists: {Message}", e.Message); }
    }

    // Caller holds _lock. Re-read from the store if the cache has aged out, so a
    // change made on another instance shows up within the TTL.
    private void EnsureFresh()
    {
        if (_clock.GetUtcNow() - _loadedAt >= Ttl) Reload();
    }

    private static string Normalise(string? s) => (s ?? "").Trim().ToLowerInvariant();

    /// <summary>Does an entry's scope cover this request's resource? Exact match,
    /// or a scheme wildcard (<c>web:*</c> covers <c>web:*</c> hosts) — never across
    /// schemes.</summary>
    private static bool Covers(string entryResource, string requestResource)
    {
        if (string.Equals(entryResource, requestResource, StringComparison.OrdinalIgnoreCase)) return true;
        if (entryResource.EndsWith(":*", StringComparison.Ordinal))
        {
            var scheme = entryResource[..^1];               // "web:"
            return requestResource.StartsWith(scheme, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private bool Matches(string list, string resource, string ip, string subject, string country)
    {
        foreach (var e in _entries)
        {
            if (e.List != list || !Covers(e.Resource, resource)) continue;
            var value = Normalise(e.Value);
            var hit = e.Type switch
            {
                "ip"      => Normalise(ip) == value,
                "subject" => Normalise(subject) == value,
                "country" => Normalise(country) == value,
                _         => false
            };
            if (hit) return true;
        }
        return false;
    }

    public bool IsBlocked(string resource, string ip, string subject, string country)
    {
        lock (_lock) { EnsureFresh(); return Matches("block", resource, ip, subject, country); }
    }

    public bool IsAllowed(string resource, string ip, string subject)
    {
        lock (_lock) { EnsureFresh(); return Matches("allow", resource, ip, subject, ""); }
    }

    public void Add(string list, string resource, string type, string value, string added)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(resource)) return;
        lock (_lock)
        {
            _store.Mutate(Key, cur =>
            {
                var entries = Parse(cur).entries;
                var exists = entries.Any(e =>
                    e.List == list && e.Type == type &&
                    string.Equals(e.Resource, resource, StringComparison.OrdinalIgnoreCase) &&
                    Normalise(e.Value) == Normalise(value));
                if (!exists)
                    entries.Add(new Entry { List = list, Resource = resource, Type = type, Value = value, Added = added });
                return JsonSerializer.Serialize(entries);
            });
            Reload();
        }
    }

    public IReadOnlyList<Entry> All(string list)
    {
        lock (_lock) { EnsureFresh(); return _entries.Where(e => e.List == list).ToList(); }
    }

    /// <summary>Removes the n-th entry of that list, counted as <see cref="All"/> returns them.</summary>
    public bool RemoveAt(string list, int index)
    {
        lock (_lock)
        {
            EnsureFresh();
            var ofList = _entries.Where(e => e.List == list).ToList();
            if (index < 0 || index >= ofList.Count) return false;
            var target = ofList[index];

            _store.Mutate(Key, cur =>
            {
                var entries = Parse(cur).entries;
                var victim = entries.FirstOrDefault(e =>
                    e.List == target.List && e.Resource == target.Resource && e.Type == target.Type &&
                    e.Value == target.Value && e.Added == target.Added);
                if (victim is not null) entries.Remove(victim);
                return JsonSerializer.Serialize(entries);
            });
            Reload();
            return true;
        }
    }
}
