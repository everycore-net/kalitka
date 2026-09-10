using System.Text.Json;
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

    private readonly string _path;
    private readonly ILogger<AccessLists> _log;
    private readonly object _lock = new();
    private List<Entry> _entries = new();

    public AccessLists(IOptions<GateOptions> options, ILogger<AccessLists> log)
    {
        _path = options.Value.ListsPath;
        _log = log;
        Load();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            _entries = JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(_path)) ?? new();

            // Migrate pre-0.8.1 entries: no resource means the web behaviour they
            // were created for, not a domain-wide policy; "input" is now "subject".
            var migrated = false;
            foreach (var e in _entries)
            {
                if (string.IsNullOrEmpty(e.Resource)) { e.Resource = "web:*"; migrated = true; }
                if (e.Type == "input") { e.Type = "subject"; migrated = true; }
            }
            if (migrated) Save();
        }
        catch (Exception e)
        {
            // A broken list must not keep the gate from starting: an empty list
            // means "ask me about everyone", which is the safe direction.
            _log.LogWarning("Could not read {Path}: {Message}", _path, e.Message);
            _entries = new();
        }
    }

    private void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(_path, JsonSerializer.Serialize(_entries));
        }
        catch (Exception e)
        {
            _log.LogWarning("Could not write {Path}: {Message}", _path, e.Message);
        }
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
        lock (_lock) return Matches("block", resource, ip, subject, country);
    }

    public bool IsAllowed(string resource, string ip, string subject)
    {
        lock (_lock) return Matches("allow", resource, ip, subject, "");
    }

    public void Add(string list, string resource, string type, string value, string added)
    {
        if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(resource)) return;
        lock (_lock)
        {
            var exists = _entries.Any(e =>
                e.List == list && e.Type == type &&
                string.Equals(e.Resource, resource, StringComparison.OrdinalIgnoreCase) &&
                Normalise(e.Value) == Normalise(value));
            if (exists) return;

            _entries.Add(new Entry { List = list, Resource = resource, Type = type, Value = value, Added = added });
            Save();
        }
    }

    public IReadOnlyList<Entry> All(string list)
    {
        lock (_lock) return _entries.Where(e => e.List == list).ToList();
    }

    /// <summary>Removes the n-th entry of that list, counted as <see cref="All"/> returns them.</summary>
    public bool RemoveAt(string list, int index)
    {
        lock (_lock)
        {
            var ofList = _entries.Where(e => e.List == list).ToList();
            if (index < 0 || index >= ofList.Count) return false;
            _entries.Remove(ofList[index]);
            Save();
            return true;
        }
    }
}
