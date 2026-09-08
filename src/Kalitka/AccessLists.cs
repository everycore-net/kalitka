using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Two persistent lists: <c>block</c> (never bother me again) and
/// <c>allow</c> (let this one straight through). An entry matches on the
/// client IP, on what the visitor typed, or — block list only — on country.
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
        /// <summary>ip | input | country</summary>
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
            if (File.Exists(_path))
                _entries = JsonSerializer.Deserialize<List<Entry>>(File.ReadAllText(_path)) ?? new();
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

    private bool Matches(string list, string ip, string input, string country)
    {
        foreach (var e in _entries)
        {
            if (e.List != list) continue;
            var value = Normalise(e.Value);
            var hit = e.Type switch
            {
                "ip"      => Normalise(ip) == value,
                "input"   => Normalise(input) == value,
                "country" => Normalise(country) == value,
                _         => false
            };
            if (hit) return true;
        }
        return false;
    }

    public bool IsBlocked(string ip, string input, string country)
    {
        lock (_lock) return Matches("block", ip, input, country);
    }

    public bool IsAllowed(string ip, string input)
    {
        lock (_lock) return Matches("allow", ip, input, "");
    }

    public void Add(string list, string type, string value, string added)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        lock (_lock)
        {
            var exists = _entries.Any(e =>
                e.List == list && e.Type == type && Normalise(e.Value) == Normalise(value));
            if (exists) return;

            _entries.Add(new Entry { List = list, Type = type, Value = value, Added = added });
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
