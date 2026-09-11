using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Kalitka;

/// <summary>
/// Where the per-instance <i>config</i> lives — the block/allow lists, which hosts
/// are armed, and runtime settings. Small, rarely-written state, kept as one JSON
/// blob per key ("lists", "enforced", "settings"). Two operations:
///
/// * <see cref="Get"/> — read the blob (or null if unset).
/// * <see cref="Mutate"/> — an <b>atomic</b> read-modify-write: the store hands the
///   current blob to <paramref name="update"/> and persists what it returns, under a
///   lock/transaction so two instances editing at once cannot lose each other's
///   change. This is what makes config multi-node-safe, not just durable.
///
/// The blob format is the caller's (the same JSON the file backend has always
/// written), so file-backed deployments keep their exact lists.json / enforced.json
/// / settings.json — the store only changes the medium, not the shape.
/// </summary>
public interface IConfigStore
{
    string? Get(string key);
    void Mutate(string key, Func<string?, string> update);
}

/// <summary>Single-process config: a dictionary under a lock. For tests and the
/// no-persistence default.</summary>
public sealed class InMemoryConfigStore : IConfigStore
{
    private readonly Dictionary<string, string> _d = new();
    private readonly object _lock = new();

    public string? Get(string key)
    {
        lock (_lock) return _d.TryGetValue(key, out var v) ? v : null;
    }

    public void Mutate(string key, Func<string?, string> update)
    {
        lock (_lock)
        {
            _d.TryGetValue(key, out var cur);
            _d[key] = update(cur);
        }
    }
}

/// <summary>
/// The file backend — today's behaviour, preserved for single-instance deployments:
/// "lists"/"enforced"/"settings" map to <c>ListsPath</c>/<c>EnforcedPath</c>/
/// <c>SettingsPath</c>, and the blob is the file's text verbatim. Any other key
/// (e.g. "agent-profiles") is a <c>&lt;key&gt;.json</c> file in the same data
/// directory, so new config keys persist without a schema change. Not multi-node
/// (each instance has its own files); a broken read degrades to null, never throws.
/// </summary>
public sealed class JsonFileConfigStore : IConfigStore
{
    private readonly IReadOnlyDictionary<string, string> _paths;
    private readonly string _baseDir;
    private readonly ILogger _log;
    private readonly object _lock = new();

    public JsonFileConfigStore(GateOptions o, ILogger log)
    {
        _paths = new Dictionary<string, string>
        {
            ["lists"] = o.ListsPath,
            ["enforced"] = o.EnforcedPath,
            ["settings"] = o.SettingsPath,
        };
        // Derive other keys' files next to the settings file (all three default to /data).
        _baseDir = Path.GetDirectoryName(o.SettingsPath) is { Length: > 0 } d ? d : ".";
        _log = log;
    }

    // Known keys keep their exact configured path; anything else is a file in the
    // data directory. Only sane key names become files (no path separators).
    private string? PathFor(string key) =>
        _paths.TryGetValue(key, out var p) ? p
        : key.IndexOfAny(new[] { '/', '\\', '.' }) < 0 ? Path.Combine(_baseDir, key + ".json")
        : null;

    public string? Get(string key)
    {
        var path = PathFor(key);
        if (path is null) return null;
        lock (_lock)
        {
            try { return File.Exists(path) ? File.ReadAllText(path) : null; }
            catch (Exception e) { _log.LogWarning("Could not read {Path}: {Message}", path, e.Message); return null; }
        }
    }

    public void Mutate(string key, Func<string?, string> update)
    {
        var path = PathFor(key);
        if (path is null) return;
        lock (_lock)
        {
            string? cur = null;
            try { if (File.Exists(path)) cur = File.ReadAllText(path); }
            catch (Exception e) { _log.LogWarning("Could not read {Path}: {Message}", path, e.Message); }

            var next = update(cur);
            try
            {
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(path, next);
            }
            catch (Exception e) { _log.LogWarning("Could not write {Path}: {Message}", path, e.Message); }
        }
    }
}
