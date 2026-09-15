using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>Config for one integration (Jira, Freshdesk, ServiceNow, …) that raises requests on
/// behalf of a person named in a ticket. It authenticates with a bearer <see cref="Token"/>, may only
/// ask for resources within <see cref="Scope"/>, is rate-limited, and audits under its own actor
/// (<c>integration:&lt;id&gt;</c>). It never approves — it can only raise (the same invariant as the
/// missing approve tool in the MCP server).</summary>
public sealed class IntegrationClientOptions
{
    public string Id { get; set; } = "";
    public string Token { get; set; } = "";
    /// <summary>Resource globs this integration may ask for (e.g. <c>rdp:*</c>, <c>db:reports</c>).</summary>
    public string[] Scope { get; set; } = Array.Empty<string>();
    public int MaxRequestsPerMinute { get; set; } = 60;
}

public sealed record IntegrationClient(string Id, string[] Scope, int MaxRequestsPerMinute)
{
    /// <summary>May this integration ask for <paramref name="resource"/>? True iff one of its scope
    /// globs covers it — same matcher as covering grants, so scope means the same everywhere.</summary>
    public bool MayRequest(string resource) => Scope.Any(s => Coverage.Covers(s, resource));

    /// <summary>The audit/actor identity — never an anonymous "system".</summary>
    public string Actor => "integration:" + Id;
}

/// <summary>
/// Resolves an integration by its bearer token (constant-time) and rate-limits it. Built from
/// <see cref="GateOptions.IntegrationClients"/>; empty means the request API is closed.
/// </summary>
public sealed class IntegrationRegistry
{
    private readonly List<(byte[] Token, IntegrationClient Client)> _clients = new();
    private readonly TimeProvider _clock;
    private readonly ConcurrentWindow _rate = new();

    public IntegrationRegistry(IOptions<GateOptions> options, TimeProvider? clock = null)
    {
        _clock = clock ?? TimeProvider.System;
        foreach (var c in options.Value.IntegrationClients)
        {
            if (string.IsNullOrWhiteSpace(c.Id) || string.IsNullOrEmpty(c.Token)) continue;
            _clients.Add((Encoding.UTF8.GetBytes(c.Token),
                new IntegrationClient(c.Id.Trim(), c.Scope ?? Array.Empty<string>(), Math.Max(1, c.MaxRequestsPerMinute))));
        }
    }

    public bool Any => _clients.Count > 0;

    /// <summary>The integration for a bearer token, or null. Compares every candidate in constant
    /// time so a wrong token cannot be distinguished by timing.</summary>
    public IntegrationClient? Resolve(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var bytes = Encoding.UTF8.GetBytes(token);
        IntegrationClient? match = null;
        foreach (var (candidate, client) in _clients)
            if (CryptographicOperations.FixedTimeEquals(candidate, bytes)) match = client;
        return match;
    }

    /// <summary>Record a request and report whether the integration is within its per-minute budget.</summary>
    public bool WithinRate(IntegrationClient client) =>
        _rate.Allow(client.Id, client.MaxRequestsPerMinute, TimeSpan.FromMinutes(1), _clock.GetUtcNow());

    // A tiny per-key fixed-window rate limiter.
    private sealed class ConcurrentWindow
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (int Count, DateTimeOffset Start)> _w = new();
        public bool Allow(string key, int max, TimeSpan window, DateTimeOffset now)
        {
            var updated = _w.AddOrUpdate(key,
                _ => (1, now),
                (_, cur) => now - cur.Start >= window ? (1, now) : (cur.Count + 1, cur.Start));
            return updated.Count <= max;
        }
    }
}

/// <summary>
/// Idempotency for integration requests: one ticket, one request. Maps <c>(integration, external id)</c>
/// to the request id we raised, so a retried call returns the same request rather than multiplying it.
/// Durable, in the shared config store, so it holds across restarts and nodes. (A concurrent first
/// call for the same ticket can still race to two requests; the loser is a waiting request that
/// expires — hardened with an atomic reserve later, alongside webhooks.)
/// </summary>
public sealed class IntegrationIdempotency
{
    private const string Key = "integration-idempotency";
    private readonly IConfigStore _config;

    public IntegrationIdempotency(IConfigStore config) => _config = config;

    public static string Compose(string integrationId, string externalId) => integrationId + "\n" + externalId;

    public string? Lookup(string compositeKey) =>
        Parse(_config.Get(Key)).TryGetValue(compositeKey, out var id) ? id : null;

    /// <summary>Record the request id for a key, keeping the first if one is already there.</summary>
    public void Record(string compositeKey, string requestId)
    {
        _config.Mutate(Key, cur =>
        {
            var map = Parse(cur);
            if (!map.ContainsKey(compositeKey)) map[compositeKey] = requestId;
            return JsonSerializer.Serialize(map);
        });
    }

    private static Dictionary<string, string> Parse(string? blob) =>
        string.IsNullOrWhiteSpace(blob) ? new() : (JsonSerializer.Deserialize<Dictionary<string, string>>(blob) ?? new());
}
