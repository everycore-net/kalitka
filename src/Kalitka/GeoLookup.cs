using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>Where a request appears to come from — shown in the notification only.</summary>
public sealed record Place(string Country, string CountryCode, string City)
{
    public static readonly Place Unknown = new("", "", "");
    public bool IsKnown => CountryCode.Length > 0;
}

/// <summary>
/// Rough IP geolocation for the notification. The point is that approving blind is
/// worse than approving slowly: "someone called Anna" is a different decision from
/// "someone called Anna, from a datacentre in a country you have no customers in".
///
/// It is a seam so the lookup can be an external HTTP service (<see cref="HttpGeoLookup"/>),
/// a local MaxMind database that keeps visitor IPs on the box
/// (<see cref="MaxMindGeoLookup"/>), or nothing (<see cref="NullGeoLookup"/>).
/// A lookup never blocks or fails a request: private addresses are skipped and any
/// error degrades to <see cref="Place.Unknown"/>.
/// </summary>
public interface IGeoLookup
{
    Task<Place> Locate(string ip, CancellationToken ct);
}

/// <summary>Shared helpers for the geo providers.</summary>
internal static class GeoNet
{
    /// <summary>Ranges that never leave the building — skip the lookup entirely,
    /// both to save a call and to never send an internal address to a third party.</summary>
    public static bool IsPrivate(string ip) =>
        ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.")
        || ip.StartsWith("172.16.") || ip.StartsWith("172.17.") || ip.StartsWith("172.18.")
        || ip.StartsWith("172.19.") || ip.StartsWith("172.2") || ip.StartsWith("172.30.")
        || ip.StartsWith("172.31.") || ip == "::1" || ip.StartsWith("fd") || ip.StartsWith("fe80");
}

/// <summary>No geolocation — always unknown. The privacy-first default when neither
/// a MaxMind database nor a URL is configured; the notification just omits the place.</summary>
public sealed class NullGeoLookup : IGeoLookup
{
    public Task<Place> Locate(string ip, CancellationToken ct) => Task.FromResult(Place.Unknown);
}

/// <summary>
/// HTTP geolocation (ip-api.com by default, via <see cref="GateOptions.GeoUrl"/>).
/// Convenient and keyless, but it sends every visitor's IP to a third party — a
/// GDPR consideration. <see cref="MaxMindGeoLookup"/> is the on-box alternative.
/// </summary>
public sealed class HttpGeoLookup : IGeoLookup
{
    private readonly HttpClient _http;
    private readonly GateOptions _options;
    private readonly ILogger<HttpGeoLookup> _log;

    public HttpGeoLookup(HttpClient http, IOptions<GateOptions> options, ILogger<HttpGeoLookup> log)
    {
        _http = http;
        _options = options.Value;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(6);
    }

    public async Task<Place> Locate(string ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ip) || GeoNet.IsPrivate(ip) || string.IsNullOrWhiteSpace(_options.GeoUrl))
            return Place.Unknown;

        try
        {
            var url = _options.GeoUrl.Replace("{ip}", Uri.EscapeDataString(ip));
            using var stream = await _http.GetStreamAsync(url, ct);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
            var root = doc.RootElement;

            return new Place(
                root.TryGetProperty("country", out var c) ? c.GetString() ?? "" : "",
                root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "" : "",
                root.TryGetProperty("city", out var ci) ? ci.GetString() ?? "" : "");
        }
        catch (Exception e)
        {
            _log.LogWarning("Geo lookup for {Ip} failed: {Message}", ip, e.Message);
            return Place.Unknown;
        }
    }
}
