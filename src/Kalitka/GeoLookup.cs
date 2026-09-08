using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Rough IP geolocation, shown in the notification only. The point is that
/// approving blind is worse than approving slowly: "someone called Anna" is
/// a different decision from "someone called Anna, from a datacentre in a
/// country you have no customers in".
///
/// Never blocks the request: private addresses are skipped and any failure
/// degrades to "unknown".
/// </summary>
public sealed class GeoLookup
{
    private readonly HttpClient _http;
    private readonly GateOptions _options;
    private readonly ILogger<GeoLookup> _log;

    public GeoLookup(HttpClient http, IOptions<GateOptions> options, ILogger<GeoLookup> log)
    {
        _http = http;
        _options = options.Value;
        _log = log;
        _http.Timeout = TimeSpan.FromSeconds(6);
    }

    public sealed record Place(string Country, string CountryCode, string City)
    {
        public static readonly Place Unknown = new("", "", "");
        public bool IsKnown => CountryCode.Length > 0;
    }

    public async Task<Place> Locate(string ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ip) || IsPrivate(ip) || string.IsNullOrWhiteSpace(_options.GeoUrl))
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

    public static bool IsPrivate(string ip) =>
        ip.StartsWith("10.") || ip.StartsWith("192.168.") || ip.StartsWith("127.")
        || ip.StartsWith("172.16.") || ip.StartsWith("172.17.") || ip.StartsWith("172.18.")
        || ip.StartsWith("172.19.") || ip.StartsWith("172.2") || ip.StartsWith("172.30.")
        || ip.StartsWith("172.31.") || ip == "::1" || ip.StartsWith("fd") || ip.StartsWith("fe80");
}
