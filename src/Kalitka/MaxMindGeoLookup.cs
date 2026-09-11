using System.Net;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;
using Microsoft.Extensions.Logging;

namespace Kalitka;

/// <summary>
/// On-box geolocation from a local MaxMind GeoLite2/GeoIP2 database (.mmdb). Unlike
/// <see cref="HttpGeoLookup"/> it sends no visitor IP anywhere — the lookup is a
/// read against a file, which is the privacy answer for GDPR-sensitive deployments.
///
/// The database is not shipped: it needs a (free) MaxMind account + licence key and
/// a periodic download, pointed at by <see cref="GateOptions.GeoDbPath"/>. Works
/// with a City database (country + city) or a Country-only one (country). The reader
/// is thread-safe and long-lived, so this is a singleton. Like every provider it
/// never fails a request — an unknown address or any error degrades to
/// <see cref="Place.Unknown"/>.
/// </summary>
public sealed class MaxMindGeoLookup : IGeoLookup, IDisposable
{
    private readonly DatabaseReader _reader;
    private readonly bool _hasCity;
    private readonly ILogger<MaxMindGeoLookup> _log;

    public MaxMindGeoLookup(string dbPath, ILogger<MaxMindGeoLookup> log)
    {
        _log = log;
        _reader = new DatabaseReader(dbPath);   // throws if the file is missing or not an .mmdb
        // GeoLite2-City / GeoIP2-City vs -Country: pick the query the db can answer.
        _hasCity = _reader.Metadata.DatabaseType.Contains("City", StringComparison.OrdinalIgnoreCase);
    }

    public Task<Place> Locate(string ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ip) || GeoNet.IsPrivate(ip) || !IPAddress.TryParse(ip, out var addr))
            return Task.FromResult(Place.Unknown);

        try
        {
            if (_hasCity)
            {
                var r = _reader.City(addr);
                return Task.FromResult(new Place(
                    r.Country.Name ?? "", r.Country.IsoCode ?? "", r.City.Name ?? ""));
            }

            var c = _reader.Country(addr);
            return Task.FromResult(new Place(c.Country.Name ?? "", c.Country.IsoCode ?? "", ""));
        }
        catch (AddressNotFoundException)
        {
            return Task.FromResult(Place.Unknown);   // IP simply not in the database
        }
        catch (Exception e)
        {
            _log.LogWarning("MaxMind lookup for {Ip} failed: {Message}", ip, e.Message);
            return Task.FromResult(Place.Unknown);
        }
    }

    public void Dispose() => _reader.Dispose();
}
