using System.Net;
using System.Net.Sockets;

namespace Kalitka;

/// <summary>
/// Works out who the client actually is. Everything kalitka decides — allow,
/// block, bypass, rate limit — rests on this one answer, so it is deliberately
/// paranoid and deliberately testable.
///
/// Two mistakes are easy to make here and both are fatal:
///
/// 1. <b>Taking the leftmost entry of X-Forwarded-For.</b> A proxy only ever
///    appends on the right; everything to the left is whatever the caller
///    wrote. Reading left to right means the client picks their own address —
///    and with it their own place on your allow list. The real client is found
///    by walking from the right and skipping the proxies you trust.
///
/// 2. <b>Trusting the headers at all.</b> They mean nothing unless the request
///    reached you from a proxy you trust. If it did not, the only honest answer
///    is the address the connection actually came from.
/// </summary>
public static class ClientIp
{
    /// <summary>
    /// The address to make decisions about, plus whether forwarded headers were
    /// honoured. The flag is worth logging: "we ignored the headers" explains a
    /// whole class of surprised bug reports.
    /// </summary>
    public readonly record struct Result(string Ip, bool ForwardedHonoured);

    public static Result Resolve(string? peer, string? forwardedFor, string? realIp, IReadOnlyList<IPNetwork> trustedProxies)
    {
        var peerAddress = Parse(peer);

        // No trusted proxies configured, or the request did not come from one:
        // the headers are hearsay. Use what the socket says.
        if (peerAddress is null || trustedProxies.Count == 0 || !IsTrusted(peerAddress, trustedProxies))
            return new Result(peerAddress?.ToString() ?? "", false);

        // Right to left: the last entry was appended by the proxy nearest to us.
        // Skip our own proxies; the first address that is not one of them is the
        // client. Anything further left is unverifiable and must be ignored.
        var chain = (forwardedFor ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => Parse(part))
            .Where(address => address is not null)
            .Select(address => address!)
            .ToList();

        for (var i = chain.Count - 1; i >= 0; i--)
        {
            if (!IsTrusted(chain[i], trustedProxies))
                return new Result(chain[i].ToString(), true);
        }

        // Every hop was a trusted proxy — a health check or an internal caller.
        // X-Real-Ip is a single value set by the nearest proxy, so it is usable
        // once we know that proxy is trusted.
        var real = Parse(realIp);
        if (real is not null) return new Result(real.ToString(), true);

        return new Result(peerAddress.ToString(), true);
    }

    private static bool IsTrusted(IPAddress address, IReadOnlyList<IPNetwork> trusted)
    {
        foreach (var network in trusted)
        {
            // A v4 address arriving over a dual-stack socket looks like
            // ::ffff:10.0.0.1 and would not match a v4 network otherwise.
            var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
            if (network.BaseAddress.AddressFamily != candidate.AddressFamily) continue;
            if (network.Contains(candidate)) return true;
        }
        return false;
    }

    private static IPAddress? Parse(string? value)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value)) return null;

        // Proxies may append a port ("10.0.0.1:51234"), and IPv6 arrives in
        // brackets. Strip both before parsing.
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close > 0) value = value[1..close];
        }
        else if (value.Count(c => c == ':') == 1)
        {
            value = value[..value.IndexOf(':')];
        }

        if (!IPAddress.TryParse(value, out var address)) return null;

        return address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6
            ? address
            : null;
    }

    /// <summary>Parses CIDR entries, skipping malformed ones rather than failing.</summary>
    public static List<IPNetwork> ParseNetworks(IEnumerable<string> cidrs, Action<string>? onBad = null)
    {
        var networks = new List<IPNetwork>();
        foreach (var entry in cidrs)
        {
            try { networks.Add(IPNetwork.Parse(entry.Trim())); }
            catch { onBad?.Invoke(entry); }
        }
        return networks;
    }
}
