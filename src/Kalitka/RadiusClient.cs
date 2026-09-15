using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// One RADIUS client kalitka answers: matched by the <b>source of the UDP datagram</b> (an exact IP
/// or a CIDR), never by a NAS attribute the packet chose. Each client brings its own shared secret,
/// the <see cref="Resource"/> its approvals are about (the policy namespace — a VPN and an RD Gateway
/// must not share one just because both send RADIUS), a display name, and an optional per-client
/// Message-Authenticator requirement. <see cref="SecretPrevious"/> is accepted alongside
/// <see cref="Secret"/> so the shared secret can be rotated without a flap — the same overlap
/// discipline as the signing keys.
/// </summary>
public sealed record RadiusClient(
    string Secret, string SecretPrevious, string Resource, string DisplayName, bool? RequireMessageAuthenticator,
    string GrantScope = "");

/// <summary>Bound from config: a RADIUS client entry.</summary>
public sealed class RadiusClientOptions
{
    /// <summary>The datagram source that identifies this client: an exact IP (<c>10.0.0.10</c>) or a
    /// CIDR (<c>10.0.0.0/24</c>). The most specific match wins.</summary>
    public string Source { get; set; } = "";
    public string Secret { get; set; } = "";
    /// <summary>The previous secret, accepted during a rotation window.</summary>
    public string SecretPrevious { get; set; } = "";
    /// <summary>The resource/policy namespace this client's approvals are about, e.g.
    /// <c>rdp:rdgw-prod</c>, <c>vpn:office</c>, <c>network:wifi-corp</c>.</summary>
    public string Resource { get; set; } = "";
    public string DisplayName { get; set; } = "";
    /// <summary>Override the global Message-Authenticator requirement for this one client
    /// (the legacy escape hatch, scoped where it belongs). Null = use the global default.</summary>
    public bool? RequireMessageAuthenticator { get; set; }

    /// <summary>The covering scope this client's approvals may cover — a resource glob bounding what a
    /// perimeter approval here can reach (e.g. gateway RDG-01 covers <c>rdp:site-a/*</c>). Set on the
    /// client (channel config), never by the requester. Empty = this client's approvals cover only
    /// their exact resource. See docs/design/covering-grant.md.</summary>
    public string GrantScope { get; set; } = "";
}

/// <summary>
/// Resolves the RADIUS client for a datagram source. Built from <see cref="GateOptions.RadiusClients"/>;
/// if none are configured but a legacy <see cref="GateOptions.RadiusSharedSecret"/> is set, a single
/// catch-all client is synthesised from the legacy fields, so existing deployments keep working.
/// </summary>
public sealed class RadiusClientRegistry
{
    private sealed record Rule(byte[] Network, int Prefix, AddressFamily Family, bool MatchAll, RadiusClient Client);

    private readonly List<Rule> _rules = new();

    public RadiusClientRegistry(IOptions<GateOptions> options)
    {
        var o = options.Value;
        foreach (var c in o.RadiusClients)
        {
            if (string.IsNullOrWhiteSpace(c.Source) || string.IsNullOrEmpty(c.Secret)) continue;
            var client = new RadiusClient(c.Secret, c.SecretPrevious ?? "",
                string.IsNullOrWhiteSpace(c.Resource) ? o.RadiusResource : c.Resource,
                string.IsNullOrWhiteSpace(c.DisplayName) ? c.Source : c.DisplayName,
                c.RequireMessageAuthenticator, c.GrantScope ?? "");
            if (TryParseRule(c.Source, client, out var rule)) _rules.Add(rule);
        }

        // Legacy fallback: no registry, but a single shared secret configured → one catch-all client.
        if (_rules.Count == 0 && !string.IsNullOrEmpty(o.RadiusSharedSecret))
            _rules.Add(new Rule(Array.Empty<byte>(), 0, AddressFamily.Unspecified, MatchAll: true,
                new RadiusClient(o.RadiusSharedSecret, o.RadiusSharedSecretPrevious ?? "", o.RadiusResource, "radius", null)));
    }

    /// <summary>Whether any client is configured — used to keep the listener dormant otherwise.</summary>
    public bool HasAny => _rules.Count > 0;

    /// <summary>The client for a datagram source, most-specific match first, or null if none.</summary>
    public RadiusClient? Match(IPAddress source)
    {
        var addr = source.GetAddressBytes();
        Rule? best = null;
        foreach (var r in _rules)
        {
            if (r.MatchAll) { best ??= r; continue; }          // catch-all is the least specific
            if (r.Family != source.AddressFamily) continue;
            if (!PrefixMatches(addr, r.Network, r.Prefix)) continue;
            if (best is null || best.MatchAll || r.Prefix > best.Prefix) best = r;
        }
        return best?.Client;
    }

    private static bool TryParseRule(string source, RadiusClient client, out Rule rule)
    {
        rule = null!;
        var slash = source.IndexOf('/');
        var ipPart = slash >= 0 ? source[..slash] : source;
        if (!IPAddress.TryParse(ipPart.Trim(), out var ip)) return false;

        var bytes = ip.GetAddressBytes();
        var fullBits = bytes.Length * 8;
        var prefix = fullBits;
        if (slash >= 0)
        {
            if (!int.TryParse(source[(slash + 1)..], out prefix) || prefix < 0 || prefix > fullBits) return false;
        }
        rule = new Rule(bytes, prefix, ip.AddressFamily, MatchAll: false, client);
        return true;
    }

    // Compare the first <paramref name="prefix"/> bits of two same-length addresses.
    private static bool PrefixMatches(byte[] addr, byte[] network, int prefix)
    {
        if (addr.Length != network.Length) return false;
        var fullBytes = prefix / 8;
        for (var i = 0; i < fullBytes; i++)
            if (addr[i] != network[i]) return false;
        var rem = prefix % 8;
        if (rem == 0) return true;
        var mask = (byte)(0xFF << (8 - rem));
        return (addr[fullBytes] & mask) == (network[fullBytes] & mask);
    }
}
