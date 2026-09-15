using System.Net;
using System.Text;
using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// The outcome of a primary-credential check. <see cref="Ok"/> is "the password is right".
/// <see cref="Sid"/>/<see cref="Upn"/> are the <b>canonical directory identity</b> resolved after a
/// successful bind — the string after a bind (the typed username) is not yet a stable identity, but
/// the AD objectSid is. When <see cref="Established"/>, RADIUS can assert a trusted <c>sid:</c>
/// subject, which is the same identity a Windows host agent asserts — so one person is one subject
/// across both entrances, and a covering grant can span them.
/// </summary>
public sealed record CredentialResult(bool Ok, string Sid = "", string Upn = "")
{
    public static readonly CredentialResult Fail = new(false);
    /// <summary>Verified <b>and</b> a canonical directory SID resolved — safe to trust as a subject.</summary>
    public bool Established => Ok && Sid.Length > 0;
}

/// <summary>
/// Verifies a user's primary credentials for the RADIUS channel — the "you are who you say" half,
/// before kalitka adds the "and an admin said yes" half. A seam so the check (LDAP today) can vary by
/// deployment without touching the RADIUS state machine.
/// </summary>
public interface ICredentialVerifier
{
    Task<CredentialResult> Verify(string username, string password, CancellationToken ct);
}

/// <summary>DEV/DEMO ONLY: accept any non-empty password. Turns RADIUS into approval-only with no
/// password check — never in production. No canonical identity, so the subject stays claimed.</summary>
public sealed class AcceptAnyCredentialVerifier : ICredentialVerifier
{
    public Task<CredentialResult> Verify(string username, string password, CancellationToken ct) =>
        Task.FromResult(!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password) ? new CredentialResult(true) : CredentialResult.Fail);
}

/// <summary>Fail-closed default: no verifier configured, so nothing verifies. Keeps RADIUS from
/// silently accepting when neither LDAP nor the dev switch is set.</summary>
public sealed class DenyAllCredentialVerifier : ICredentialVerifier
{
    public Task<CredentialResult> Verify(string username, string password, CancellationToken ct) => Task.FromResult(CredentialResult.Fail);
}

/// <summary>
/// Verifies credentials by binding to a domain controller as the user (a correct password is the only
/// way a bind succeeds). An empty password is rejected up front — an anonymous bind can otherwise
/// succeed and would be a false positive.
/// </summary>
public sealed class LdapCredentialVerifier : ICredentialVerifier
{
    private readonly GateOptions _options;
    private readonly ILogger<LdapCredentialVerifier> _log;

    public LdapCredentialVerifier(IOptions<GateOptions> options, ILogger<LdapCredentialVerifier> log)
    {
        _options = options.Value;
        _log = log;
    }

    public Task<CredentialResult> Verify(string username, string password, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return Task.FromResult(CredentialResult.Fail);

        var uri = new Uri(_options.LdapUrl);
        // Passwords travel to the DC on the bind, so ldaps:// is the norm. A plaintext ldap:// is
        // refused unless explicitly allowed for a trusted segment — fail closed, do not bind.
        if (uri.Scheme != "ldaps" && !_options.LdapAllowInsecure)
        {
            _log.LogError("LDAP verify refused: {Url} is not ldaps:// and LdapAllowInsecure is off", _options.LdapUrl);
            return Task.FromResult(CredentialResult.Fail);
        }

        return Task.Run(() =>
        {
            try
            {
                var id = new LdapDirectoryIdentifier(uri.Host, uri.IsDefaultPort ? (uri.Scheme == "ldaps" ? 636 : 389) : uri.Port);
                using var conn = new LdapConnection(id) { AuthType = AuthType.Basic };
                conn.SessionOptions.ProtocolVersion = 3;
                if (uri.Scheme == "ldaps") conn.SessionOptions.SecureSocketLayer = true;
                conn.Timeout = TimeSpan.FromSeconds(Math.Max(1, _options.LdapTimeoutSeconds));   // a hung DC must not pin the slot
                var bindName = string.Format(_options.LdapBindFormat, username);
                conn.Credential = new NetworkCredential(bindName, password);
                conn.Bind();   // throws unless the password is correct

                // Resolve the canonical identity so RADIUS can assert a trusted sid: — the same
                // subject a Windows host agent asserts. Best-effort: a failure here still verifies
                // the password, it only leaves the subject claimed (os:) rather than established.
                var (sid, upn) = ResolveIdentity(conn, username);
                return new CredentialResult(true, sid, upn);
            }
            catch (LdapException e)
            {
                _log.LogInformation("LDAP bind rejected for {User}: {Message}", username, e.Message);
                return CredentialResult.Fail;
            }
            catch (Exception e)
            {
                _log.LogWarning("LDAP verify error: {Message}", e.Message);
                return CredentialResult.Fail;   // fail closed
            }
        }, ct);
    }

    // Search the directory (as the just-bound user) for the user's own objectSid and UPN. Returns
    // empty strings when not configured or not found — never throws into the verify result.
    private (string Sid, string Upn) ResolveIdentity(LdapConnection conn, string username)
    {
        if (string.IsNullOrEmpty(_options.LdapSearchBase)) return ("", "");
        try
        {
            var filter = string.Format(_options.LdapUserFilter, EscapeFilter(username));
            var request = new SearchRequest(_options.LdapSearchBase, filter, SearchScope.Subtree, "objectSid", "userPrincipalName");
            if (conn.SendRequest(request) is not SearchResponse resp || resp.Entries.Count == 0) return ("", "");

            var entry = resp.Entries[0];
            var sid = "";
            if (entry.Attributes["objectSid"] is { Count: > 0 } sidAttr &&
                sidAttr.GetValues(typeof(byte[])) is { Length: > 0 } vals && vals[0] is byte[] bytes)
                sid = AdSid.FromBinary(bytes) ?? "";
            var upn = entry.Attributes["userPrincipalName"] is { Count: > 0 } upnAttr ? upnAttr[0] as string ?? "" : "";
            return (sid, upn);
        }
        catch (Exception e)
        {
            _log.LogWarning("LDAP identity resolution failed for {User}: {Message}", username, e.Message);
            return ("", "");
        }
    }

    // RFC 4515 escaping for the filter assertion value — never let a username inject into the filter.
    private static string EscapeFilter(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            sb.Append(c switch
            {
                '\\' => "\\5c", '*' => "\\2a", '(' => "\\28", ')' => "\\29", '\0' => "\\00",
                _ => c.ToString(),
            });
        return sb.ToString();
    }
}
