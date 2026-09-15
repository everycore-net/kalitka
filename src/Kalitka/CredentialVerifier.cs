using System.Net;
using System.DirectoryServices.Protocols;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Kalitka;

/// <summary>
/// Verifies a user's primary credentials for the RADIUS channel — the "you are who you say" half,
/// before kalitka adds the "and an admin said yes" half. A seam so the check (LDAP today) can vary by
/// deployment without touching the RADIUS state machine.
/// </summary>
public interface ICredentialVerifier
{
    Task<bool> Verify(string username, string password, CancellationToken ct);
}

/// <summary>DEV/DEMO ONLY: accept any non-empty password. Turns RADIUS into approval-only with no
/// password check — never in production.</summary>
public sealed class AcceptAnyCredentialVerifier : ICredentialVerifier
{
    public Task<bool> Verify(string username, string password, CancellationToken ct) =>
        Task.FromResult(!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password));
}

/// <summary>Fail-closed default: no verifier configured, so nothing verifies. Keeps RADIUS from
/// silently accepting when neither LDAP nor the dev switch is set.</summary>
public sealed class DenyAllCredentialVerifier : ICredentialVerifier
{
    public Task<bool> Verify(string username, string password, CancellationToken ct) => Task.FromResult(false);
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

    public Task<bool> Verify(string username, string password, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password)) return Task.FromResult(false);
        return Task.Run(() =>
        {
            try
            {
                var uri = new Uri(_options.LdapUrl);
                var id = new LdapDirectoryIdentifier(uri.Host, uri.IsDefaultPort ? (uri.Scheme == "ldaps" ? 636 : 389) : uri.Port);
                using var conn = new LdapConnection(id) { AuthType = AuthType.Basic };
                conn.SessionOptions.ProtocolVersion = 3;
                if (uri.Scheme == "ldaps") conn.SessionOptions.SecureSocketLayer = true;
                var bindName = string.Format(_options.LdapBindFormat, username);
                conn.Credential = new NetworkCredential(bindName, password);
                conn.Bind();   // throws unless the password is correct
                return true;
            }
            catch (LdapException e)
            {
                _log.LogInformation("LDAP bind rejected for {User}: {Message}", username, e.Message);
                return false;
            }
            catch (Exception e)
            {
                _log.LogWarning("LDAP verify error: {Message}", e.Message);
                return false;   // fail closed
            }
        }, ct);
    }
}
