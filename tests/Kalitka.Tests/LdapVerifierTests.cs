using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// LdapCredentialVerifier fails closed: an empty password never binds, and a plaintext ldap:// URL
/// is refused (no bind attempted) unless insecure LDAP is explicitly allowed — passwords go to the
/// DC on the bind, so ldaps:// is the norm.
/// </summary>
public class LdapVerifierTests
{
    private static LdapCredentialVerifier Verifier(string url, bool allowInsecure)
    {
        var opts = Options.Create(new GateOptions { LdapUrl = url, LdapAllowInsecure = allowInsecure });
        return new LdapCredentialVerifier(opts, NullLogger<LdapCredentialVerifier>.Instance);
    }

    [Fact]
    public async Task An_empty_password_is_rejected_without_binding()
    {
        var v = Verifier("ldaps://dc.example", allowInsecure: false);
        Assert.False((await v.Verify("anna", "", default)).Ok);
    }

    [Fact]
    public async Task A_plaintext_ldap_url_is_refused_unless_explicitly_allowed()
    {
        // Refused before any connection — fail closed, do not send the password in the clear.
        var refused = Verifier("ldap://dc.example", allowInsecure: false);
        Assert.False((await refused.Verify("anna", "pw", default)).Ok);
    }
}
