using System.Text;
using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Microsoft/Entra identity extraction and — the security-critical part — tenant gating: the identity
/// is keyed on tid+oid, and a multi-tenant authority is safe only because a disallowed tenant is
/// rejected here.
/// </summary>
public class MicrosoftAuthTests
{
    private static MicrosoftAuth Auth(string tenant = "organizations", string[]? allowed = null) =>
        new(new HttpClient(), Options.Create(new GateOptions
        {
            GateHost = "gate.example.com",
            MicrosoftClientId = "cid",
            MicrosoftClientSecret = "sec",
            MicrosoftTenant = tenant,
            MicrosoftAllowedTenants = allowed ?? Array.Empty<string>(),
        }), NullLogger<MicrosoftAuth>.Instance);

    // A minimal id_token: only the payload segment is read (it arrived over TLS from the token
    // endpoint), so header and signature are placeholders.
    private static string IdToken(string json) =>
        "e30." + Base64Url.Encode(Encoding.UTF8.GetBytes(json)) + ".sig";

    [Fact]
    public void Identity_is_keyed_on_tid_and_oid_not_email()
    {
        var id = Auth().FromIdToken(IdToken("{\"tid\":\"T1\",\"oid\":\"O1\",\"email\":\"bob@corp.com\"}"));
        Assert.NotNull(id);
        Assert.Equal("ms", id!.Scheme);
        Assert.Equal("T1:O1", id.Subject);
        Assert.Equal("ms:T1:O1", id.Actor);
        Assert.Equal("bob@corp.com", id.Email);
    }

    [Fact]
    public void A_disallowed_tenant_is_rejected()
    {
        var auth = Auth(allowed: new[] { "TRUSTED" });
        Assert.Null(auth.FromIdToken(IdToken("{\"tid\":\"OTHER\",\"oid\":\"O1\",\"email\":\"x@y.com\"}")));
        Assert.NotNull(auth.FromIdToken(IdToken("{\"tid\":\"TRUSTED\",\"oid\":\"O1\",\"email\":\"x@y.com\"}")));
    }

    [Fact]
    public void Missing_tid_or_oid_is_rejected()
    {
        Assert.Null(Auth().FromIdToken(IdToken("{\"oid\":\"O1\"}")));
        Assert.Null(Auth().FromIdToken(IdToken("{\"tid\":\"T1\"}")));
    }

    [Fact]
    public void Email_falls_back_to_upn_or_preferred_username()
    {
        var id = Auth().FromIdToken(IdToken("{\"tid\":\"T1\",\"oid\":\"O1\",\"preferred_username\":\"bob@corp.com\"}"));
        Assert.Equal("bob@corp.com", id!.Email);
    }

    [Fact]
    public void A_single_tenant_authority_needs_no_allowlist()
    {
        // MicrosoftTenant is a specific tid → Entra only issues for it; no MicrosoftAllowedTenants set.
        var id = Auth(tenant: "T1").FromIdToken(IdToken("{\"tid\":\"T1\",\"oid\":\"O1\",\"email\":\"a@b.com\"}"));
        Assert.NotNull(id);
    }

    private static MicrosoftAuth VisitorAuth(string[]? emails = null, string[]? domains = null, string[]? tenants = null) =>
        new(new HttpClient(), Options.Create(new GateOptions
        {
            GateHost = "gate.example.com", MicrosoftClientId = "c", MicrosoftClientSecret = "s",
            MicrosoftEmails = emails ?? Array.Empty<string>(),
            MicrosoftDomains = domains ?? Array.Empty<string>(),
            MicrosoftAllowedTenants = tenants ?? Array.Empty<string>(),
        }), NullLogger<MicrosoftAuth>.Instance);

    [Fact]
    public void Visitor_allowlist_matches_email_or_domain()
    {
        Assert.True(VisitorAuth(emails: new[] { "bob@corp.com" }).IsPermitted("bob@corp.com"));
        Assert.True(VisitorAuth(domains: new[] { "corp.com" }).IsPermitted("anyone@corp.com"));
        Assert.False(VisitorAuth(domains: new[] { "corp.com" }).IsPermitted("x@other.com"));
    }

    [Fact]
    public void Visitor_tenant_wide_entry_only_when_the_tenant_is_restricted()
    {
        // No address/domain list but tenants restricted → trust the tenant gate.
        Assert.True(VisitorAuth(tenants: new[] { "T1" }).IsPermitted("anyone@corp.com"));
        // Nothing configured → fail closed (a multi-tenant authority must not let the world in).
        Assert.False(VisitorAuth().IsPermitted("anyone@corp.com"));
    }
}
