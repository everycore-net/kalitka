using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The beneficiary check enables RDP only for the exact person Core approved, matched on the full
/// stable subject identity (os:DOMAIN\user) — never a bare login name. The regression this guards is
/// the confused deputy: <c>CONTOSO\anna</c> and <c>SRV01\anna</c> share the login "anna" but are
/// different people, and a grant approved for one must not enable the other.
/// </summary>
public class BeneficiaryMatchTests
{
    private static CallerSubject Caller(string account) =>
        new("S-1-5-21-" + account.GetHashCode(), account, account[(account.IndexOf('\\') + 1)..], "os:" + account);

    [Fact]
    public void Matches_the_same_full_identity_case_insensitively()
    {
        var c = Caller("CONTOSO\\anna");
        Assert.True(RdpActivator.BeneficiaryMatches("os:CONTOSO\\anna", c));
        Assert.True(RdpActivator.BeneficiaryMatches("os:contoso\\anna", c));   // Core stores it lower-cased
    }

    [Fact]
    public void Rejects_the_same_login_in_a_different_domain_or_machine()
    {
        // The old tail-compare passed this — the hole finding #2 closes.
        Assert.False(RdpActivator.BeneficiaryMatches("os:CONTOSO\\anna", Caller("SRV01\\anna")));
        Assert.False(RdpActivator.BeneficiaryMatches("os:DOMAIN-A\\svc", Caller("DOMAIN-B\\svc")));
    }

    [Fact]
    public void An_empty_or_missing_approved_identity_never_matches()
    {
        var c = Caller("CONTOSO\\anna");
        Assert.False(RdpActivator.BeneficiaryMatches("", c));
        Assert.False(RdpActivator.BeneficiaryMatches(null, c));
    }

    [Fact]
    public void BeneficiaryDenial_separates_version_skew_from_a_real_mismatch()
    {
        var c = Caller("CONTOSO\\anna");
        // Both refuse (fail closed), but the operator's fix differs: upgrade Core vs investigate a grant
        // for someone else. A bare beneficiary-mismatch on a version skew read as a security event.
        Assert.Null(RdpActivator.BeneficiaryDenial("os:contoso\\anna", c));                       // may proceed
        Assert.Equal(GrantOutcome.SubjectIdentityMissing, RdpActivator.BeneficiaryDenial("", c)); // Core too old
        Assert.Equal(GrantOutcome.SubjectIdentityMissing, RdpActivator.BeneficiaryDenial(null, c));
        Assert.Equal(GrantOutcome.Forbidden, RdpActivator.BeneficiaryDenial("os:SRV01\\anna", c)); // genuine mismatch
    }
}
