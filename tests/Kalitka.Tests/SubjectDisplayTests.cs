using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// <see cref="PendingRequest.SubjectDisplay"/> — the one string every notifier renders to the approver:
/// the asserted machine identity plus the SID when both are known, so a privileged action is decided
/// against the real principal rather than a spoofable bare login.
/// </summary>
public class SubjectDisplayTests
{
    private static PendingRequest Req(string identity, string sid) =>
        new() { SubjectIdentity = identity, SubjectSid = sid };

    [Fact]
    public void Account_and_sid_are_shown_together()
    {
        Assert.Equal("os:contoso\\anna (sid:S-1-5-21-1-2-3-1104)",
            Req("os:contoso\\anna", "S-1-5-21-1-2-3-1104").SubjectDisplay());
    }

    [Fact]
    public void Account_alone_when_no_sid()
    {
        Assert.Equal("os:contoso\\anna", Req("os:contoso\\anna", "").SubjectDisplay());
    }

    [Fact]
    public void A_sid_identity_is_not_doubled()
    {
        // The RADIUS path already carries the SID as the identity (sid:…); don't append it twice.
        Assert.Equal("sid:S-1-5-21-1-2-3-1104", Req("sid:S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1104").SubjectDisplay());
    }

    [Fact]
    public void Sid_only_falls_back_to_a_sid_label()
    {
        Assert.Equal("sid:S-1-5-21-1-2-3-1104", Req("", "S-1-5-21-1-2-3-1104").SubjectDisplay());
    }

    [Fact]
    public void No_subject_is_empty()
    {
        Assert.Equal("", Req("", "").SubjectDisplay());
    }
}
