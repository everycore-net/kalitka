using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The trigger for ending a lease early: a real RDP logoff (4634, logon type 10) for an account,
/// tested as a pure function over the event's data. We must act only on an actual RDP logoff and
/// only for a real account, so the wrong logon type or a non-account SID is ignored.
/// </summary>
public class RdpLogoffTests
{
    private const string Sid = "S-1-5-21-1004336348-1177238915-682003330-1114";

    private static Dictionary<string, string> Logoff(
        string logonType = "10", string sid = Sid, string user = "anna", string domain = "CONTOSO") =>
        new()
        {
            ["LogonType"] = logonType,
            ["TargetUserSid"] = sid,
            ["TargetUserName"] = user,
            ["TargetDomainName"] = domain,
        };

    [Fact]
    public void An_rdp_logoff_parses_to_the_account()
    {
        var l = RdpLogoff.TryParse(Logoff());
        Assert.NotNull(l);
        Assert.Equal(Sid, l!.Sid);
        Assert.Equal("CONTOSO\\anna", l.Account);
    }

    [Fact]
    public void A_non_rdp_logoff_is_ignored()
    {
        Assert.Null(RdpLogoff.TryParse(Logoff(logonType: "2")));   // console
        Assert.Null(RdpLogoff.TryParse(Logoff(logonType: "3")));   // network (e.g. a share)
    }

    [Fact]
    public void A_non_account_sid_is_ignored()
    {
        Assert.Null(RdpLogoff.TryParse(Logoff(sid: "S-1-5-18")));   // SYSTEM logs off constantly
        Assert.Null(RdpLogoff.TryParse(Logoff(sid: "S-1-0-0")));
    }

    [Fact]
    public void A_local_account_has_no_domain_prefix()
    {
        var l = RdpLogoff.TryParse(Logoff(domain: ""));
        Assert.NotNull(l);
        Assert.Equal("anna", l!.Account);
    }

    [Fact]
    public void EventData_is_pulled_from_the_real_4634_xml_shape()
    {
        const string xml = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>4634</EventID></System>
          <EventData>
            <Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-1114</Data>
            <Data Name='TargetUserName'>anna</Data>
            <Data Name='TargetDomainName'>CONTOSO</Data>
            <Data Name='TargetLogonId'>0x3e7a1</Data>
            <Data Name='LogonType'>10</Data>
          </EventData>
        </Event>
        """;
        var l = RdpLogoff.TryParse(EventData.Parse(xml));
        Assert.NotNull(l);
        Assert.Equal("CONTOSO\\anna", l!.Account);
    }
}
