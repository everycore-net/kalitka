using KalitkaAgent;
using Xunit;

namespace KalitkaAgent.Windows.Tests;

/// <summary>
/// The trigger conditions for auto-raising on a denied RDP logon, tested as a pure function over a
/// 4625's EventData — this is the security-relevant edge (we must act only on an RDP logon that was
/// refused for lack of the right, and only for a real account whose identity the OS asserted).
/// </summary>
public class RdpDenialTests
{
    private const string Host = "WIN-01";
    private const string Sid = "S-1-5-21-1004336348-1177238915-682003330-1114";

    private static Dictionary<string, string> Denial(
        string logonType = "10", string subStatus = "0xC000015B", string status = "0xC000006D",
        string sid = Sid, string user = "anna", string domain = "CONTOSO", string ip = "10.0.0.9") =>
        new()
        {
            ["LogonType"] = logonType,
            ["Status"] = status,
            ["SubStatus"] = subStatus,
            ["TargetUserSid"] = sid,
            ["TargetUserName"] = user,
            ["TargetDomainName"] = domain,
            ["IpAddress"] = ip,
        };

    [Fact]
    public void A_denied_rdp_logon_parses_into_an_os_asserted_subject()
    {
        var d = RdpDenial.TryParse(Denial(), Host);
        Assert.NotNull(d);
        Assert.Equal(Sid, d!.Sid);
        Assert.Equal("CONTOSO\\anna", d.Account);
        Assert.Equal("anna", d.User);
        Assert.Equal("10.0.0.9", d.Ip);
        Assert.Equal("rdp:WIN-01", d.Resource);
        Assert.Equal("os:CONTOSO\\anna", d.ToSubject().SubjectIdentity);
    }

    [Fact]
    public void The_code_is_accepted_whether_it_rides_in_substatus_or_status()
    {
        Assert.NotNull(RdpDenial.TryParse(Denial(subStatus: "0x0", status: "0xC000015B"), Host));
        Assert.NotNull(RdpDenial.TryParse(Denial(subStatus: "0xc000015b", status: "0x0"), Host));   // lower-case too
    }

    [Fact]
    public void A_non_rdp_logon_type_is_ignored()
    {
        Assert.Null(RdpDenial.TryParse(Denial(logonType: "3"), Host));    // network
        Assert.Null(RdpDenial.TryParse(Denial(logonType: "2"), Host));    // interactive at the console
    }

    [Fact]
    public void A_different_failure_reason_is_ignored()
    {
        // 0xC000006A = bad password, 0xC0000064 = no such user — not "logon type not granted".
        Assert.Null(RdpDenial.TryParse(Denial(subStatus: "0xC000006A", status: "0xC000006D"), Host));
        Assert.Null(RdpDenial.TryParse(Denial(subStatus: "0xC0000064", status: "0xC000006D"), Host));
    }

    [Fact]
    public void A_non_account_sid_is_ignored()
    {
        Assert.Null(RdpDenial.TryParse(Denial(sid: "S-1-0-0"), Host));        // null SID
        Assert.Null(RdpDenial.TryParse(Denial(sid: "S-1-5-7"), Host));        // anonymous
        Assert.Null(RdpDenial.TryParse(Denial(sid: "S-1-5-18"), Host));       // SYSTEM
    }

    [Fact]
    public void A_missing_username_is_ignored()
    {
        Assert.Null(RdpDenial.TryParse(Denial(user: ""), Host));
    }

    [Fact]
    public void A_local_account_has_no_domain_prefix_and_an_unknown_ip_is_blank()
    {
        var d = RdpDenial.TryParse(Denial(domain: "", ip: "-"), Host);
        Assert.NotNull(d);
        Assert.Equal("anna", d!.Account);
        Assert.Equal("", d.Ip);
    }

    [Fact]
    public void EventData_is_pulled_from_the_real_4625_xml_shape()
    {
        const string xml = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>4625</EventID></System>
          <EventData>
            <Data Name='SubjectUserSid'>S-1-0-0</Data>
            <Data Name='TargetUserSid'>S-1-5-21-1004336348-1177238915-682003330-1114</Data>
            <Data Name='TargetUserName'>anna</Data>
            <Data Name='TargetDomainName'>CONTOSO</Data>
            <Data Name='Status'>0xc000006d</Data>
            <Data Name='SubStatus'>0xc000015b</Data>
            <Data Name='LogonType'>10</Data>
            <Data Name='IpAddress'>10.0.0.9</Data>
          </EventData>
        </Event>
        """;
        var data = SecurityLogWatcher.ParseEventData(xml);
        var d = RdpDenial.TryParse(data, Host);
        Assert.NotNull(d);
        Assert.Equal("CONTOSO\\anna", d!.Account);
        Assert.Equal("rdp:WIN-01", d.Resource);
    }
}
