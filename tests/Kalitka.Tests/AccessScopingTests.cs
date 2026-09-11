using System.Text.Json;
using Kalitka;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

public class AccessScopingTests
{
    private static AccessLists Lists(string? path = null)
    {
        var opts = Options.Create(new GateOptions
        {
            ListsPath = path ?? Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json")
        });
        return new AccessLists(opts, NullLogger<AccessLists>.Instance);
    }

    [Fact]
    public void Allow_entries_do_not_leak_across_resources()
    {
        var lists = Lists();
        lists.Add("allow", "web:*", "subject", "root", "t");

        Assert.True(lists.IsAllowed("web:grafana.example.com", "1.2.3.4", "root"));  // web:* covers a web host
        Assert.False(lists.IsAllowed("ssh:prod-01", "1.2.3.4", "root"));            // but never an SSH login

        lists.Add("allow", "ssh:prod-01", "subject", "deploy", "t");
        Assert.True(lists.IsAllowed("ssh:prod-01", "", "deploy"));
        Assert.False(lists.IsAllowed("ssh:other-01", "", "deploy"));               // exact host only
        Assert.False(lists.IsAllowed("web:app.example.com", "", "deploy"));        // an ssh entry is not web
    }

    [Fact]
    public void Scheme_wildcard_covers_only_its_scheme()
    {
        var lists = Lists();
        lists.Add("block", "ssh:*", "ip", "203.0.113.9", "t");
        Assert.True(lists.IsBlocked("ssh:anything", "203.0.113.9", "", ""));
        Assert.False(lists.IsBlocked("web:anything", "203.0.113.9", "", ""));
    }

    [Fact]
    public void Legacy_entries_without_a_resource_are_read_as_web_star()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json");
        // Pre-0.8.1 shape: no Resource, Type "input".
        File.WriteAllText(path, JsonSerializer.Serialize(new[]
        {
            new { List = "allow", Type = "input", Value = "root", Added = "t" }
        }));

        var lists = Lists(path);
        Assert.True(lists.IsAllowed("web:grafana.example.com", "", "root"));   // preserved for web
        Assert.False(lists.IsAllowed("ssh:prod-01", "", "root"));             // NOT a PAM policy
    }

    // ---- Agent resource binding --------------------------------------------

    private static GateService Gate(string[] agentResources)
    {
        var opts = Options.Create(new GateOptions
        {
            HmacSecret = "unit-test-signing-key-0123456789",
            GateHost = "gate.example.com",
            GeoUrl = "",
            AgentResources = agentResources,
            ListsPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
            EnforcedPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
            SettingsPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".json"),
        });
        var geo = new HttpGeoLookup(new HttpClient(), opts, NullLogger<HttpGeoLookup>.Instance);
        var lists = new AccessLists(opts, NullLogger<AccessLists>.Instance);
        return new GateService(new FakeTelegram(), geo, lists, opts, NullLogger<GateService>.Instance,
            new FakeTimeProvider());
    }

    [Fact]
    public void Agent_may_raise_only_its_bound_resources()
    {
        var bound = Gate(new[] { "ssh:prod-01" });
        Assert.True(bound.AgentMayRaise("ssh:prod-01"));
        Assert.False(bound.AgentMayRaise("ssh:domain-controller-01"));   // cannot claim another host

        var wild = Gate(new[] { "ssh:*" });
        Assert.True(wild.AgentMayRaise("ssh:whatever"));
        Assert.False(wild.AgentMayRaise("web:whatever"));

        var open = Gate(Array.Empty<string>());
        Assert.True(open.AgentMayRaise("ssh:anything"));                 // unbound = any (PoC)
    }
}
