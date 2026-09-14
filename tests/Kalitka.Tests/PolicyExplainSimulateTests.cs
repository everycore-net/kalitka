using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// explain/simulate are ordinary core features, built first and before any AI: a deterministic
/// trace of how the effective decision was reached, and a deterministic classification of what
/// a proposed policy change would do. They must go through the same composition as the request
/// engine (so a trace can never disagree with reality), and the impact taxonomy — No change /
/// Restriction / Authority expansion / Mixed — must be exact, because "authority expansion"
/// is what earns a change its own approval.
/// </summary>
public class PolicyExplainSimulateTests
{
    private const string Actor = "google:admin";

    private static PolicyService Fresh()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
        return new PolicyService(new InMemoryConfigStore(), new InMemoryAuditStore(), clock);
    }

    private static AccessPolicy P(string name, string resource, string[] tags, int required = 1, int ttl = 0) =>
        new(name, resource, tags, required, ttl);

    // ---- explain --------------------------------------------------------------

    [Fact]
    public void Explain_agrees_with_the_engine_and_attributes_each_value()
    {
        var svc = Fresh();
        svc.Save(P("base", "ssh:*", new[] { "env:prod" }, required: 1), Actor, default).Wait();
        svc.Save(P("ddl", "ssh:*", new[] { "env:prod" }, required: 3, ttl: 15) with { Subject = SubjectApproval.Forbidden },
            Actor, default).Wait();

        var tags = new[] { "env:prod" };
        var ex = svc.Explain("ssh:db-01", tags);

        // Same composed decision the request engine would use (compared field-wise: the record
        // holds arrays, so value equality on the whole record is reference-sensitive).
        var eng = svc.Effective("ssh:db-01", tags);
        Assert.Equal(eng.RequiredApprovals, ex.Effective.RequiredApprovals);
        Assert.Equal(eng.GrantTtlMinutes, ex.Effective.GrantTtlMinutes);
        Assert.Equal(eng.Subject, ex.Effective.Subject);
        Assert.Equal(eng.MatchedPolicies, ex.Effective.MatchedPolicies);
        Assert.Equal(3, ex.Effective.RequiredApprovals);
        Assert.Equal(15, ex.Effective.GrantTtlMinutes);
        Assert.Equal(SubjectApproval.Forbidden, ex.Effective.Subject);

        // Attribution names the policy responsible for each strictest value.
        Assert.Equal(new[] { "ddl" }, Src(ex, "approvals"));
        Assert.Equal(new[] { "ddl" }, Src(ex, "grant_ttl_minutes"));
        Assert.Equal(new[] { "ddl" }, Src(ex, "subject"));
    }

    [Fact]
    public void Explain_says_why_each_policy_did_not_match()
    {
        var svc = Fresh();
        svc.Save(P("prod", "ssh:*", new[] { "env:prod" }), Actor, default).Wait();
        svc.Save(P("dbonly", "db:*", new[] { "env:prod" }), Actor, default).Wait();

        var ex = svc.Explain("ssh:x", new[] { "env:staging" });
        Assert.All(ex.Considered, c => Assert.False(c.Matched));
        Assert.Contains("agent lacks tag env:prod", Reason(ex, "prod"));
        Assert.Contains("not matched by db:*", Reason(ex, "dbonly"));
        Assert.Same(PolicyDecision.None, ex.Effective);   // nothing matched -> the default
        Assert.Empty(ex.Sources);
    }

    // ---- simulate: the four impact classes ------------------------------------

    [Fact]
    public void Adding_a_stricter_policy_is_a_restriction()
    {
        var svc = Fresh();
        var change = new PolicyChange.Upsert(P("new", "ssh:*", new[] { "env:prod" }, required: 2));
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.Restriction, impact.Class);
        Assert.False(impact.RequiresApproval);
        Assert.Equal(1, impact.Before.RequiredApprovals);
        Assert.Equal(2, impact.After.RequiredApprovals);
    }

    [Fact]
    public void Lowering_approvals_is_an_authority_expansion_that_needs_approval()
    {
        var svc = Fresh();
        svc.Save(P("p", "ssh:*", new[] { "env:prod" }, required: 2), Actor, default).Wait();
        var change = new PolicyChange.Upsert(P("p", "ssh:*", new[] { "env:prod" }, required: 1));
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.AuthorityExpansion, impact.Class);
        Assert.True(impact.RequiresApproval);
    }

    [Fact]
    public void Deleting_a_restricting_policy_is_an_authority_expansion()
    {
        var svc = Fresh();
        svc.Save(P("guard", "ssh:*", new[] { "env:prod" }, required: 2, ttl: 15), Actor, default).Wait();
        var impact = svc.Simulate(new PolicyChange.Remove("guard"), "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.AuthorityExpansion, impact.Class);
        Assert.True(impact.RequiresApproval);
        Assert.Equal(2, impact.Before.RequiredApprovals);
        Assert.Equal(1, impact.After.RequiredApprovals);
    }

    [Fact]
    public void More_approvals_but_a_longer_ttl_is_a_mixed_change()
    {
        var svc = Fresh();
        svc.Save(P("p", "ssh:*", new[] { "env:prod" }, required: 1, ttl: 15), Actor, default).Wait();
        // required 1 -> 2 (restriction), ttl 15 -> 60 (expansion): mixed.
        var change = new PolicyChange.Upsert(P("p", "ssh:*", new[] { "env:prod" }, required: 2, ttl: 60));
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.MixedChange, impact.Class);
        Assert.True(impact.RequiresApproval);
    }

    [Fact]
    public void An_unrelated_change_is_no_effective_change_for_this_context()
    {
        var svc = Fresh();
        svc.Save(P("prod", "ssh:*", new[] { "env:prod" }, required: 2), Actor, default).Wait();
        // Tightening a DB policy does not touch an SSH/prod request.
        var change = new PolicyChange.Upsert(P("db", "db:*", new[] { "env:prod" }, required: 3));
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.NoChange, impact.Class);
        Assert.False(impact.RequiresApproval);
        Assert.Empty(impact.Deltas);
    }

    [Fact]
    public void Relaxing_subject_from_forbidden_to_optional_expands_authority()
    {
        var svc = Fresh();
        svc.Save(P("p", "ssh:*", new[] { "env:prod" }) with { Subject = SubjectApproval.Forbidden }, Actor, default).Wait();
        var change = new PolicyChange.Upsert(P("p", "ssh:*", new[] { "env:prod" }) with { Subject = SubjectApproval.Optional });
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.AuthorityExpansion, impact.Class);
        var subj = Assert.Single(impact.Deltas, d => d.Field == "subject");
        Assert.Equal("forbidden", subj.Before);
        Assert.Equal("optional", subj.After);
    }

    [Fact]
    public void Widening_a_principal_allow_list_expands_narrowing_restricts()
    {
        var svc = Fresh();
        svc.Save(P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = new[] { "deploy", "root" } }, Actor, default).Wait();

        // {deploy,root} -> {deploy,root,ops}: superset, allows more.
        var widen = svc.Simulate(new PolicyChange.Upsert(
            P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = new[] { "deploy", "root", "ops" } }),
            "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.AuthorityExpansion, widen.Class);

        // {deploy,root} -> {deploy}: subset, allows fewer.
        var narrow = svc.Simulate(new PolicyChange.Upsert(
            P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = new[] { "deploy" } }),
            "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.Restriction, narrow.Class);

        // {deploy,root} -> (dropped): no constraint at all, allows anyone.
        var drop = svc.Simulate(new PolicyChange.Upsert(
            P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = Array.Empty<string>() }),
            "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.AuthorityExpansion, drop.Class);
    }

    [Fact]
    public void Swapping_one_allowed_principal_for_another_is_mixed()
    {
        var svc = Fresh();
        svc.Save(P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = new[] { "deploy" } }, Actor, default).Wait();
        var change = new PolicyChange.Upsert(
            P("p", "ssh:*", new[] { "env:prod" }) with { AllowedPrincipals = new[] { "readonly" } });
        var impact = svc.Simulate(change, "ssh:x", new[] { "env:prod" });
        Assert.Equal(PolicyImpactClass.MixedChange, impact.Class);   // adds readonly, removes deploy
    }

    private static string[] Src(PolicyExplanation ex, string field) =>
        ex.Sources.First(s => s.Field == field).FromPolicies;

    private static string Reason(PolicyExplanation ex, string policy) =>
        ex.Considered.First(c => c.Name == policy).Reason;
}
