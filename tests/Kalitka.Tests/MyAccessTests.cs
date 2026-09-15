using Kalitka;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// "My access": a person sees the sessions they hold and the requests they have in flight, matched by
/// their operator-principal identities against the subject identity on each — and nobody else's, nor
/// anything ended, expired, or unattributable.
/// </summary>
public class MyAccessTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static OperatorPrincipal Anna() =>
        new("anna", "Anna", new[] { "os:contoso\\anna", "google:anna" });

    private static SessionRecord Session(string id, string subjectIdentity, DateTimeOffset? expires,
        DateTimeOffset? ended = null) =>
        new(id, "g", "r", "anna", "rdp:WIN-01", "agent-1", Now.AddMinutes(-5), ended, "", "")
        { ExpiresAt = expires, SubjectIdentity = subjectIdentity, Profile = "rdp" };

    private static PendingRequest Request(string id, string subjectIdentity, string state = "waiting") =>
        new() { Id = id, Resource = "db:reports", State = state, SubjectIdentity = subjectIdentity, Raised = Now };

    private static (MyAccessService svc, InMemorySessionStore sessions, InMemoryRequestStore requests) Build()
    {
        var clock = new FakeTimeProvider(Now);
        var sessions = new InMemorySessionStore();
        var requests = new InMemoryRequestStore();
        return (new MyAccessService(sessions, requests, clock), sessions, requests);
    }

    [Fact]
    public void Shows_open_sessions_for_one_of_the_persons_identities()
    {
        var (svc, sessions, _) = Build();
        sessions.Start(Session("mine", "os:CONTOSO\\anna", Now.AddHours(1)));      // normalised match, case-insensitive
        sessions.Start(Session("also-mine", "google:anna", Now.AddHours(1)));
        sessions.Start(Session("someone-else", "os:contoso\\bob", Now.AddHours(1)));

        var held = svc.For(Anna()).Held;
        Assert.Equal(new[] { "also-mine", "mine" }, held.Select(h => h.SessionId).OrderBy(x => x));
    }

    [Fact]
    public void Excludes_ended_expired_and_unattributable_sessions()
    {
        var (svc, sessions, _) = Build();
        sessions.Start(Session("ended", "google:anna", Now.AddHours(1), ended: Now.AddMinutes(-1)));
        sessions.Start(Session("expired", "google:anna", Now.AddMinutes(-1)));
        sessions.Start(Session("no-identity", "", Now.AddHours(1)));               // pre-0.48 / unattributable
        sessions.Start(Session("live", "google:anna", Now.AddHours(1)));

        var held = svc.For(Anna()).Held;
        Assert.Equal(new[] { "live" }, held.Select(h => h.SessionId));
    }

    [Fact]
    public void Shows_only_the_persons_waiting_requests()
    {
        var (svc, _, requests) = Build();
        requests.Add(Request("mine", "google:anna"));
        requests.Add(Request("resolved", "google:anna", state: "approved"));       // not waiting
        requests.Add(Request("someone-else", "os:contoso\\bob"));

        var pending = svc.For(Anna()).Pending;
        Assert.Equal(new[] { "mine" }, pending.Select(p => p.RequestId));
    }

    [Fact]
    public void A_person_with_no_matching_identity_holds_nothing()
    {
        var (svc, sessions, requests) = Build();
        sessions.Start(Session("s", "google:anna", Now.AddHours(1)));
        requests.Add(Request("r", "google:anna"));

        var view = svc.For(new OperatorPrincipal("bob", "Bob", new[] { "google:bob" }));
        Assert.Empty(view.Held);
        Assert.Empty(view.Pending);
    }
}
