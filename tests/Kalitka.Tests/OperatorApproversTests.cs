using Kalitka;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>Runtime-granted approve rights: the set itself, and that it composes with the static
/// <c>ApproverEmails</c> in <see cref="AdminAuth.ResolvePermissions"/>.</summary>
public class OperatorApproversTests
{
    private static OperatorApprovers Svc(IConfigStore store) =>
        new(store, new InMemoryAuditStore(), new FakeTimeProvider());

    [Fact]
    public async Task Grant_then_contains_then_revoke()
    {
        var s = Svc(new InMemoryConfigStore());
        Assert.False(s.Contains("bob@example.com"));
        await s.Grant("Bob@Example.com", "admin", default);   // normalised
        Assert.True(s.Contains("bob@example.com"));
        Assert.Single(s.All());
        Assert.True(await s.Revoke("bob@example.com", "admin", default));
        Assert.False(s.Contains("bob@example.com"));
    }

    [Fact]
    public async Task A_runtime_approver_gets_the_approver_permission_bundle()
    {
        var store = new InMemoryConfigStore();
        var approvers = Svc(store);
        var opts = Options.Create(new GateOptions());   // no static ApproverEmails
        var auth = new AdminAuth(new GoogleAuth(new HttpClient(), opts,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<GoogleAuth>.Instance),
            new TokenSigner("k"), opts, new FakeTimeProvider(), approvers);

        Assert.Empty(auth.ResolvePermissions("bob@example.com"));
        await approvers.Grant("bob@example.com", "admin", default);
        Assert.Contains(Perm.RequestsDecide, auth.ResolvePermissions("bob@example.com"));
    }
}
