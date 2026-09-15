using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The covering-grant matcher (docs/design/covering-grant.md): a perimeter approval's scope covers a
/// host only within one kind, by exact match or a trailing wildcard past the kind boundary. These
/// cases are the security edge — a too-generous matcher would turn one approval into access to
/// resources nobody approved.
/// </summary>
public class CoverageTests
{
    [Theory]
    [InlineData("rdp:host-1", "rdp:host-1")]              // exact
    [InlineData("rdp:*", "rdp:host-1")]                   // whole kind
    [InlineData("rdp:*", "rdp:site-a/win-7")]
    [InlineData("rdp:site-a/*", "rdp:site-a/win-7")]      // a site
    [InlineData("RDP:*", "rdp:host-1")]                   // case-insensitive
    public void Covers_when_the_scope_includes_the_resource(string scope, string resource) =>
        Assert.True(Coverage.Covers(scope, resource));

    [Theory]
    [InlineData("rdp:host-1", "rdp:host-2")]              // different host, exact scope
    [InlineData("rdp:site-a/*", "rdp:site-b/win-1")]      // different site
    [InlineData("rdp:*", "db:reports")]                   // never across kinds
    [InlineData("*", "rdp:host-1")]                       // a bare star names no kind
    [InlineData("rdp*", "rdp:host-1")]                    // wildcard before the kind boundary
    [InlineData("", "rdp:host-1")]                        // empty scope covers nothing
    [InlineData("rdp:*", "")]                             // empty resource is covered by nothing
    public void Does_not_cover(string scope, string resource) =>
        Assert.False(Coverage.Covers(scope, resource));

    [Fact]
    public void Cardinality_counts_distinct_covered_hosts()
    {
        var known = new[]
        {
            "rdp:site-a/win-1", "rdp:site-a/win-2", "rdp:site-a/win-2",   // a duplicate
            "rdp:site-b/win-9", "db:reports",
        };
        Assert.Equal(2, Coverage.Cardinality("rdp:site-a/*", known));   // two distinct site-a hosts
        Assert.Equal(3, Coverage.Cardinality("rdp:*", known));          // all three rdp hosts
        Assert.Equal(1, Coverage.Cardinality("db:reports", known));     // exact
        Assert.Equal(0, Coverage.Cardinality("", known));
    }
}
