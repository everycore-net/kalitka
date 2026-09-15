using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// The requestable catalogue and its disclosure control: a person sees only units offered to a group
/// they are in, and how much of that they see depends on their visibility mode — defaulting to the
/// most closed. The catalogue is the "what can I ask for" surface, so leaking beyond a person's
/// entitlement, or defaulting open, would be the bug.
/// </summary>
public class CatalogTests
{
    private static CatalogService Fresh() =>
        new(new InMemoryConfigStore(), new InMemoryAuditStore(), TimeProvider.System);

    private static OperatorPrincipal Person(params string[] groups) =>
        new("p1", "Anna", new[] { "google:anna" }) { Groups = groups };

    private static async Task Seed(CatalogService c)
    {
        await c.Save("fin-share", "share:\\\\fs01\\finance", "File shares", "Finance share", new[] { "finance" }, "admin", default);
        await c.Save("dev-box", "rdp:DEV-01", "Dev servers", "Dev box", new[] { "devs" }, "admin", default);
        await c.Save("reports-db", "db:reports", "Databases", "Reports DB", new[] { "finance", "devs" }, "admin", default);
    }

    [Fact]
    public async Task Saves_updates_with_revisions_and_deletes()
    {
        var c = Fresh();
        await c.Save("x", "rdp:A", "Dev servers", "Box A", new[] { "devs" }, "admin", default);
        Assert.Equal("rdp:A", c.Get("x")!.Resource);
        Assert.Equal(1, c.Get("x")!.Revision);

        await c.Save("x", "rdp:A", "Dev servers", "Box A (renamed)", new[] { "devs" }, "admin", default);
        Assert.Equal("Box A (renamed)", c.Get("x")!.DisplayName);
        Assert.Equal(2, c.Get("x")!.Revision);        // append-only history

        Assert.True(await c.Delete("x", "admin", default));
        Assert.Null(c.Get("x"));
    }

    [Fact]
    public async Task A_resource_is_required()
    {
        var c = Fresh();
        Assert.Equal("resource required", await c.Save("x", "", "cat", "name", new[] { "g" }, "admin", default));
    }

    [Fact]
    public async Task Only_units_offered_to_one_of_the_persons_groups_are_entitled()
    {
        var c = Fresh();
        await Seed(c);

        var full = c.VisibleTo(Person("finance"), CatalogVisibility.Full);
        Assert.Equal(new[] { "fin-share", "reports-db" }, full.Items.Select(i => i.Id).OrderBy(x => x));

        // Someone in no catalogue group sees nothing, even in Full mode.
        Assert.Empty(c.VisibleTo(Person("nobody"), CatalogVisibility.Full).Items);
        Assert.Empty(c.VisibleTo(Person(), CatalogVisibility.Full).Items);
    }

    [Fact]
    public async Task The_mode_decides_how_much_is_disclosed()
    {
        var c = Fresh();
        await Seed(c);
        var anna = Person("finance");

        // Categories: names of categories only, no concrete units.
        var cats = c.VisibleTo(anna, CatalogVisibility.Categories);
        Assert.Empty(cats.Items);
        Assert.Equal(new[] { "Databases", "File shares" }, cats.Categories);

        // Full: the concrete units plus their categories.
        var full = c.VisibleTo(anna, CatalogVisibility.Full);
        Assert.Equal(2, full.Items.Count);
        Assert.Equal(new[] { "Databases", "File shares" }, full.Categories);
    }

    [Fact]
    public async Task Defaults_to_the_most_closed_disclosing_nothing_requestable()
    {
        var c = Fresh();
        await Seed(c);
        var view = c.VisibleTo(Person("finance"));   // no mode passed
        Assert.Equal(CatalogVisibility.ApprovedOnly, view.Mode);
        Assert.Empty(view.Items);
        Assert.Empty(view.Categories);
    }
}
