using System.Net.Http;
using Kalitka;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Kalitka.Tests;

/// <summary>
/// Language negotiation from Accept-Language, and that the visitor pages render in
/// the negotiated language (en/de/ru, English fallback).
/// </summary>
public class LocalizationTests
{
    [Theory]
    [InlineData(null, Lang.En)]
    [InlineData("", Lang.En)]
    [InlineData("de", Lang.De)]
    [InlineData("ru", Lang.Ru)]
    [InlineData("de-DE,de;q=0.9,en;q=0.8", Lang.De)]
    [InlineData("en-US,en;q=0.9,de;q=0.8", Lang.En)]
    [InlineData("fr-FR,fr;q=0.9", Lang.En)]              // unknown → fallback
    [InlineData("fr,de;q=0.7,en;q=0.6", Lang.De)]        // skips unknown, best known
    [InlineData("de;q=0.3,ru;q=0.9", Lang.Ru)]           // honours q-weight
    [InlineData("*", Lang.En)]
    [InlineData("RU-ru", Lang.Ru)]                       // case-insensitive
    public void Negotiate_picks_the_expected_language(string? header, Lang expected) =>
        Assert.Equal(expected, L10n.Negotiate(header));

    [Fact]
    public void For_returns_the_matching_bundle_with_the_right_lang_code()
    {
        Assert.Equal("en", L10n.For(Lang.En).Code);
        Assert.Equal("de", L10n.For(Lang.De).Code);
        Assert.Equal("ru", L10n.For(Lang.Ru).Code);
    }

    public class Http : IClassFixture<GateFactory>
    {
        private readonly GateFactory _f;
        public Http(GateFactory f) => _f = f;

        private async Task<string> RequestPage(string? acceptLanguage)
        {
            var client = _f.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
            var req = new HttpRequestMessage(HttpMethod.Get, "/request?target=app.example.com");
            if (acceptLanguage is not null) req.Headers.Add("Accept-Language", acceptLanguage);
            return await (await client.SendAsync(req)).Content.ReadAsStringAsync();
        }

        [Fact]
        public async Task German_browser_gets_the_german_form()
        {
            var html = await RequestPage("de-DE,de;q=0.9,en;q=0.5");
            Assert.Contains("lang=\"de\"", html);
            Assert.Contains("Anfragen", html);                       // "Ask" button
            Assert.Contains("Anklopfen. Freigeben. Eintreten.", html); // tagline
        }

        [Fact]
        public async Task Russian_browser_gets_the_russian_form()
        {
            var html = await RequestPage("ru");
            Assert.Contains("lang=\"ru\"", html);
            Assert.Contains("Запросить", html);
        }

        [Fact]
        public async Task Unknown_or_missing_language_falls_back_to_english()
        {
            var html = await RequestPage(null);
            Assert.Contains("lang=\"en\"", html);
            Assert.Contains(">Ask</button>", html);
        }

        [Fact]
        public async Task Every_page_carries_the_source_offer_footer()
        {
            var html = await RequestPage(null);
            Assert.Contains("github.com/everycore-net/kalitka", html);   // AGPL §13 source offer
        }

        [Fact]
        public async Task Pages_carry_the_brand_icon_as_favicon_and_mark()
        {
            var html = await RequestPage(null);
            Assert.Contains("rel=\"icon\"", html);              // favicon
            Assert.Contains("data:image/png;base64,", html);   // inlined brand mark, no asset request
        }
    }
}
