using Kalitka;
using Xunit;

namespace Kalitka.Tests;

/// <summary>The invite QR renders as a self-contained inline SVG (dark modules on white) — enough to
/// be embedded in the page and scanned; scannability itself is the encoder library's contract.</summary>
public class QrTests
{
    [Fact]
    public void It_renders_an_inline_svg_with_modules()
    {
        var svg = Qr.Svg("https://gate.example.com/enroll?t=" + new string('x', 300));
        Assert.StartsWith("<svg", svg);
        Assert.Contains("<path", svg);
        Assert.Contains("fill=\"#000000\"", svg);   // dark modules
        Assert.Contains("fill=\"#ffffff\"", svg);   // light background a scanner needs
        Assert.EndsWith("</svg>", svg);
    }

    [Fact]
    public void It_handles_short_and_long_payloads()
    {
        Assert.Contains("<path", Qr.Svg("x"));
        Assert.Contains("<path", Qr.Svg(new string('y', 800)));
    }
}
