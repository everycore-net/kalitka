using System.Text;
using Net.Codecrete.QrCodeGenerator;

namespace Kalitka;

/// <summary>
/// A QR code as an inline SVG — for the enrolment invite, so a phone camera opens the link rather
/// than the admin reading a long URL aloud. The encoder is a focused MIT library; the rendering is
/// ours, so the page stays self-contained (the SVG is inline HTML, no asset request). Dark modules on
/// a white tile with a quiet-zone border, which is what a scanner needs.
/// </summary>
public static class Qr
{
    public static string Svg(string text, int moduleSize = 5, int quietModules = 4)
    {
        var qr = QrCode.EncodeText(text, QrCode.Ecc.Medium);
        var dim = qr.Size + 2 * quietModules;
        var px = dim * moduleSize;

        var path = new StringBuilder();
        for (var y = 0; y < qr.Size; y++)
            for (var x = 0; x < qr.Size; x++)
                if (qr.GetModule(x, y))
                {
                    var mx = (x + quietModules) * moduleSize;
                    var my = (y + quietModules) * moduleSize;
                    path.Append($"M{mx} {my}h{moduleSize}v{moduleSize}h-{moduleSize}z");
                }

        return $"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{px}\" height=\"{px}\" "
             + $"viewBox=\"0 0 {px} {px}\" role=\"img\" aria-label=\"enrolment QR code\">"
             + $"<rect width=\"{px}\" height=\"{px}\" fill=\"#ffffff\"/>"
             + $"<path d=\"{path}\" fill=\"#000000\"/></svg>";
    }
}
