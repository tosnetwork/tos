import { describe, it, expect } from "vitest";
import { generateQRCodeSVG, createQRCodeElement, TOS_LOGO_SVG } from "./QRCode.js";

describe("generateQRCodeSVG", () => {
  it("returns a string containing an <svg tag", () => {
    const svg = generateQRCodeSVG({ value: "https://example.com" });
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });

  it("includes xmlns attribute for valid SVG", () => {
    const svg = generateQRCodeSVG({ value: "https://example.com" });
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
  });

  it("contains the TOS logo by default (showLogo defaults to true)", () => {
    const svg = generateQRCodeSVG({ value: "https://example.com" });
    // The logo is inlined as a <rect> with fill="#0088CC" and the diamond paths
    expect(svg).toContain('fill="#0088CC"');
    expect(svg).toContain("M16 6L26 12V20L16 26L6 20V12L16 6Z");
  });

  it("omits the logo when showLogo is false", () => {
    const svg = generateQRCodeSVG({ value: "https://example.com", showLogo: false });
    // Without logo, there should be no <g transform=... for the logo
    expect(svg).not.toContain("<g transform=");
  });

  it("produces different SVGs for different values", () => {
    const svg1 = generateQRCodeSVG({ value: "https://example.com" });
    const svg2 = generateQRCodeSVG({ value: "https://other.com/path" });
    expect(svg1).not.toBe(svg2);
  });

  it("uses the specified size", () => {
    const svg = generateQRCodeSVG({ value: "test", size: 200 });
    expect(svg).toContain('width="200"');
    expect(svg).toContain('height="200"');
  });

  it("uses the default size of 260", () => {
    const svg = generateQRCodeSVG({ value: "test" });
    expect(svg).toContain('width="260"');
    expect(svg).toContain('height="260"');
  });

  it("uses custom foreground color", () => {
    const svg = generateQRCodeSVG({ value: "test", fgColor: "#ff0000" });
    expect(svg).toContain('fill="#ff0000"');
  });

  it("uses custom background color", () => {
    const svg = generateQRCodeSVG({ value: "test", bgColor: "#000000" });
    expect(svg).toContain('fill="#000000"');
  });

  it("produces valid SVG for an empty string value", () => {
    // qrcode-generator can encode empty strings; should not throw
    const svg = generateQRCodeSVG({ value: "" });
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });

  it("supports different error correction levels", () => {
    const svgL = generateQRCodeSVG({ value: "test", errorCorrectionLevel: "L" });
    const svgH = generateQRCodeSVG({ value: "test", errorCorrectionLevel: "H" });
    // Different correction levels produce different module counts, so SVGs differ
    expect(svgL).not.toBe(svgH);
  });
});

// ---------------------------------------------------------------------------
// createQRCodeElement
// ---------------------------------------------------------------------------

describe("createQRCodeElement", () => {
  it("returns an HTMLDivElement with the QR SVG inside", () => {
    const el = createQRCodeElement({ value: "https://example.com" });
    expect(el).toBeInstanceOf(HTMLDivElement);
    expect(el.className).toBe("tos-qr-view__container");
    expect(el.innerHTML).toContain("<svg");
  });
});

// ---------------------------------------------------------------------------
// TOS_LOGO_SVG export
// ---------------------------------------------------------------------------

describe("TOS_LOGO_SVG", () => {
  it("is exported and contains an SVG", () => {
    expect(TOS_LOGO_SVG).toContain("<svg");
    expect(TOS_LOGO_SVG).toContain("</svg>");
  });
});
