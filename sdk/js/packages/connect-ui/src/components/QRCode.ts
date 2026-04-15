/**
 * QR Code generator component for @tos/connect-ui.
 *
 * Renders a QR code as an inline SVG with a TOS-branded center logo.
 * Uses the lightweight `qrcode-generator` library.
 */

import qrGenerator from "qrcode-generator";

// ---------------------------------------------------------------------------
// SVG Icons
// ---------------------------------------------------------------------------

/** TOS diamond logo SVG (used as center overlay). */
const TOS_LOGO_SVG = `<svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect width="32" height="32" rx="6" fill="#0088CC"/>
  <path d="M16 6L26 12V20L16 26L6 20V12L16 6Z" fill="white" fill-opacity="0.9"/>
  <path d="M16 10L21 13V19L16 22L11 19V13L16 10Z" fill="#0088CC"/>
</svg>`;

// ---------------------------------------------------------------------------
// QRCodeGenerator
// ---------------------------------------------------------------------------

export interface QRCodeOptions {
  /** The data to encode. */
  value: string;
  /** Size of the SVG in pixels (width and height). Default 260. */
  size?: number;
  /** Whether to show the TOS logo in the center. Default true. */
  showLogo?: boolean;
  /** Error correction level. Default "M". */
  errorCorrectionLevel?: "L" | "M" | "Q" | "H";
  /** Foreground color for the QR modules. Default "#1a1a2e". */
  fgColor?: string;
  /** Background color. Default "#ffffff". */
  bgColor?: string;
}

/**
 * Generate a QR code as an SVG string.
 *
 * Uses error correction level "M" by default, which allows the center
 * logo overlay without impacting scannability.
 */
export function generateQRCodeSVG(options: QRCodeOptions): string {
  const safeColor = (c: string) => /^#[0-9a-fA-F]{3,8}$/.test(c) ? c : "#000000";

  const {
    value,
    size = 260,
    showLogo = true,
    errorCorrectionLevel = "M",
    fgColor: rawFg = "#1a1a2e",
    bgColor: rawBg = "#ffffff",
  } = options;

  const fgColor = safeColor(rawFg);
  const bgColor = safeColor(rawBg);

  // Generate QR data
  const qr = qrGenerator(0, errorCorrectionLevel);
  qr.addData(value, "Byte");
  qr.make();

  const moduleCount = qr.getModuleCount();
  const quietZone = 2;
  const totalModules = moduleCount + quietZone * 2;
  const cellSize = size / totalModules;

  // Build SVG paths
  const paths: string[] = [];

  // Logo exclusion zone (center area where logo sits)
  const logoModules = showLogo ? Math.ceil(moduleCount * 0.22) : 0;
  const logoStart = Math.floor((moduleCount - logoModules) / 2);
  const logoEnd = logoStart + logoModules;

  for (let row = 0; row < moduleCount; row++) {
    for (let col = 0; col < moduleCount; col++) {
      if (!qr.isDark(row, col)) continue;

      // Skip modules in the logo zone
      if (showLogo && row >= logoStart && row < logoEnd && col >= logoStart && col < logoEnd) {
        continue;
      }

      const x = (col + quietZone) * cellSize;
      const y = (row + quietZone) * cellSize;
      const r = cellSize * 0.38; // Rounded dot radius

      // Render as rounded rectangles for a modern look
      paths.push(
        `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" ` +
        `width="${cellSize.toFixed(2)}" height="${cellSize.toFixed(2)}" ` +
        `rx="${r.toFixed(2)}" fill="${fgColor}"/>`
      );
    }
  }

  // Build the SVG
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" shape-rendering="crispEdges">`;
  svg += `<rect width="${size}" height="${size}" fill="${bgColor}"/>`;
  svg += paths.join("");

  // Add center logo
  if (showLogo) {
    const logoSize = logoModules * cellSize;
    const logoX = (size - logoSize) / 2;
    const logoY = (size - logoSize) / 2;
    const logoPad = logoSize * 0.15;

    svg += `<rect x="${(logoX - logoPad).toFixed(2)}" y="${(logoY - logoPad).toFixed(2)}" `;
    svg += `width="${(logoSize + logoPad * 2).toFixed(2)}" height="${(logoSize + logoPad * 2).toFixed(2)}" `;
    svg += `rx="${(logoSize * 0.18).toFixed(2)}" fill="${bgColor}"/>`;

    // Inline the TOS logo
    const innerSize = logoSize * 0.7;
    const innerX = (size - innerSize) / 2;
    const innerY = (size - innerSize) / 2;
    svg += `<g transform="translate(${innerX.toFixed(2)}, ${innerY.toFixed(2)}) scale(${(innerSize / 32).toFixed(4)})">`;
    // Inline the logo paths (without the outer SVG wrapper)
    svg += `<rect width="32" height="32" rx="6" fill="#0088CC"/>`;
    svg += `<path d="M16 6L26 12V20L16 26L6 20V12L16 6Z" fill="white" fill-opacity="0.9"/>`;
    svg += `<path d="M16 10L21 13V19L16 22L11 19V13L16 10Z" fill="#0088CC"/>`;
    svg += `</g>`;
  }

  svg += `</svg>`;
  return svg;
}

/**
 * Create a DOM element containing the QR code SVG.
 */
export function createQRCodeElement(options: QRCodeOptions): HTMLDivElement {
  const container = document.createElement("div");
  container.className = "tos-qr-view__container";
  container.innerHTML = generateQRCodeSVG(options);
  return container;
}

// Re-export for internal use
export { TOS_LOGO_SVG };
