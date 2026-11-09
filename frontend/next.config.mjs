// output beror på mål: TAURI=1 → statisk export (desktop-appen serverar assets),
// annars standalone (Docker-bilden kör en självförsörjande server). Dev (`next dev`)
// påverkas inte av output.
export default {
  reactStrictMode: true,
  output: process.env.TAURI === "1" ? "export" : "standalone",
  images: { unoptimized: true },
};

