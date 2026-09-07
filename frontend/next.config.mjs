/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  async headers() {
    // Set here as well as at the edge: on Vercel there is no nginx in front, and a
    // header that only exists in a config file we aren't running is not a header.
    return [{
      source: "/:path*",
      headers: [
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "no-referrer" },
        { key: "Permissions-Policy", value: "camera=(self), microphone=(self), geolocation=()" },
        {
          key: "Content-Security-Policy",
          // No 'unsafe-eval'. connect-src is limited to the API origin so injected
          // script cannot exfiltrate to an attacker-controlled host.
          value: [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' blob: data:",
            "media-src 'self' blob:",
            `connect-src 'self' ${process.env.NEXT_PUBLIC_API_ORIGIN ?? ""} ${process.env.NEXT_PUBLIC_WS_ORIGIN ?? ""}`.trim(),
            "font-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
          ].join("; "),
        },
      ],
    }];
  },
};
export default nextConfig;
