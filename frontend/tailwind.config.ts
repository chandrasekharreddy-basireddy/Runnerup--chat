import type { Config } from "tailwindcss";

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { DEFAULT: "#12151a", soft: "#3d4451", faint: "#7b8494" },
        surface: { DEFAULT: "#ffffff", sunk: "#f4f6f9", edge: "#e2e6ec" },
        accent: { DEFAULT: "#2f5fd8", soft: "#e8eefc" },
        danger: "#c0392b",
      },
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
      },
    },
  },
  plugins: [],
} satisfies Config;
