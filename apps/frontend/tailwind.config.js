/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#0C0C0E",
        surface: "#141416",
        raised: "#1C1C1F",
        hover: "#232327",
        line: "#26262A",
        "line-strong": "#38383E",
        ink: "#EDEDEF",
        muted: "#A1A1AA",
        faint: "#6E6E78",
        accent: { DEFAULT: "#F5A524", strong: "#FFBE55", dim: "#3B2A0C", ink: "#1A1204" },
        sev: {
          critical: "#E5484D",
          high: "#F76B15",
          medium: "#9E8CFC",
          low: "#3B9EFF",
          info: "#7E7E87",
        },
        ok: "#3DD68C",
      },
      fontFamily: {
        sans: ['"Geist Variable"', "system-ui", "sans-serif"],
        mono: ['"Geist Mono Variable"', "ui-monospace", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: { panel: "2px", control: "2px" },
    },
  },
  plugins: [],
};
