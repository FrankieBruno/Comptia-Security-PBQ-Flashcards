/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: { extend: {} },
  safelist: [
    { pattern: /(bg|text|border|ring)-(slate|emerald|rose)-(100|200|300|400|600|700|800)/ },
    { pattern: /(from|to)-slate-(50|100)/ },
  ],
  plugins: [],
};
