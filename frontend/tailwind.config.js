/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        cs: {
          bg: '#0a0e17',
          bg2: '#0f1520',
          bg3: '#151c2c',
          bg4: '#1a2235',
          border: '#1e2a40',
          border2: '#2a3a55',
          text: '#c8d6e5',
          text2: '#8899aa',
          text3: '#556677',
          cyan: '#00f0ff',
          red: '#ff3355',
          green: '#00ff88',
          orange: '#ff9500',
          purple: '#a855f7',
          yellow: '#ffd000',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Outfit', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
