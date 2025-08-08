import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#ECFEFF',
          100: '#CFFAFE',
          200: '#A5F3FC',
          300: '#67E8F9',
          400: '#22D3EE',
          500: '#06B6D4',
          600: '#0891B2',
          700: '#0E7490',
          800: '#155E75',
          900: '#164E63',
        },
        surface: '#0B1220',
      },
      boxShadow: {
        card: '0 10px 30px rgba(0,0,0,.25)'
      },
      maxWidth: {
        container: '1100px'
      }
    },
  },
  plugins: [],
}

export default config


