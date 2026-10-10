module.exports = {
  content: ['./master-server/templates/*.html', './master-server/static/*.js'],
  theme: {
    fontSize: { sm: ['14px', '20px'], base: ['16px', '24px'], '2xl': ['24px', '32px'], '4xl': ['36px', '40px'] },
    extend: {
      colors: {
        console: { bg: '#0D1117', panel: '#161B22', line: '#21262D', text: '#E6EDF3', muted: '#8B949E' },
        signal: { amber: '#D4A24C', cyan: '#4CC9D4', red: '#E5534B' }
      },
      fontFamily: { sans: ['IBM Plex Sans', 'sans-serif'], mono: ['IBM Plex Mono', 'monospace'] },
      gridTemplateColumns: { console: '192px minmax(0, 1fr)', operations: 'minmax(0, 2fr) minmax(0, 3fr)', node: '112px minmax(0, 1fr) 168px 104px' },
      maxHeight: { log: '560px' },
      minWidth: { topology: '760px' }
    }
  },
  plugins: []
};
