import { AbsoluteFill, spring, useCurrentFrame, useVideoConfig } from 'remotion'

const BLUE = '#3b82f6'
const RED = '#ef4444'
const GREEN = '#22c55e'
const AMBER = '#f59e0b'
const MUTED = '#64748b'
const CARD_BG = '#0f1520'
const BORDER = '#1e293b'

const PROTOCOLS = [
  { text: 'Modbus', x: '6%', y: '15%' },
  { text: 'S7comm', x: '80%', y: '10%' },
  { text: 'EtherNet/IP', x: '85%', y: '72%' },
  { text: 'HSMS', x: '5%', y: '78%' },
  { text: 'OPC-UA', x: '42%', y: '6%' },
  { text: 'BACnet', x: '70%', y: '88%' },
]

const STATS = [
  { label: '8', desc: 'Protocols', color: BLUE },
  { label: '4', desc: 'Frameworks', color: GREEN },
  { label: '29', desc: 'Controls', color: AMBER },
  { label: '1', desc: 'Binary', color: '#a855f7' },
]

export const OtThumbnail: React.FC = () => {
  return (
    <AbsoluteFill style={{
      backgroundColor: '#080c12',
      justifyContent: 'center',
      alignItems: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
    }}>
      {/* Grid background */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.04,
        backgroundImage: `linear-gradient(${MUTED} 1px, transparent 1px), linear-gradient(90deg, ${MUTED} 1px, transparent 1px)`,
        backgroundSize: '60px 60px',
      }} />

      {/* Red glow top */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 300,
        background: `linear-gradient(${RED}12, transparent)`,
      }} />

      {/* Blue glow center */}
      <div style={{
        position: 'absolute', inset: 0,
        background: `radial-gradient(ellipse at center, ${BLUE}08 0%, transparent 60%)`,
      }} />

      {/* Floating protocols */}
      {PROTOCOLS.map((p, i) => (
        <div key={i} style={{
          position: 'absolute', left: p.x, top: p.y,
          fontSize: 14, fontFamily: '"SF Mono", monospace',
          color: MUTED, opacity: 0.2, fontWeight: 600, letterSpacing: '0.05em',
        }}>
          {p.text}
        </div>
      ))}

      {/* Shield icon */}
      <div style={{
        position: 'absolute', top: 80, left: '50%', transform: 'translateX(-50%)',
        width: 60, height: 70,
        display: 'flex', justifyContent: 'center', alignItems: 'center',
      }}>
        <svg width="60" height="70" viewBox="0 0 60 70" fill="none">
          <path d="M30 2L4 16V38C4 52 16 64 30 68C44 64 56 52 56 38V16L30 2Z"
            stroke={RED} strokeWidth="2" fill={`${RED}10`} />
          <path d="M20 35L27 42L40 28" stroke={GREEN} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>

      {/* Main content */}
      <div style={{ textAlign: 'center', zIndex: 1, marginTop: 40 }}>
        {/* Title */}
        <div style={{
          fontSize: 72, fontWeight: 800, color: '#e2e8f0',
          letterSpacing: '-0.02em',
        }}>
          go-ot-security
        </div>

        {/* Subtitle */}
        <div style={{
          fontSize: 26, fontWeight: 400, color: '#94a3b8',
          marginTop: 8,
        }}>
          OT/ICS Security Assessment Platform
        </div>

        {/* Tagline */}
        <div style={{
          fontSize: 18, fontWeight: 500, color: BLUE,
          marginTop: 16,
        }}>
          Scan. Assess. Monitor. One binary.
        </div>

        {/* Stats row */}
        <div style={{
          display: 'flex', gap: 20, marginTop: 40,
          justifyContent: 'center',
        }}>
          {STATS.map((s, i) => (
            <div key={i} style={{
              background: CARD_BG, borderRadius: 10,
              border: `1px solid ${BORDER}`, padding: '16px 24px',
              minWidth: 120,
            }}>
              <div style={{
                fontSize: 36, fontWeight: 800, color: s.color,
                fontFamily: '"SF Mono", monospace',
              }}>
                {s.label}
              </div>
              <div style={{
                fontSize: 13, color: MUTED, fontWeight: 500,
                marginTop: 2, letterSpacing: '0.03em',
              }}>
                {s.desc}
              </div>
            </div>
          ))}
        </div>

        {/* Framework badges */}
        <div style={{
          display: 'flex', gap: 12, marginTop: 28,
          justifyContent: 'center',
        }}>
          {['IEC 62443', 'NIST CSF 2.0', 'ISO 27001', 'SEMI E187'].map((fw, i) => (
            <div key={i} style={{
              background: `${BLUE}10`, border: `1px solid ${BLUE}25`,
              borderRadius: 6, padding: '5px 14px',
              fontSize: 13, color: '#94a3b8', fontWeight: 500,
            }}>
              {fw}
            </div>
          ))}
        </div>
      </div>

      {/* Bottom bar */}
      <div style={{
        position: 'absolute', bottom: 32, left: 0, right: 0,
        display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 24,
      }}>
        <span style={{ fontSize: 14, color: '#334155', fontWeight: 600 }}>
          Go &middot; Single Binary &middot; MIT License
        </span>
        <span style={{ fontSize: 14, color: '#334155' }}>|</span>
        <span style={{ fontSize: 14, color: '#334155', fontWeight: 500 }}>
          github.com/seikaikyo/go-ot-security
        </span>
      </div>
    </AbsoluteFill>
  )
}
