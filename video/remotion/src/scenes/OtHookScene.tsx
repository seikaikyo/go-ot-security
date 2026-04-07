import { AbsoluteFill, interpolate, useCurrentFrame, useVideoConfig } from 'remotion'

const DANGER = '#ef4444'
const MUTED = '#64748b'

const PROTOCOLS = [
  { text: 'Modbus', x: '10%', y: '18%', delay: 0 },
  { text: 'S7comm', x: '75%', y: '12%', delay: 15 },
  { text: 'EtherNet/IP', x: '82%', y: '65%', delay: 30 },
  { text: 'HSMS', x: '8%', y: '72%', delay: 45 },
  { text: 'BACnet', x: '48%', y: '8%', delay: 10 },
  { text: 'DNP3', x: '62%', y: '82%', delay: 25 },
  { text: 'OPC-UA', x: '28%', y: '85%', delay: 40 },
  { text: 'Telnet:23', x: '88%', y: '35%', delay: 55 },
  { text: 'FTP:21', x: '15%', y: '45%', delay: 35 },
  { text: 'RDP:3389', x: '55%', y: '30%', delay: 20 },
]

export const OtHookScene: React.FC = () => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()

  // Typewriter effect
  const fullText = 'Factory networks are exposed.\nLegacy devices have no encryption.'
  const charCount = Math.floor(interpolate(frame, [20, 150], [0, fullText.length], { extrapolateRight: 'clamp' }))
  const visibleText = fullText.slice(0, charCount)
  const cursorOpacity = frame % 30 < 15 ? 1 : 0

  // "What if" fade in
  const whatIfOpacity = interpolate(frame, [170, 200], [0, 1], { extrapolateRight: 'clamp' })
  const whatIfY = interpolate(frame, [170, 200], [20, 0], { extrapolateRight: 'clamp' })

  // Background pulse
  const bgPulse = interpolate(frame % 90, [0, 45, 90], [0.02, 0.05, 0.02])

  // Warning flash
  const warningOpacity = interpolate(frame, [5, 15], [0, 0.08], { extrapolateRight: 'clamp' })

  return (
    <AbsoluteFill style={{ backgroundColor: '#080c12', justifyContent: 'center', alignItems: 'center' }}>
      {/* Subtle grid background */}
      <div style={{
        position: 'absolute', inset: 0, opacity: bgPulse,
        backgroundImage: `linear-gradient(${MUTED}15 1px, transparent 1px), linear-gradient(90deg, ${MUTED}15 1px, transparent 1px)`,
        backgroundSize: '60px 60px',
      }} />

      {/* Red warning gradient at top */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 200,
        background: `linear-gradient(${DANGER}${Math.round(warningOpacity * 255).toString(16).padStart(2, '0')}, transparent)`,
      }} />

      {/* Floating protocol names */}
      {PROTOCOLS.map((item, i) => {
        const opacity = interpolate(frame, [item.delay, item.delay + 30], [0, 0.15], { extrapolateRight: 'clamp' })
        const y = interpolate(frame, [0, 300], [0, -12])
        const isInsecure = ['Telnet:23', 'FTP:21', 'RDP:3389'].includes(item.text)
        return (
          <div key={i} style={{
            position: 'absolute', left: item.x, top: item.y,
            transform: `translateY(${y}px)`,
            fontSize: 14, fontFamily: '"SF Mono", "Fira Code", monospace',
            color: isInsecure ? DANGER : MUTED,
            opacity, fontWeight: 600, letterSpacing: '0.05em',
          }}>
            {item.text}
          </div>
        )
      })}

      {/* Lock icons scattered */}
      {[
        { x: '35%', y: '25%', delay: 50 },
        { x: '68%', y: '48%', delay: 70 },
        { x: '22%', y: '60%', delay: 90 },
      ].map((item, i) => {
        const opacity = interpolate(frame, [item.delay, item.delay + 20], [0, 0.1], { extrapolateRight: 'clamp' })
        return (
          <div key={`lock-${i}`} style={{
            position: 'absolute', left: item.x, top: item.y,
            fontSize: 24, opacity, color: DANGER,
          }}>
            {'\u26A0'}
          </div>
        )
      })}

      {/* Main text */}
      <div style={{ textAlign: 'center', zIndex: 1, maxWidth: 950, padding: '0 60px' }}>
        <div style={{
          fontSize: 52, fontWeight: 700, color: '#e2e8f0',
          lineHeight: 1.3, whiteSpace: 'pre-line',
          fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
        }}>
          {visibleText}
          <span style={{ opacity: cursorOpacity, color: DANGER }}>|</span>
        </div>

        <div style={{
          marginTop: 48,
          fontSize: 28, fontWeight: 500, color: '#3b82f6',
          opacity: whatIfOpacity,
          transform: `translateY(${whatIfY}px)`,
        }}>
          What if you could scan, assess, and monitor in minutes?
        </div>
      </div>

      {/* Bottom brand */}
      <div style={{
        position: 'absolute', bottom: 48,
        fontSize: 14, color: '#334155', fontWeight: 600, letterSpacing: '0.15em',
      }}>
        GO-OT-SECURITY
      </div>
    </AbsoluteFill>
  )
}
