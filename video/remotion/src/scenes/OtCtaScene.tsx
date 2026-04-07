import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion'

const BLUE = '#3b82f6'
const MUTED = '#64748b'
const GREEN = '#22c55e'
const CARD_BG = '#0f1520'
const BORDER = '#1e293b'

const FEATURES = [
  { label: 'Protocols', value: '8 industrial', icon: '\u{1F50C}' },
  { label: 'Frameworks', value: '4 compliance', icon: '\u{1F6E1}' },
  { label: 'Deployment', value: 'Single binary', icon: '\u{1F4E6}' },
  { label: 'Safety', value: 'Read-only scan', icon: '\u{1F512}' },
]

const TERMINAL_LINES = [
  { text: '$ go build -o ot-security ./cmd/server/', color: GREEN, delay: 100 },
  { text: '$ ./ot-security', color: GREEN, delay: 120 },
  { text: 'INFO  Listening on :8443', color: '#94a3b8', delay: 135 },
  { text: 'INFO  Dashboard: http://localhost:8443', color: BLUE, delay: 145 },
  { text: 'INFO  Ready to scan', color: '#94a3b8', delay: 155 },
]

export const OtCtaScene: React.FC = () => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()

  // Title animation
  const titleScale = spring({ frame, fps, config: { damping: 12, stiffness: 80 } })
  const titleOpacity = interpolate(frame, [0, 12], [0, 1], { extrapolateRight: 'clamp' })

  // Subtitle
  const subOpacity = interpolate(frame, [20, 35], [0, 1], { extrapolateRight: 'clamp' })
  const subY = interpolate(frame, [20, 35], [15, 0], { extrapolateRight: 'clamp' })

  // Bottom info
  const bottomOpacity = interpolate(frame, [200, 220], [0, 1], { extrapolateRight: 'clamp' })

  return (
    <AbsoluteFill style={{
      backgroundColor: '#080c12',
      justifyContent: 'center', alignItems: 'center',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", sans-serif',
    }}>
      {/* Subtle radial glow */}
      <div style={{
        position: 'absolute', inset: 0,
        background: `radial-gradient(ellipse at center, ${BLUE}08 0%, transparent 70%)`,
      }} />

      <div style={{ textAlign: 'center', zIndex: 1, maxWidth: 1000 }}>
        {/* Title */}
        <div style={{
          fontSize: 64, fontWeight: 800, color: '#e2e8f0',
          opacity: titleOpacity, transform: `scale(${titleScale})`,
          letterSpacing: '-0.02em',
        }}>
          go-ot-security
        </div>

        {/* Subtitle */}
        <div style={{
          fontSize: 24, fontWeight: 400, color: '#94a3b8',
          marginTop: 12, opacity: subOpacity,
          transform: `translateY(${subY}px)`,
        }}>
          Open Source. Read-Only. One Binary.
        </div>

        {/* Feature cards */}
        <div style={{
          display: 'flex', gap: 16, marginTop: 40,
          justifyContent: 'center',
        }}>
          {FEATURES.map((f, i) => {
            const delay = 45 + i * 10
            const scale = spring({ frame: Math.max(0, frame - delay), fps, config: { damping: 12, stiffness: 100 } })
            return (
              <div key={i} style={{
                background: CARD_BG, borderRadius: 8,
                border: `1px solid ${BORDER}`, padding: '14px 20px',
                transform: `scale(${scale})`, minWidth: 140,
              }}>
                <div style={{ fontSize: 12, color: MUTED, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
                  {f.label.toUpperCase()}
                </div>
                <div style={{ fontSize: 16, color: '#e2e8f0', fontWeight: 600 }}>
                  {f.value}
                </div>
              </div>
            )
          })}
        </div>

        {/* Terminal */}
        <div style={{
          marginTop: 36, background: '#0a0e14', borderRadius: 10,
          border: `1px solid ${BORDER}`, padding: '16px 24px',
          textAlign: 'left', fontFamily: '"SF Mono", "Fira Code", monospace',
          maxWidth: 600, marginLeft: 'auto', marginRight: 'auto',
          opacity: interpolate(frame, [85, 100], [0, 1], { extrapolateRight: 'clamp' }),
        }}>
          {/* Terminal dots */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
            <div style={{ width: 10, height: 10, borderRadius: 5, background: '#ef4444' }} />
            <div style={{ width: 10, height: 10, borderRadius: 5, background: '#f59e0b' }} />
            <div style={{ width: 10, height: 10, borderRadius: 5, background: '#22c55e' }} />
          </div>
          {TERMINAL_LINES.map((line, i) => {
            const opacity = interpolate(frame, [line.delay, line.delay + 8], [0, 1], { extrapolateRight: 'clamp' })
            return (
              <div key={i} style={{ fontSize: 13, color: line.color, opacity, marginBottom: 4 }}>
                {line.text}
              </div>
            )
          })}
        </div>

        {/* Bottom info */}
        <div style={{ marginTop: 36, opacity: bottomOpacity }}>
          <div style={{ fontSize: 16, color: BLUE, fontWeight: 600 }}>
            github.com/seikaikyo/go-ot-security
          </div>
          <div style={{ fontSize: 13, color: MUTED, marginTop: 8 }}>
            MIT License &middot; Built with AI-assisted development &middot; Contributions welcome
          </div>
        </div>
      </div>
    </AbsoluteFill>
  )
}
