import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion'

const AMBER = '#f59e0b'
const RED = '#ef4444'
const BLUE = '#3b82f6'
const GREEN = '#22c55e'
const MUTED = '#64748b'
const CARD_BG = '#0f1520'
const BORDER = '#1e293b'

const ALERTS = [
  { text: 'New device detected: 192.168.1.45', severity: 'high', technique: 'T0842', delay: 20 },
  { text: 'Port 502 opened on 192.168.1.12', severity: 'critical', technique: 'T0855', delay: 50 },
  { text: 'Config drift: register 40001 changed', severity: 'critical', technique: 'T0821', delay: 80 },
  { text: 'Default credentials: 192.168.1.100', severity: 'high', technique: 'T0812', delay: 110 },
  { text: 'Insecure protocol: Telnet on .50', severity: 'medium', technique: 'T0883', delay: 140 },
]

const SEVERITY_COLORS: Record<string, string> = {
  critical: RED,
  high: AMBER,
  medium: BLUE,
}

const GOLDEN_REGS = [
  { addr: '40001', golden: '0x0064', current: '0x0064', changed: false },
  { addr: '40002', golden: '0x00C8', current: '0x00FF', changed: true },
  { addr: '40003', golden: '0x0032', current: '0x0032', changed: false },
  { addr: '40004', golden: '0x01F4', current: '0x01F4', changed: false },
  { addr: '40005', golden: '0x0096', current: '0x0050', changed: true },
  { addr: '40006', golden: '0x012C', current: '0x012C', changed: false },
]

const MITRE_TECHNIQUES = [
  { id: 'T0842', name: 'Network Sniffing', delay: 160 },
  { id: 'T0855', name: 'Unauthorized Command', delay: 175 },
  { id: 'T0821', name: 'Modify Controller Tasking', delay: 190 },
  { id: 'T0812', name: 'Default Credentials', delay: 205 },
  { id: 'T0836', name: 'Modify Parameter', delay: 220 },
]

export const OtMonitorScene: React.FC = () => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()

  return (
    <AbsoluteFill style={{ backgroundColor: '#080c12', padding: '40px 50px' }}>
      {/* Section title */}
      <div style={{
        fontSize: 16, fontWeight: 600, color: AMBER, letterSpacing: '0.1em',
        opacity: interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' }),
        marginBottom: 24,
      }}>
        NETWORK MONITORING + CONFIGURATION MANAGEMENT
      </div>

      <div style={{ display: 'flex', gap: 32, flex: 1 }}>
        {/* Left: Alert feed */}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 12, letterSpacing: '0.05em' }}>
            ALERT FEED
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {ALERTS.map((alert, i) => {
              const opacity = interpolate(frame, [alert.delay, alert.delay + 12], [0, 1], { extrapolateRight: 'clamp' })
              const slideX = interpolate(frame, [alert.delay, alert.delay + 12], [40, 0], { extrapolateRight: 'clamp' })
              const borderColor = SEVERITY_COLORS[alert.severity] || MUTED
              return (
                <div key={i} style={{
                  background: CARD_BG, borderRadius: 6,
                  borderLeft: `3px solid ${borderColor}`,
                  padding: '10px 14px',
                  opacity, transform: `translateX(${slideX}px)`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 13, color: '#e2e8f0' }}>{alert.text}</span>
                    <span style={{
                      fontSize: 10, color: borderColor, fontWeight: 600,
                      background: `${borderColor}15`, padding: '2px 6px', borderRadius: 4,
                      fontFamily: '"SF Mono", monospace',
                    }}>
                      {alert.technique}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: MUTED, marginTop: 4 }}>
                    {alert.severity.toUpperCase()} | MITRE ATT&CK for ICS
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right column */}
        <div style={{ flex: 0.85, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Register diff */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: 16,
            opacity: interpolate(frame, [60, 80], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 12, letterSpacing: '0.05em' }}>
              CONFIG DRIFT: 192.168.1.200
            </div>
            {/* Header */}
            <div style={{
              display: 'flex', padding: '4px 0 8px', borderBottom: `1px solid ${BORDER}`,
              fontSize: 10, color: MUTED, fontWeight: 600, letterSpacing: '0.05em',
            }}>
              <div style={{ width: 60 }}>ADDR</div>
              <div style={{ width: 80 }}>GOLDEN</div>
              <div style={{ width: 80 }}>CURRENT</div>
              <div style={{ width: 40 }}></div>
            </div>
            {GOLDEN_REGS.map((reg, i) => {
              const delay = 90 + i * 8
              const opacity = interpolate(frame, [delay, delay + 8], [0, 1], { extrapolateRight: 'clamp' })
              return (
                <div key={i} style={{
                  display: 'flex', padding: '5px 0',
                  fontSize: 12, fontFamily: '"SF Mono", monospace',
                  opacity,
                  borderBottom: i < GOLDEN_REGS.length - 1 ? `1px solid ${BORDER}40` : 'none',
                }}>
                  <div style={{ width: 60, color: MUTED }}>{reg.addr}</div>
                  <div style={{ width: 80, color: '#94a3b8' }}>{reg.golden}</div>
                  <div style={{ width: 80, color: reg.changed ? RED : '#94a3b8', fontWeight: reg.changed ? 600 : 400 }}>
                    {reg.current}
                  </div>
                  <div style={{ width: 40, textAlign: 'center' }}>
                    {reg.changed && <span style={{ color: RED, fontSize: 14 }}>{'\u2260'}</span>}
                  </div>
                </div>
              )
            })}
          </div>

          {/* MITRE ATT&CK badges */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: 16,
            opacity: interpolate(frame, [150, 170], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 12, letterSpacing: '0.05em' }}>
              MITRE ATT&CK FOR ICS
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {MITRE_TECHNIQUES.map((t, i) => {
                const scale = spring({ frame: Math.max(0, frame - t.delay), fps, config: { damping: 12, stiffness: 100 } })
                return (
                  <div key={i} style={{
                    background: `${RED}12`, border: `1px solid ${RED}30`,
                    borderRadius: 6, padding: '6px 10px',
                    transform: `scale(${scale})`,
                  }}>
                    <div style={{ fontSize: 11, color: RED, fontWeight: 600, fontFamily: '"SF Mono", monospace' }}>
                      {t.id}
                    </div>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>
                      {t.name}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </AbsoluteFill>
  )
}
