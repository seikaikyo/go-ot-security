import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion'

const BLUE = '#3b82f6'
const GREEN = '#22c55e'
const AMBER = '#f59e0b'
const RED = '#ef4444'
const MUTED = '#64748b'
const CARD_BG = '#0f1520'
const BORDER = '#1e293b'

const DEVICES = [
  { ip: '192.168.1.1', vendor: 'Cisco', type: 'Router', risk: 2.0, color: GREEN },
  { ip: '192.168.1.10', vendor: 'Dell', type: 'Workstation', risk: 1.5, color: GREEN },
  { ip: '192.168.1.50', vendor: '-', type: 'DB Server', risk: 3.0, color: AMBER },
  { ip: '192.168.1.100', vendor: 'Siemens', type: 'PLC', risk: 6.5, color: RED },
  { ip: '192.168.1.101', vendor: 'Weintek', type: 'HMI', risk: 4.5, color: AMBER },
  { ip: '192.168.1.102', vendor: 'MOXA', type: 'Gateway', risk: 3.5, color: AMBER },
  { ip: '192.168.1.200', vendor: 'Rockwell', type: 'PLC', risk: 7.0, color: RED },
  { ip: '192.168.1.201', vendor: 'ABB', type: 'Drive', risk: 5.0, color: RED },
]

const PROBES = [
  { name: 'Modbus', port: 502 },
  { name: 'S7comm', port: 102 },
  { name: 'EtherNet/IP', port: 44818 },
  { name: 'HSMS', port: 5000 },
  { name: 'OPC-UA', port: 4840 },
  { name: 'BACnet', port: 47808 },
  { name: 'DNP3', port: 20000 },
  { name: 'MQTT', port: 1883 },
]

const FRAMEWORKS = [
  { name: 'IEC 62443', score: 72, color: BLUE },
  { name: 'NIST CSF 2.0', score: 68, color: GREEN },
  { name: 'ISO 27001', score: 65, color: AMBER },
  { name: 'SEMI E187', score: 78, color: '#a855f7' },
]

export const OtDiscoveryScene: React.FC = () => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()

  return (
    <AbsoluteFill style={{ backgroundColor: '#080c12', padding: '40px 50px' }}>
      {/* Section title */}
      <div style={{
        fontSize: 16, fontWeight: 600, color: BLUE, letterSpacing: '0.1em',
        opacity: interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' }),
        marginBottom: 24,
      }}>
        ASSET DISCOVERY + VULNERABILITY ASSESSMENT
      </div>

      <div style={{ display: 'flex', gap: 32, flex: 1 }}>
        {/* Left: Device scan results */}
        <div style={{ flex: 1.2 }}>
          {/* Scan progress */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: '12px 16px', marginBottom: 16,
            opacity: interpolate(frame, [5, 20], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ fontSize: 13, color: MUTED, marginBottom: 8 }}>
              Scanning 192.168.1.0/24
            </div>
            <div style={{ height: 4, borderRadius: 2, background: '#1e293b' }}>
              <div style={{
                height: '100%', borderRadius: 2, background: BLUE,
                width: `${interpolate(frame, [10, 120], [0, 100], { extrapolateRight: 'clamp' })}%`,
              }} />
            </div>
          </div>

          {/* Device list */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: '12px 0', overflow: 'hidden',
          }}>
            {/* Header */}
            <div style={{
              display: 'flex', padding: '4px 16px 8px', borderBottom: `1px solid ${BORDER}`,
              fontSize: 11, color: MUTED, fontWeight: 600, letterSpacing: '0.05em',
            }}>
              <div style={{ width: 130 }}>IP</div>
              <div style={{ width: 90 }}>VENDOR</div>
              <div style={{ width: 90 }}>TYPE</div>
              <div style={{ width: 50, textAlign: 'right' }}>RISK</div>
            </div>
            {/* Rows */}
            {DEVICES.map((d, i) => {
              const delay = 30 + i * 12
              const opacity = interpolate(frame, [delay, delay + 10], [0, 1], { extrapolateRight: 'clamp' })
              const slideX = interpolate(frame, [delay, delay + 10], [-20, 0], { extrapolateRight: 'clamp' })
              return (
                <div key={i} style={{
                  display: 'flex', padding: '6px 16px',
                  fontSize: 13, fontFamily: '"SF Mono", monospace',
                  opacity, transform: `translateX(${slideX}px)`,
                  borderBottom: i < DEVICES.length - 1 ? `1px solid ${BORDER}40` : 'none',
                }}>
                  <div style={{ width: 130, color: '#e2e8f0' }}>{d.ip}</div>
                  <div style={{ width: 90, color: MUTED }}>{d.vendor}</div>
                  <div style={{ width: 90, color: '#94a3b8' }}>{d.type}</div>
                  <div style={{
                    width: 50, textAlign: 'right',
                    color: d.risk >= 5 ? RED : d.risk >= 3 ? AMBER : GREEN,
                    fontWeight: 600,
                  }}>
                    {d.risk.toFixed(1)}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right column */}
        <div style={{ flex: 0.8, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Protocol probes */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: 16,
            opacity: interpolate(frame, [15, 30], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 12, letterSpacing: '0.05em' }}>
              PROTOCOL PROBES
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {PROBES.map((p, i) => {
                const delay = 40 + i * 10
                const scale = spring({ frame: Math.max(0, frame - delay), fps, config: { damping: 12, stiffness: 100 } })
                const checkOpacity = interpolate(frame, [delay + 15, delay + 20], [0, 1], { extrapolateRight: 'clamp' })
                return (
                  <div key={i} style={{
                    background: '#1e293b', borderRadius: 6, padding: '6px 10px',
                    transform: `scale(${scale})`,
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}>
                    <span style={{ fontSize: 12, color: '#94a3b8', fontFamily: '"SF Mono", monospace' }}>
                      {p.name}
                    </span>
                    <span style={{ fontSize: 10, color: MUTED }}>:{p.port}</span>
                    <span style={{ fontSize: 12, color: GREEN, opacity: checkOpacity }}>
                      {'\u2713'}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Compliance frameworks */}
          <div style={{
            background: CARD_BG, borderRadius: 8, border: `1px solid ${BORDER}`,
            padding: 16, flex: 1,
            opacity: interpolate(frame, [80, 100], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 16, letterSpacing: '0.05em' }}>
              COMPLIANCE ASSESSMENT
            </div>
            {FRAMEWORKS.map((fw, i) => {
              const delay = 100 + i * 15
              const barWidth = interpolate(frame, [delay, delay + 40], [0, fw.score], { extrapolateRight: 'clamp' })
              const numOpacity = interpolate(frame, [delay + 20, delay + 30], [0, 1], { extrapolateRight: 'clamp' })
              return (
                <div key={i} style={{ marginBottom: i < FRAMEWORKS.length - 1 ? 14 : 0 }}>
                  <div style={{
                    display: 'flex', justifyContent: 'space-between', marginBottom: 4,
                    fontSize: 13, color: '#94a3b8',
                  }}>
                    <span>{fw.name}</span>
                    <span style={{ opacity: numOpacity, color: fw.color, fontWeight: 600, fontFamily: '"SF Mono", monospace' }}>
                      {Math.round(barWidth)}%
                    </span>
                  </div>
                  <div style={{ height: 6, borderRadius: 3, background: '#1e293b' }}>
                    <div style={{
                      height: '100%', borderRadius: 3,
                      background: fw.color,
                      width: `${barWidth}%`,
                    }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </AbsoluteFill>
  )
}
