import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion'

const BLUE = '#3b82f6'
const GREEN = '#22c55e'
const AMBER = '#f59e0b'
const RED = '#ef4444'
const MUTED = '#64748b'
const CARD_BG = '#0f1520'
const BORDER = '#1e293b'

const STATS = [
  { label: 'DEVICES', value: 47, color: BLUE },
  { label: 'CRITICAL', value: 3, color: RED },
  { label: 'WARNINGS', value: 12, color: AMBER },
  { label: 'COMPLIANT', value: 82, suffix: '%', color: GREEN },
]

const DEVICE_ROWS = [
  { ip: '192.168.1.1', name: 'core-router', proto: 'SNMP', risk: 'Low', riskColor: GREEN },
  { ip: '192.168.1.50', name: 'db-server', proto: 'MSSQL', risk: 'Med', riskColor: AMBER },
  { ip: '192.168.1.100', name: 'siemens-plc', proto: 'S7comm', risk: 'High', riskColor: RED },
  { ip: '192.168.1.101', name: 'weintek-hmi', proto: 'HTTP', risk: 'Med', riskColor: AMBER },
  { ip: '192.168.1.102', name: 'moxa-gw', proto: 'Modbus', risk: 'Med', riskColor: AMBER },
  { ip: '192.168.1.200', name: 'ab-plc', proto: 'EtherNet/IP', risk: 'Crit', riskColor: RED },
  { ip: '192.168.1.201', name: 'abb-drive', proto: 'Modbus', risk: 'High', riskColor: RED },
  { ip: '192.168.1.210', name: 'equip-01', proto: 'HSMS', risk: 'High', riskColor: RED },
]

const FRAMEWORKS_DETAIL = [
  { name: 'IEC 62443-3-3', controls: '10', passed: 7, total: 10, color: BLUE },
  { name: 'NIST CSF 2.0', controls: '7', passed: 5, total: 7, color: GREEN },
  { name: 'ISO 27001:2022', controls: '7', passed: 4, total: 7, color: AMBER },
  { name: 'SEMI E187', controls: '5', passed: 4, total: 5, color: '#a855f7' },
]

export const OtDashboardScene: React.FC = () => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()

  return (
    <AbsoluteFill style={{ backgroundColor: '#080c12', padding: '28px 40px' }}>
      {/* Dashboard header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 20,
        opacity: interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' }),
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#e2e8f0', letterSpacing: '0.05em' }}>
            OT SECURITY
          </div>
          <div style={{
            display: 'flex', gap: 2, background: '#1e293b', borderRadius: 6, padding: 2,
          }}>
            <div style={{
              padding: '4px 12px', borderRadius: 4,
              background: BLUE, color: '#fff',
              fontSize: 12, fontWeight: 600,
            }}>discover</div>
            <div style={{
              padding: '4px 12px', borderRadius: 4,
              color: MUTED, fontSize: 12, fontWeight: 600,
            }}>monitor</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 8, height: 8, borderRadius: 4, background: GREEN }} />
          <span style={{ fontSize: 12, color: MUTED }}>Online</span>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
        {STATS.map((s, i) => {
          const delay = 10 + i * 8
          const scale = spring({ frame: Math.max(0, frame - delay), fps, config: { damping: 12, stiffness: 100 } })
          const countUp = Math.round(interpolate(frame, [delay, delay + 30], [0, s.value], { extrapolateRight: 'clamp' }))
          return (
            <div key={i} style={{
              flex: 1, background: CARD_BG, borderRadius: 8,
              border: `1px solid ${BORDER}`, padding: '14px 16px',
              transform: `scale(${scale})`,
            }}>
              <div style={{ fontSize: 11, color: MUTED, fontWeight: 600, letterSpacing: '0.08em', marginBottom: 6 }}>
                {s.label}
              </div>
              <div style={{ fontSize: 32, fontWeight: 700, color: s.color, fontFamily: '"SF Mono", monospace' }}>
                {countUp}{s.suffix || ''}
              </div>
            </div>
          )
        })}
      </div>

      {/* IT/OT separation warning */}
      <div style={{
        background: `${RED}10`, border: `1px solid ${RED}30`, borderRadius: 6,
        padding: '8px 16px', marginBottom: 16,
        display: 'flex', alignItems: 'center', gap: 8,
        opacity: interpolate(frame, [50, 65], [0, 1], { extrapolateRight: 'clamp' }),
      }}>
        <span style={{ color: RED, fontSize: 14 }}>{'\u26A0'}</span>
        <span style={{ fontSize: 13, color: RED, fontWeight: 500 }}>
          IT/OT NOT SEPARATED -- 6 IT and 3 OT devices on same subnet
        </span>
      </div>

      <div style={{ display: 'flex', gap: 20, flex: 1 }}>
        {/* Device table */}
        <div style={{
          flex: 1.3, background: CARD_BG, borderRadius: 8,
          border: `1px solid ${BORDER}`, padding: '12px 0',
          opacity: interpolate(frame, [30, 50], [0, 1], { extrapolateRight: 'clamp' }),
        }}>
          <div style={{
            display: 'flex', padding: '4px 16px 8px', borderBottom: `1px solid ${BORDER}`,
            fontSize: 10, color: MUTED, fontWeight: 600, letterSpacing: '0.05em',
          }}>
            <div style={{ width: 120 }}>IP</div>
            <div style={{ width: 100 }}>NAME</div>
            <div style={{ width: 80 }}>PROTOCOL</div>
            <div style={{ width: 50, textAlign: 'right' }}>RISK</div>
          </div>
          {DEVICE_ROWS.map((d, i) => {
            const delay = 55 + i * 8
            const opacity = interpolate(frame, [delay, delay + 8], [0, 1], { extrapolateRight: 'clamp' })
            return (
              <div key={i} style={{
                display: 'flex', padding: '5px 16px',
                fontSize: 12, fontFamily: '"SF Mono", monospace', opacity,
                borderBottom: i < DEVICE_ROWS.length - 1 ? `1px solid ${BORDER}40` : 'none',
              }}>
                <div style={{ width: 120, color: '#e2e8f0' }}>{d.ip}</div>
                <div style={{ width: 100, color: '#94a3b8' }}>{d.name}</div>
                <div style={{ width: 80, color: MUTED }}>{d.proto}</div>
                <div style={{
                  width: 50, textAlign: 'right',
                  color: d.riskColor, fontWeight: 600, fontSize: 11,
                }}>
                  {d.risk}
                </div>
              </div>
            )
          })}
        </div>

        {/* Compliance panel */}
        <div style={{
          flex: 0.7, background: CARD_BG, borderRadius: 8,
          border: `1px solid ${BORDER}`, padding: 16,
          opacity: interpolate(frame, [70, 90], [0, 1], { extrapolateRight: 'clamp' }),
        }}>
          <div style={{ fontSize: 13, color: MUTED, fontWeight: 600, marginBottom: 16, letterSpacing: '0.05em' }}>
            COMPLIANCE
          </div>
          {FRAMEWORKS_DETAIL.map((fw, i) => {
            const delay = 100 + i * 12
            const passedAnim = Math.round(interpolate(frame, [delay, delay + 25], [0, fw.passed], { extrapolateRight: 'clamp' }))
            const pct = Math.round((passedAnim / fw.total) * 100)
            return (
              <div key={i} style={{ marginBottom: 16 }}>
                <div style={{
                  display: 'flex', justifyContent: 'space-between',
                  fontSize: 12, color: '#94a3b8', marginBottom: 6,
                }}>
                  <span>{fw.name}</span>
                  <span style={{ fontFamily: '"SF Mono", monospace', color: fw.color, fontWeight: 600 }}>
                    {passedAnim}/{fw.total}
                  </span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: '#1e293b' }}>
                  <div style={{
                    height: '100%', borderRadius: 3, background: fw.color,
                    width: `${pct}%`,
                  }} />
                </div>
              </div>
            )
          })}

          {/* Scan terminal */}
          <div style={{
            marginTop: 20, background: '#0a0e14', borderRadius: 6,
            padding: '10px 12px', fontFamily: '"SF Mono", monospace', fontSize: 11,
            opacity: interpolate(frame, [150, 170], [0, 1], { extrapolateRight: 'clamp' }),
          }}>
            <div style={{ color: GREEN }}>$ ot-security scan</div>
            <div style={{ color: MUTED, marginTop: 4 }}>
              {frame > 180 ? 'Found 47 devices' : 'Scanning...'}
            </div>
            {frame > 190 && (
              <div style={{ color: MUTED }}>3 critical, 12 warnings</div>
            )}
            {frame > 200 && (
              <div style={{ color: BLUE }}>Dashboard: localhost:8443</div>
            )}
          </div>
        </div>
      </div>
    </AbsoluteFill>
  )
}
