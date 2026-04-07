import { AbsoluteFill, Audio, Sequence, interpolate, staticFile, useCurrentFrame } from 'remotion'
import type { SceneConfig } from './audioConfig.otsec.en'
import { BottomBar } from './components/BottomBar'
import { OtHookScene } from './scenes/OtHookScene'
import { OtDiscoveryScene } from './scenes/OtDiscoveryScene'
import { OtMonitorScene } from './scenes/OtMonitorScene'
import { OtDashboardScene } from './scenes/OtDashboardScene'
import { OtCtaScene } from './scenes/OtCtaScene'

interface OtSecVideoProps {
  locale: string
  scenes: SceneConfig[]
}

const SCENE_COMPONENTS: Record<string, React.FC> = {
  'ot-hook': OtHookScene,
  'ot-discovery': OtDiscoveryScene,
  'ot-monitor': OtMonitorScene,
  'ot-dashboard': OtDashboardScene,
  'ot-cta': OtCtaScene,
}

const SCENE_META: Record<string, Record<string, { title: string; subtitle: string; accent: string }>> = {
  en: {
    'ot-hook': { title: 'The Problem', subtitle: 'Exposed factory networks', accent: '#ef4444' },
    'ot-discovery': { title: 'Scan & Assess', subtitle: '8 protocols, one binary', accent: '#3b82f6' },
    'ot-monitor': { title: 'Monitor & Protect', subtitle: 'Continuous threat detection', accent: '#f59e0b' },
    'ot-dashboard': { title: 'Dashboard', subtitle: 'Compliance at a glance', accent: '#22c55e' },
    'ot-cta': { title: 'go-ot-security', subtitle: 'Open Source', accent: '#3b82f6' },
  },
  ja: {
    'ot-hook': { title: '\u8ab2\u984c', subtitle: '\u9732\u51fa\u3057\u305f\u5de5\u5834\u30cd\u30c3\u30c8\u30ef\u30fc\u30af', accent: '#ef4444' },
    'ot-discovery': { title: '\u30b9\u30ad\u30e3\u30f3\uff06\u8a55\u4fa1', subtitle: '8\u30d7\u30ed\u30c8\u30b3\u30eb\u3001\u5358\u4e00\u30d0\u30a4\u30ca\u30ea', accent: '#3b82f6' },
    'ot-monitor': { title: '\u76e3\u8996\uff06\u4fdd\u8b77', subtitle: '\u7d99\u7d9a\u7684\u306a\u8105\u5a01\u691c\u51fa', accent: '#f59e0b' },
    'ot-dashboard': { title: '\u30c0\u30c3\u30b7\u30e5\u30dc\u30fc\u30c9', subtitle: '\u30b3\u30f3\u30d7\u30e9\u30a4\u30a2\u30f3\u30b9\u3092\u4e00\u89a7\u8868\u793a', accent: '#22c55e' },
    'ot-cta': { title: 'go-ot-security', subtitle: '\u30aa\u30fc\u30d7\u30f3\u30bd\u30fc\u30b9', accent: '#3b82f6' },
  },
}

const SUBTITLES: Record<string, Record<string, string[]>> = {
  en: {
    'ot-hook': [
      'Factory protocols have no authentication.',
      'Modbus, SECS, S7comm \u2014 designed before security mattered.',
      'Legacy devices on modern networks.',
      'What if you could assess them in minutes?',
    ],
    'ot-discovery': [
      'Subnet scan identifies every device.',
      'Eight industrial protocol probes.',
      'MAC vendor identification and classification.',
      'Risk scoring from port and protocol analysis.',
    ],
    'ot-monitor': [
      'Continuous network monitoring.',
      'New device and port change detection.',
      'PLC register snapshot and drift alerts.',
      'MITRE ATT&CK for ICS mapping.',
    ],
    'ot-dashboard': [
      'Device inventory and risk overview.',
      'Vulnerability findings with CVE references.',
      'Four compliance frameworks in one view.',
      'IEC 62443, NIST CSF, ISO 27001, SEMI E187.',
    ],
    'ot-cta': [
      'Single Go binary. No dependencies.',
      'Read-only. Designed to be safe for production.',
      'Open source. MIT license.',
      'AI-assisted development.',
    ],
  },
  ja: {
    'ot-hook': [
      '\u5de5\u5834\u30d7\u30ed\u30c8\u30b3\u30eb\u306b\u306f\u8a8d\u8a3c\u304c\u3042\u308a\u307e\u305b\u3093\u3002',
      'Modbus\u3001SECS\u3001S7comm \u2014 \u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u4ee5\u524d\u306e\u8a2d\u8a08\u3002',
      '\u30e2\u30c0\u30f3\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u4e0a\u306e\u30ec\u30ac\u30b7\u30fc\u6a5f\u5668\u3002',
      '\u6570\u5206\u3067\u8a55\u4fa1\u3067\u304d\u308b\u3068\u3057\u305f\u3089\uff1f',
    ],
    'ot-discovery': [
      '\u30b5\u30d6\u30cd\u30c3\u30c8\u30b9\u30ad\u30e3\u30f3\u3067\u5168\u30c7\u30d0\u30a4\u30b9\u3092\u7279\u5b9a\u3002',
      '8\u3064\u306e\u7523\u696d\u30d7\u30ed\u30c8\u30b3\u30eb\u306b\u5bfe\u5fdc\u3002',
      'MAC\u30d9\u30f3\u30c0\u30fc\u8b58\u5225\u3068\u30c7\u30d0\u30a4\u30b9\u5206\u985e\u3002',
      '\u30dd\u30fc\u30c8\u3068\u30d7\u30ed\u30c8\u30b3\u30eb\u5206\u6790\u3067\u30ea\u30b9\u30af\u30b9\u30b3\u30a2\u7b97\u51fa\u3002',
    ],
    'ot-monitor': [
      '\u7d99\u7d9a\u7684\u306a\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u76e3\u8996\u3002',
      '\u65b0\u898f\u30c7\u30d0\u30a4\u30b9\u3068\u30dd\u30fc\u30c8\u5909\u66f4\u306e\u691c\u51fa\u3002',
      'PLC\u30ec\u30b8\u30b9\u30bf\u306e\u30b9\u30ca\u30c3\u30d7\u30b7\u30e7\u30c3\u30c8\u3068\u30c9\u30ea\u30d5\u30c8\u691c\u51fa\u3002',
      'MITRE ATT&CK for ICS\u3078\u306e\u30de\u30c3\u30d4\u30f3\u30b0\u3002',
    ],
    'ot-dashboard': [
      '\u30c7\u30d0\u30a4\u30b9\u30a4\u30f3\u30d9\u30f3\u30c8\u30ea\u3068\u30ea\u30b9\u30af\u6982\u8981\u3002',
      'CVE\u53c2\u7167\u4ed8\u304d\u306e\u8106\u5f31\u6027\u691c\u51fa\u3002',
      '4\u3064\u306e\u30b3\u30f3\u30d7\u30e9\u30a4\u30a2\u30f3\u30b9\u30d5\u30ec\u30fc\u30e0\u30ef\u30fc\u30af\u3092\u4e00\u753b\u9762\u3067\u3002',
      'IEC 62443\u3001NIST CSF\u3001ISO 27001\u3001SEMI E187\u3002',
    ],
    'ot-cta': [
      'Go\u5358\u4e00\u30d0\u30a4\u30ca\u30ea\u3002\u4f9d\u5b58\u95a2\u4fc2\u306a\u3057\u3002',
      '\u8aad\u307f\u53d6\u308a\u5c02\u7528\u3002\u672c\u756a\u74b0\u5883\u306b\u5b89\u5168\u306a\u8a2d\u8a08\u3002',
      '\u30aa\u30fc\u30d7\u30f3\u30bd\u30fc\u30b9\u3002MIT\u30e9\u30a4\u30bb\u30f3\u30b9\u3002',
      'AI\u652f\u63f4\u958b\u767a\u3002',
    ],
  },
}

function getSceneStart(scenes: SceneConfig[], index: number): number {
  return scenes.slice(0, index).reduce((sum, s) => sum + s.durationInFrames, 0)
}

export const OtSecVideo: React.FC<OtSecVideoProps> = ({ locale, scenes }) => {
  const frame = useCurrentFrame()
  const localeMeta = SCENE_META[locale] || SCENE_META.en
  const localeSubs = SUBTITLES[locale] || SUBTITLES.en

  // Determine current scene
  let currentSceneIndex = 0
  let accumulated = 0
  for (let i = 0; i < scenes.length; i++) {
    accumulated += scenes[i].durationInFrames
    if (frame < accumulated) { currentSceneIndex = i; break }
    if (i === scenes.length - 1) currentSceneIndex = i
  }
  const currentScene = scenes[currentSceneIndex]
  const meta = localeMeta[currentScene.scene] || { title: '', subtitle: '', accent: '#3b82f6' }

  // Subtitle calculation
  const sceneStart = getSceneStart(scenes, currentSceneIndex)
  const sceneFrame = frame - sceneStart
  const subs = localeSubs[currentScene.scene] || []
  const subDuration = currentScene.durationInFrames / Math.max(subs.length, 1)
  const subIndex = Math.min(Math.floor(sceneFrame / subDuration), subs.length - 1)
  const subText = subs[subIndex] || ''
  const subLocalFrame = sceneFrame - subIndex * subDuration
  const subOpacity = interpolate(subLocalFrame, [0, 10, subDuration - 8, subDuration], [0, 1, 1, 0], { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' })

  return (
    <AbsoluteFill style={{
      backgroundColor: '#080c12',
      fontFamily: '-apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", sans-serif',
    }}>
      {/* Scene sequences */}
      {scenes.map((scene, idx) => {
        const Component = SCENE_COMPONENTS[scene.scene]
        if (!Component) return null
        return (
          <Sequence key={scene.id} from={getSceneStart(scenes, idx)} durationInFrames={scene.durationInFrames}>
            <Component />
          </Sequence>
        )
      })}

      {/* Audio narration */}
      {scenes.map((scene, idx) => (
        scene.audioFile ? (
          <Sequence key={`audio-${scene.id}`} from={getSceneStart(scenes, idx)} durationInFrames={scene.durationInFrames}>
            <Audio src={staticFile(`audio/otsec-${locale}/${scene.audioFile}`)} volume={0.85} />
          </Sequence>
        ) : null
      ))}

      {/* Subtitles */}
      {subText && (
        <div style={{
          position: 'absolute',
          bottom: currentScene.scene === 'ot-cta' ? 40 : 150,
          left: 0, right: 0,
          textAlign: 'center',
          opacity: subOpacity,
        }}>
          <span style={{
            fontSize: 22,
            color: '#fff',
            background: 'rgba(0, 0, 0, 0.65)',
            padding: '8px 24px',
            borderRadius: 8,
            fontWeight: 500,
          }}>
            {subText}
          </span>
        </div>
      )}

      {/* Bottom bar (skip for CTA scene) */}
      {currentScene.scene !== 'ot-cta' && (
        <Sequence from={getSceneStart(scenes, currentSceneIndex)} durationInFrames={currentScene.durationInFrames}>
          <BottomBar
            title={meta.title}
            subtitle={meta.subtitle}
            accent={meta.accent}
            sceneIndex={currentSceneIndex}
            totalScenes={scenes.length}
          />
        </Sequence>
      )}
    </AbsoluteFill>
  )
}
