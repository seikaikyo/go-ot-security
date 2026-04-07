import { interpolate, useCurrentFrame } from 'remotion'

interface BottomBarProps {
  title: string
  subtitle: string
  accent?: string
  sceneIndex: number
  totalScenes: number
}

export const BottomBar: React.FC<BottomBarProps> = ({
  title,
  subtitle,
  accent = '#3b82f6',
  sceneIndex,
  totalScenes,
}) => {
  const frame = useCurrentFrame()
  const slideUp = interpolate(frame, [0, 15], [60, 0], { extrapolateRight: 'clamp' })
  const opacity = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' })
  const subtitleOpacity = interpolate(frame, [8, 22], [0, 1], { extrapolateRight: 'clamp' })
  const progressWidth = ((sceneIndex + 1) / totalScenes) * 100

  return (
    <div
      style={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        height: 140,
        opacity,
        transform: `translateY(${slideUp}px)`,
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'linear-gradient(transparent, rgba(0,0,0,0.85))',
        }}
      />
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 2,
          background: accent,
          opacity: 0.7,
        }}
      />
      <div style={{ position: 'relative', padding: '20px 60px' }}>
        <div style={{ fontSize: 28, fontWeight: 700, color: '#fff' }}>{title}</div>
        <div style={{ fontSize: 18, fontWeight: 400, color: 'rgba(255,255,255,0.75)', marginTop: 4, opacity: subtitleOpacity }}>{subtitle}</div>
      </div>
      <div
        style={{
          position: 'absolute',
          bottom: 16,
          right: 60,
          fontSize: 14,
          color: 'rgba(255,255,255,0.4)',
        }}
      >
        {sceneIndex + 1}/{totalScenes}
      </div>
      <div
        style={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          height: 3,
          background: 'rgba(255,255,255,0.1)',
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${progressWidth}%`,
            background: accent,
          }}
        />
      </div>
    </div>
  )
}
