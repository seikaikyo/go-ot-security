import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion'

interface AnimatedTextProps {
  text: string
  delay?: number
  fontSize?: number
  color?: string
  fontWeight?: number
  style?: React.CSSProperties
  type?: 'fade-up' | 'spring' | 'typewriter'
}

export const AnimatedText: React.FC<AnimatedTextProps> = ({
  text,
  delay = 0,
  fontSize = 48,
  color = '#e4e8f0',
  fontWeight = 700,
  style = {},
  type = 'fade-up',
}) => {
  const frame = useCurrentFrame()
  const { fps } = useVideoConfig()
  const f = Math.max(0, frame - delay)

  if (type === 'spring') {
    const scale = spring({ frame: f, fps, config: { damping: 12, stiffness: 80 } })
    const opacity = interpolate(f, [0, 8], [0, 1], { extrapolateRight: 'clamp' })
    return (
      <div style={{ fontSize, fontWeight, color, opacity, transform: `scale(${scale})`, ...style }}>
        {text}
      </div>
    )
  }

  if (type === 'typewriter') {
    const charsToShow = Math.floor(interpolate(f, [0, text.length * 2], [0, text.length], { extrapolateRight: 'clamp' }))
    const opacity = interpolate(f, [0, 5], [0, 1], { extrapolateRight: 'clamp' })
    return (
      <div style={{ fontSize, fontWeight, color, opacity, ...style }}>
        {text.slice(0, charsToShow)}
        <span style={{ opacity: f % 20 < 10 ? 1 : 0, color: '#ef4444' }}>|</span>
      </div>
    )
  }

  // fade-up
  const opacity = interpolate(f, [0, 15], [0, 1], { extrapolateRight: 'clamp' })
  const translateY = interpolate(f, [0, 15], [30, 0], { extrapolateRight: 'clamp' })

  return (
    <div style={{ fontSize, fontWeight, color, opacity, transform: `translateY(${translateY}px)`, ...style }}>
      {text}
    </div>
  )
}
