import { Composition, Still } from 'remotion'
import { OtSecVideo } from './OtSecVideo'
import { OtThumbnail } from './scenes/OtThumbnail'
import { SCENES as SCENES_EN, TOTAL_FRAMES as TOTAL_EN, FPS } from './audioConfig.otsec.en'
import { SCENES as SCENES_JA, TOTAL_FRAMES as TOTAL_JA } from './audioConfig.otsec.ja'

export const RemotionRoot: React.FC = () => {
  return (
    <>
      {/* Thumbnail / Cover */}
      <Still
        id="OtSec-Thumbnail"
        component={OtThumbnail}
        width={1920}
        height={1080}
      />

      {/* Videos */}
      <Composition
        id="OtSec-EN"
        component={OtSecVideo}
        fps={FPS}
        durationInFrames={TOTAL_EN}
        width={1920}
        height={1080}
        defaultProps={{ locale: 'en', scenes: SCENES_EN }}
      />
      <Composition
        id="OtSec-JA"
        component={OtSecVideo}
        fps={FPS}
        durationInFrames={TOTAL_JA}
        width={1920}
        height={1080}
        defaultProps={{ locale: 'ja', scenes: SCENES_JA }}
      />
    </>
  )
}
