---
title: 英文版 + 日文版介紹影片
type: feature
status: in-progress
created: 2026-04-01
---

# 英文版 + 日文版介紹影片

## 變更內容

建立 Remotion 影片專案，產出 go-ot-security 的英文與日文介紹影片。
沿用 smart-factory-demo 的架構模式（scene 元件 + audioConfig + TTS 腳本）。

影片結構（5 場景，約 60-90 秒）：
1. **Hook** — OT 環境的資安挑戰（工廠網路暴露、legacy 設備無加密）
2. **Discovery** — Phase 1+2 資產發現 + 弱點掃描（掃描動畫 + 合規框架）
3. **Monitor** — Phase 3+4 即時監控 + 設定管理（告警 + diff 偵測）
4. **Dashboard** — 嵌入式 React 介面展示（dark theme 技術風）
5. **CTA** — 開源、MIT、AI-assisted development

TTS 方案：
- 英文：Google Cloud TTS (en-US-Neural2-D) 或 ElevenLabs
- 日文：Google Cloud TTS (ja-JP-Neural2-D) 或 ElevenLabs

## 影響範圍

新增目錄（不影響現有程式碼）：
- `video/narration.otsec.en.tsv` — 英文旁白稿
- `video/narration.otsec.ja.tsv` — 日文旁白稿
- `video/remotion/` — Remotion 專案
  - `src/OtSecVideo.tsx` — 主影片元件
  - `src/Root.tsx` / `src/index.ts` — Remotion 入口
  - `src/audioConfig.otsec.en.ts` — 英文音檔設定（自動產生）
  - `src/audioConfig.otsec.ja.ts` — 日文音檔設定（自動產生）
  - `src/scenes/` — 5 個場景元件
  - `src/components/` — 共用元件（BottomBar, AnimatedText）
  - `generate-audio.py` — TTS 產生腳本
  - `package.json` / `tsconfig.json`

## 旁白稿合規檢查（2.5 條）

- [ ] 無 `certified` / `compliant` / `production ready` 用語
- [ ] AI-assisted development 標註
- [ ] 標準引用用 `implements` / `follows`，不用 `certified`
- [ ] 效能數據標明環境（simulator）
- [ ] Google Cloud TTS ToS 遵守，不偽裝真人

## 測試計畫

1. `npm run dev` 開啟 Remotion Studio 預覽
2. 英文版 render 無錯誤
3. 日文版 render 無錯誤
4. 旁白音檔正常播放、字幕同步
5. 輸出 MP4 可正常播放
