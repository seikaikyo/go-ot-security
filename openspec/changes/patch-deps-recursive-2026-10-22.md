# 升級影片專案的 npm 相依套件修補已知漏洞

- **type**: fix
- **建立日期**: 2026-10-22

## 背景

2026-10-22 每日資安巡檢的 osv-scanner 原本沒有遞迴掃描，子目錄的鎖定檔沒被掃到。補上遞迴掃描後，`video/remotion/package-lock.json` 有 8 個套件、25 筆漏洞可在同一主版號內修補。修補前 `npm audit`：critical 1、high 12、moderate 1，共 14 筆（全部屬於執行期相依）。

Go 模組已在同日的 `patch-go-modules-2026-10-22` 提案處理，本提案不動 `go.mod` 與 `go.sum`。

## 變更內容

1. `npm update` 在既有範圍內升級：baseline-browser-mapping 2.10.13 → 2.11.30、browserslist 4.28.2 → 4.29.4、fast-uri 3.1.0 → 3.1.9、nanoid 3.3.11 → 3.3.20、source-map-js 1.2.1 → 1.2.2
2. Remotion 4.0.441 把下列三個套件釘死在舊版，`npm update` 拉不上去，改在 package.json 加 `overrides`，只釘在同一主版號：
   - loader-utils 2.0.2 → 2.0.4（`^2.0.4`，經 @remotion/bundler）
   - postcss 8.5.1 → 8.5.31（`^8.5.23`，經 @remotion/bundler）
   - ws 8.17.1 → 8.22.0（`^8.21.0`，經 @remotion/renderer）

不升 Remotion、不改程式碼，只動 package.json 與 lock 檔。

## 影響範圍

| 對象 | 影響 |
| --- | --- |
| 執行期行為 | 影片打包與算圖工具鏈的修補版升級，影片內容不變。 |
| 依賴檔 | `video/remotion/package.json`（新增 overrides）與 lock 檔。 |
| 部署 | 沒有雲端部署，影片在本機算圖。 |

## 剩餘風險

修補後 `npm audit`：high 6 筆，全部來自 extract-zip 2.0.1（經 @remotion/renderer 引入）。extract-zip 官方沒有修補版，等上游發版或 Remotion 換掉這個套件。

## UI 規格

無 UI 變更。

## 測試計畫

1. `npm ci` 修補前後都成功。
2. `npx tsc --noEmit` 修補前後都是同樣 2 個既有型別錯誤（`src/Root.tsx` 的 Composition 元件型別），與本次升級無關。
3. `npx remotion bundle src/index.ts` 修補前後都成功，產出檔案數相同（30 個）。
4. `npm audit` 修補前 14 筆，修補後 6 筆。
5. 推送後重跑每日巡檢，確認 osv-details/go-ot-security.json 的漏洞數下降。
