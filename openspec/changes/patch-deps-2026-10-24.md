# 修補 chi 的 X-Forwarded-For 偽造

- **type**: fix
- **建立日期**: 2026-10-24

## 背景

2026-10-24 每日巡檢的 osv-scanner 列出 2 筆有修補版的漏洞：

1. go.mod：github.com/go-chi/chi/v5 v5.3.0，GHSA-j6qf-3m9c-vwj3（CVE-2026-114437，middleware 的 ClientIPFromXFF 可被 X-Forwarded-For 偽造用戶端 IP），v5.4.0 修補。
2. video/remotion/package-lock.json：zod 4.3.6，GHSA-mrhx-c7xc-m3w5，4.6.6 修補。

## 變更內容

`go get github.com/go-chi/chi/v5@v5.4.0` 後 `go mod tidy`，只動 chi 一個模組。

video/remotion 的 zod 不升級：@remotion/studio 4.0.441 把 zod 釘死在 4.3.6，npm 上最新的 @remotion/studio 4.0.538 也釘在 4.5.4，兩者都在受影響範圍內，升 remotion 也修不到。

## 影響範圍

| 對象 | 影響 |
| --- | --- |
| Go 服務 | chi 次版號升級，路由 API 不變。 |
| 依賴檔 | go.mod、go.sum。 |

## 剩餘風險

video/remotion 的 zod 4.3.6 等 Remotion 改用 zod 4.6.6 以上。remotion 只在本機算圖，不部署、不接受外部輸入。

## UI 規格

無 UI 變更。

## 測試計畫

1. `go build ./...` 通過，`go test ./...` 全部通過（3 個有測試的套件）。
2. `go vet ./...` 回報 internal/discovery/portscan.go:104 的 IPv6 位址格式問題，修補前的 HEAD 同樣出現，與本次變更無關，不在本提案處理。
