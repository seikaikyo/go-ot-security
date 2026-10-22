# go-ot-security

OT/ICS 資安評估與監控平台，單一 Go 執行檔內嵌網頁儀表板，可放在樹莓派上接進工廠網路掃描。功能與控制項對應見 `README.md`。

## 目錄

| 路徑 | 內容 |
|------|------|
| `cmd/server/` | 執行檔進入點 |
| `internal/discovery/` | 網段掃描與工控協定辨識 |
| `internal/vuln/` | 已知 CVE 比對 |
| `internal/compliance/` | 控制項與標準對應 |
| `internal/monitor/` | 持續監控 |
| `internal/agent/` | 掃描代理與回報（含對協調端的身分驗證） |
| `internal/server/` | HTTP API 與儀表板 |
| `internal/store/` | 資料儲存 |
| `internal/config/` | 設定 |
| `web/dashboard/` | 儀表板前端（Vite），建構產物內嵌進執行檔 |
| `openspec/` | 變更提案，改動 20 行以上先在 `openspec/changes/` 建提案 |

## 部署

沒有雲端部署，以執行檔形式在現場設備上跑。

## 開發

- Go 版本照 `go.mod`（toolchain go1.26.10）
- 驗證：`go build ./...`、`go vet ./...`、`go test ./...`。`go vet` 目前有一個既有警告：`internal/discovery/portscan.go` 的 `"%s:%d"` 位址格式不支援 IPv6
- 這是公開 repo，不放本機路徑、帳號、金鑰
