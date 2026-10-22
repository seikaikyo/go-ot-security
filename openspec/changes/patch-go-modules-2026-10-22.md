# 升級 golang.org/x/sys 與工具鏈修補已知漏洞

- **type**: fix
- **建立日期**: 2026-10-22

## 背景

2026-10-22 每日資安巡檢的 osv-scanner 對本 repo 回報 1 筆已知漏洞，來自 `go.mod` 的 `golang.org/x/sys` v0.42.0，修補版本 v0.44.0。

同日 Go 發布 go1.26.9（10/8，crypto/tls、net/http 等安全修補）與 go1.26.10（10/19，crypto/x509 封鎖遭入侵的 eMudhra 中繼憑證機構，CVE-2026-111943）。`go.mod` 的 `toolchain` 還寫 go1.26.7。repo 也一直缺 CLAUDE.md，推送檢查會擋。

## 變更內容

1. `go get golang.org/x/sys@v0.44.0` 加 `go mod tidy`，同一主版本內升級。
2. `go mod edit -toolchain=go1.26.10`。
3. 新增 `CLAUDE.md`，說明目錄、部署方式與驗證指令。

## 影響範圍

| 對象 | 影響 |
| --- | --- |
| 執行期行為 | 無功能變更。 |
| go.mod / go.sum | 兩檔更新。 |
| 部署 | 沒有雲端部署，以執行檔在現場設備上跑。 |

## UI 規格

無 UI 變更。

## 測試計畫

1. `go build ./...`、`go vet ./...`、`go test ./...` 通過（2026-10-22 本機已跑過；vet 只有既有的 IPv6 位址格式警告）。
2. 推送後重跑每日巡檢，確認 osv-details/go-ot-security.json 的漏洞數歸零。
