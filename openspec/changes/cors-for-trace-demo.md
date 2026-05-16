# CORS for trace-demo integration

## Type

feature

## 變更內容

`cmd/server/main.go` 加 chi/cors middleware，預設允許 `http://localhost:3000`
+ `https://trace-demo.seikai.dev` 兩個 origin。原因：trace-demo Topology
theme Edit 模式新增 Scan 按鈕會直接打 `/api/scan` `/api/scan/status`
`/api/assets`，沒 CORS 瀏覽器會擋預檢請求。

## 影響範圍

| 檔案 | 改動 |
|---|---|
| `cmd/server/main.go` | import strings + go-chi/cors，掛 cors.Handler 在 RealIP/Recoverer 之後 |
| `go.mod` `go.sum` | 加 `github.com/go-chi/cors v1.2.2` 直接 dep |

## 環境變數

`CORS_ALLOWED_ORIGINS`：CSV 覆寫，預設 `http://localhost:3000,https://trace-demo.seikai.dev`。

## 測試計畫

| 步驟 | 預期 |
|---|---|
| `go build ./...` | 通過 |
| `go run ./cmd/server`，從 localhost:3000 開 trace-demo 打 `/api/scan/status` | response header 帶 `Access-Control-Allow-Origin: http://localhost:3000` |
| 從未授權 origin 打 | 沒 Access-Control 標頭，瀏覽器擋 |
