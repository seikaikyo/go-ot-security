# LinkedIn Post -- go-ot-security

## English

Built an OT/ICS security assessment tool as an open-source side project.

The problem: factory networks run protocols like Modbus, S7comm, and SECS/GEM that were designed decades ago -- most have no authentication or encryption. Connecting them to modern networks creates blind spots.

go-ot-security is a single Go binary that you can deploy on a Raspberry Pi and plug into a factory network.

Scans subnets and identifies devices using 8 industrial protocol probes. Detects vulnerabilities, default credentials, and insecure protocols. Maps findings to IEC 62443, NIST CSF 2.0, ISO 27001, and SEMI E187. Monitors for new devices, port changes, and PLC configuration drift. Includes an embedded React dashboard -- no separate frontend to deploy.

Read-only scanning only. No writes to any device. Single binary, no dependencies.

Built with AI-assisted development (Claude Code). MIT licensed.

GitHub: github.com/seikaikyo/go-ot-security

#OTSecurity #ICS #Go #OpenSource #IEC62443

---

## Japanese

OT/ICSセキュリティ評価ツールをオープンソースで開発しました。

工場ネットワークではModbus、S7comm、SECS/GEMなど数十年前に設計されたプロトコルが稼働しており、その多くは認証も暗号化もありません。モダンネットワークとの接続はセキュリティの盲点を生み出します。

go-ot-securityはGo単一バイナリで、Raspberry Piにデプロイして工場ネットワークに接続できます。

8つの産業プロトコルプローブでサブネットをスキャンし、デバイスを特定。脆弱性、デフォルトクレデンシャル、安全でないプロトコルを検出。IEC 62443、NIST CSF 2.0、ISO 27001、SEMI E187へのマッピング。新規デバイス、ポート変更、PLCレジスタの設定ドリフトを監視。組み込みReactダッシュボードでフロントエンドの別途デプロイ不要。

読み取り専用スキャンのみ。デバイスへの書き込みなし。依存関係なしの単一バイナリ。

AI支援開発（Claude Code）で構築。MITライセンス。

GitHub: github.com/seikaikyo/go-ot-security

#OTSecurity #ICS #Go #OpenSource #IEC62443
