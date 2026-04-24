# scan-process

遠端機器可疑 Process 掃描工具。透過 SSH 連入機房中的 Linux 機器，偵測高 CPU 使用率、加密貨幣挖礦程式、無檔案惡意程式及異常監聽 Port，並可在發現問題時自動發送 Slack 告警。

---

## 功能

| 嚴重程度 | 偵測項目 |
|----------|----------|
| CRITICAL | 已知加密貨幣挖礦程式（xmrig、minerd 等） |
| HIGH | 執行檔已被刪除的 Process（無檔案惡意程式指標） |
| HIGH | 從可疑路徑執行的程式（/tmp、/dev/shm 等） |
| MEDIUM | 即時 CPU 使用率超過 80% 的 Process |
| MEDIUM | Process 名稱為隨機 hex 字串（8 位以上） |
| LOW | 監聽非常用 Port（>1024）的 Process |

---

## 安裝

```bash
# 建立並啟用 Python 虛擬環境
python3 -m venv scan-process
source scan-process/bin/activate

# 安裝依賴套件
pip install -r requirements.txt
```

---

## 設定

複製並編輯 `config.yaml`，填入要掃描的機器資訊：

```yaml
machines:
  - ip: "192.168.1.10"
    username: "root"
    password: "your_password"
    port: 22          # 可選，預設 22
    label: "web001"   # 可選，預設使用 IP

  - ip: "192.168.1.11"
    username: "admin"
    password: "your_password"
    label: "db001"

# Slack 告警設定（可選）
slack_webhook_url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
slack_alert_severity:
  - CRITICAL
  - HIGH
  - MEDIUM
```

> **注意：** 請勿將含有真實密碼的 `config.yaml` 提交至版本控制系統。

---

## 使用方式

```bash
# 使用預設的 config.yaml 執行掃描
python scan.py

# 指定自訂設定檔
python scan.py --config /path/to/my_config.yaml

# 將報告儲存到指定路徑（預設自動命名並存放於 scan-report/ 目錄）
python scan.py --output /tmp/my_report.json

# 顯示每台機器的原始指令輸出（用於 debug）
python scan.py --verbose
```

---

## 報告輸出

掃描結束後，JSON 報告會自動儲存至 `scan-report/` 目錄，檔名格式為：

```
scan-report/scan_report_YYYYMMDD_HHMMSS.json
```

報告結構範例：

```json
{
  "scan_time": "2026-04-24T03:00:00.000000",
  "machines": [
    {
      "ip": "192.168.1.10",
      "label": "web001",
      "status": "connected",
      "suspicious_processes": [
        {
          "pid": "1234",
          "name": "xmrig",
          "user": "root",
          "cpu": "95.0",
          "cmd": "/tmp/xmrig --pool ...",
          "reason": "Known crypto miner process",
          "severity": "CRITICAL"
        }
      ]
    }
  ]
}
```

`status` 欄位可能值：

| 值 | 說明 |
|----|------|
| `connected` | 連線並掃描成功 |
| `connection_failed` | 無法建立 SSH 連線 |
| `scan_failed` | 連線成功但掃描過程發生錯誤 |

---

## Slack 告警

在 `config.yaml` 中填入 Slack Incoming Webhook URL，當掃描發現符合 `slack_alert_severity` 設定嚴重程度的 Process 時，會自動推送告警訊息。

取得 Webhook URL：Slack 工作區 → Apps → Incoming Webhooks → 新增設定

---

## 專案結構

```
scan-process/
├── scan.py          # 主程式
├── config.yaml      # 機器連線設定（請勿 commit 真實憑證）
├── requirements.txt # Python 依賴套件
├── scan-report/     # 掃描報告輸出目錄（自動建立）
└── README.md
```
