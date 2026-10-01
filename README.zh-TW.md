# ClaudeShield

**把機密檔案交給 Claude Code 處理，但機密內容不會離開你的電腦。**

ClaudeShield 是一組 Claude Code hooks 加上一個小指令工具，用 Go 寫成，沒有任何第三方套件。在你標記為「敏感」的資料夾裡，Claude 讀到的每個姓名、身分證字號、電話、Email、地址、金額、公司名和金鑰，都會在模型看到之前換成 `⟦PHONE_001⟧` 這種代號。Claude 寫檔或在本機執行指令時，代號再自動換回真實內容。所以你硬碟上的檔案是真實資料，送到 Anthropic 的對話裡只有代號。

除了遮罩，它還會：

- 每次開工作階段前，檢查你和 Anthropic 之間的連線有沒有被改道或攔截
- 把 Claude Code 的對話紀錄放進 AES-256 加密的磁碟映像
- 擋下要把資料送到你沒允許的網站的指令
- 擋下你沒核可過的擴充功能（外掛、MCP、hooks）

[English](README.md) · [設計文件](docs/DESIGN.md) · [導讀（給初學者）](docs/導讀.zh-TW.md)

本專案與 Anthropic 無關。以 macOS 為主（保險箱用 `hdiutil`）；hooks 和指令工具在 Linux 也能編譯和測試。

## 實際跑起來的樣子

下面是 [`scripts/e2e.sh`](scripts/e2e.sh) 的輸出。它在一個拋棄式的敏感資料夾裡放了一份假客戶名單，然後驅動真正的 Claude Code（v2.1.287，Haiku）：

```text
== 1. 整理客戶檔案
  --- Claude 的回答
  | ⟦NAME_001⟧, ⟦PHONE_001⟧, ⟦EMAIL_001⟧
  | ⟦NAME_002⟧, ⟦PHONE_002⟧, ⟦EMAIL_002⟧
  | ⟦NAME_003⟧, ⟦PHONE_003⟧, ⟦EMAIL_003⟧
  | Total: ⟦AMOUNT_004⟧
  PASS Claude 的回答裡沒有任何真實資料
  --- 硬碟上的 summary.md
  | 王小明, 0912-345-678, wang@acme-holdings.com.tw
  | 陳美玲, 0987-654-321, chen.ml@example-mail.tw
  | 林志豪, 0933-111-222, lin@zh-trading.com.tw
  | Total: NT$174300
  PASS 硬碟上的檔案是真實資料
  PASS 總額是用真實數字算的（174,300）
  PASS 存下來的對話紀錄裡沒有真實資料
== 2. 把資料送到白名單以外的網站
  PASS 被 ClaudeShield 擋下
== 3. 在訊息裡貼身分證字號
  PASS 訊息被擋下
```

Claude 從頭到尾只看到代號。它寫了一個 Python 程式，這個程式在你的電腦上用真實數字執行。裝了 `MessageDisplay` hook 的話，你自己終端機上看到的回覆會顯示真實內容；模型和對話紀錄裡仍然只有代號。

## 為什麼需要它

網路連線本來就有 TLS 加密，在咖啡廳被人錄封包看不到內容。使用 AI 助手時，機密真正會外流的地方是這些：

| 風險 | ClaudeShield 的做法 |
| --- | --- |
| 資料本身送到服務商、留在對方的紀錄裡（保存多久看帳號：30 天；個人帳號開著「幫助改善 Claude」是 5 年） | 在模型看到之前就遮罩；檢查帳號類型，個人帳號要你確認訓練開關已關閉 |
| 連線被改道：`ANTHROPIC_BASE_URL` 或代理伺服器被寫進 shell、設定檔、或下載的專案的 `.claude/settings.json` | 啟動前檢查所有環境變數和每一層設定檔，有就擋下 |
| 電腦裡被裝了根憑證，加密連線被解開（學校／公司管理的電腦、某些防毒軟體） | 不用系統信任清單，改用內建的釘選根憑證驗證 `api.anthropic.com`；DNS 結果和實際連線 IP 都要在 Anthropic 公布的網段內 |
| 硬碟上的明文對話紀錄（`~/.claude/projects`、`file-history`、`history.jsonl`） | 搬進加密映像；保險箱關著時，捷徑指向 root 擁有的 `/Volumes`，任何程式都寫不出明文 |
| 指令或提示注入把資料送出去（`curl -d`、`scp`、用 DNS 查詢夾帶資料、`git push`、`gh gist create`） | 分析每個指令會把資料送去哪；不准把代號換回真實內容後送上網；在敏感資料夾開啟 Claude Code 的系統沙盒 |
| 外掛更新或下載的專案偷偷多了 hook、MCP，能看到你的對話 | 用內容雜湊記錄每個擴充功能，有變動就擋下，直到你核可 |

## 安裝

需要 Go 1.24 以上來編譯。

```sh
git clone https://github.com/useless-husband/claudeshield && cd claudeshield
make build
./claudeshield install          # 把自己複製到 ~/.claudeshield/bin，並把 hooks 加進 ~/.claude/settings.json
claudeshield check              # 看目前的安全狀態
claudeshield vault create       # 建立 AES-256 加密的保險箱
# 關掉所有 Claude Code 視窗（包括桌面版 App）後：
claudeshield vault migrate
```

把資料夾標記成敏感資料夾，並列出規則猜不到的名字：

```sh
cd ~/work/clients
claudeshield init               # 寫入 .claudeshield.json，並為這個資料夾開啟沙盒
$EDITOR .claudeshield.json      # "terms": {"CLIENT": ["某某股份有限公司"], "PROJECT": ["獵鷹計畫"]}
claudeshield account confirm    # 個人帳號才需要：確認「幫助改善 Claude」已關閉
```

建議：把 `eval "$(claudeshield shell-init)"` 加進 `~/.zshrc`。之後打 `claude` 會先跑檢查，沒通過就不啟動。工作階段裡的 hooks 也會做同樣的檢查，所以這是第二層保護，不是唯一一層。

`claudeshield uninstall` 會移除 hooks 和它加的環境變數；保險箱和設定都會留著。

## 運作方式

每個部分在自己的套件裡：

- **`detect`** 找出機密：各家 API 金鑰、身分證與居留證（含檢查碼）、統一編號（含檢查碼）、信用卡（Luhn）、手機與市話、地址、Email、有貨幣符號的金額、公司名、欄位名稱是「姓名／電話／金額」的表格欄位、名單（`出席：王小明、陳美玲`）、稱謂前的姓名（`陳美玲小姐`），以及你自己列的詞。一般工作階段只跑高信心的「金鑰類」；敏感資料夾跑全部。
- **`tokenmap`** 保存「真實內容 ↔ 代號」對照表：同一個值永遠得到同一個代號；多個 hook 同時寫入時用檔案鎖和原子替換保護；存在保險箱裡。遮罩過的每個值都會用 Aho–Corasick 演算法再比對，所以一個名字就算後來單獨出現，也會被遮掉。
- **`hook`** 實作 SessionStart、UserPromptSubmit、PreToolUse、PostToolUse、MessageDisplay。
- **`egress`** 有一個小型 shell 解析器，分辨指令是「下載」還是「送出資料」。
- **`preflight`**、**`audit`**、**`vault`**、**`settings`**：啟動前檢查、擴充功能核可清單、加密保險箱、設定檔編輯。

## 驗證過什麼、怎麼驗證

全部在這台電腦上對 Claude Code v2.1.287 實測，指令都在專案裡：

- hook 改寫工具輸入（`updatedInput`）時不需要另外給決定，Claude Code 會照改寫後的內容走正常的權限流程。
- hook 改寫工具輸出（`updatedToolOutput`）後，Claude 看到的是改寫版，存下來的對話紀錄也是改寫版。
- 指令失敗時，hook 既不能改寫輸出，也不能停下這一輪（`continue: false` 在那個事件無效）；而且 Claude Code 的 Bash 拒絕 `trap`，也無法事先檢查 `{ }` 和 `$?`。所以 ClaudeShield 只在「沙盒會自動放行所有指令」的敏感資料夾裡包裝指令並回「允許」，詳見[設計文件](docs/DESIGN.md#the-failed-command-problem)。
- 用真的 AES-256 加密映像測試：密碼錯誤打不開、寫入後映像檔裡找不到明文、保險箱關上後透過捷徑寫入會失敗（`make vault-test`，CI 在 macOS 上也會跑）。
- 自製的「攔截用憑證」會被拒絕，真正的 Anthropic 憑證鏈會通過。

`go test ./...` 有 104 個測試、3 個模糊測試（fuzz），以及固定亂數種子的性質測試（5,000 份隨機文件遮罩後還原必須一模一樣；6 個程式同時寫同一份對照表；Aho–Corasick 和暴力搜尋結果一致）。偵測模組的覆蓋率 93%。

## 效能

Apple M5（10 核）、macOS 27，這台電腦同時有其他編譯工作在跑。指令：`make bench`、`make bench-hook`。

| 項目 | 結果 |
| --- | --- |
| 偵測，一般模式，100 KB 混合文字 | 0.86 毫秒 |
| 偵測，全面模式，100 KB 混合文字 | 10.7 毫秒 |
| 全面模式，同樣文字，外加 2,000 個記住的值要比對 | 10.9 毫秒 |
| hook 處理一次 `ls` | 中位數 3.7 毫秒 |
| hook 遮罩 100 KB 程式碼（一般資料夾） | 中位數 5.5 毫秒 |
| hook 遮罩 100 KB、約 2,000 筆的客戶 CSV（敏感資料夾） | 中位數 78 毫秒 |

## 限制

使用前請先看完：

- **偵測靠規則。** 散文裡沒有標籤、稱謂、名單或表格的名字抓不到，要加進 `terms`。兩個字的名字不猜。金額要有貨幣符號、欄位名稱或標籤。你的程式在本機算出來、直接印出來又沒有貨幣符號的數字（總額、平均），Claude 看得到：原始資料仍然遮著，但算出來的結果不會。
- **圖片、PDF、Office 檔在敏感資料夾裡會被拒絕讀取，不會遮罩。** 請先轉成文字（`textutil -convert txt 檔名.docx`、`pdftotext 檔名.pdf`）。
- **`@檔案` 引用會繞過工具**，所以敏感資料夾裡會擋下用 `@` 引用檔案的訊息，請改成用文字說「請讀 檔名」。
- **沒有沙盒的地方，失敗指令的輸出不會遮罩。** 在 `claudeshield init` 設定好的資料夾裡會包裝指令，讓失敗的輸出也經過遮罩；但指令自己呼叫 `exit` 的話還是會跳出包裝。
- **對話紀錄裡還是有一處存著真實內容。** Claude Code 會把每個 hook 的原始輸出存進對話紀錄；把代號換回真實內容來寫檔的那段輸出，裡面就是真實資料。Claude 收不到它，但它在硬碟上，所以需要保險箱。沒有保險箱時，敏感資料夾會擋下，除非你明確接受。
- **hook 程式必須存在。** 如果執行檔被刪掉，Claude Code 會當成 hook 啟動失敗然後繼續執行。`claudeshield check` 和 `claudeshield run` 會發現，但沒經過它們啟動的工作階段不會。
- **指令分析是盡力而為。** 刻意設計的指令可以藏住連線目的地。在敏感資料夾外，這是唯一一層網路把關；在資料夾內，系統沙盒會強制執行白名單。
- **它改變不了服務商的保存政策。** 遮罩限制的是送出去什麼；送出去的部分保存多久，由你的帳號條款決定。
- **你自己的螢幕**會顯示真實內容（MessageDisplay 的設計）。啟動前檢查會警告正在執行的遠端桌面程式，但看不到攝影機。

## 相關專案

就我所知，還沒有工具同時做到遮罩、連線檢查、加密對話紀錄和擴充功能稽核，但每一塊都有鄰居：

- [mask2ai](https://github.com/serkankorkut/mask2ai) 最接近：Claude Code 外掛，遮罩工具輸出裡的個資、在工具輸入裡還原代號、擋下含個資的訊息，並用 MessageDisplay 在螢幕上還原（ClaudeShield 借用了最後這個點子）。它針對土耳其的格式，沒有處理失敗指令、對外連線、連線本身、對話紀錄加密或擴充功能。
- [redact-hook](https://github.com/SilentAutomaton/redact-hook) 和 [GitGuardian ggshield 的 AI hook](https://github.com/GitGuardian/ggshield/pull/1480) 會遮掉或扣住工具輸出裡的金鑰，是單向的（沒有可以還原的代號）。
- [LLM Guard](https://github.com/protectai/llm-guard) 的 Anonymize/Deanonymize 和 [Microsoft Presidio](https://github.com/microsoft/presidio) 為一般 LLM 應用提供可還原的個資匿名化，用的是 NER 模型；ClaudeShield 改用規則和檢查碼，維持一個每次工具呼叫都跑得動的小執行檔。
- Claude Code 自己的[沙盒](https://code.claude.com/docs/en/sandboxing)和[權限規則](https://code.claude.com/docs/en/permissions)提供系統層級的強制力，ClaudeShield 在上面加了看內容的判斷。

## 編譯與測試

```sh
make build        # ./claudeshield
make test         # 單元、整合、性質測試
make race         # 加上資料競爭檢查
make lint         # gofmt、go vet、staticcheck
make fuzz         # 每個模糊測試跑 30 秒
make vault-test   # 真的加密映像（macOS）
make e2e          # 真的 Claude Code；需要已登入的 claude，會用到一點 Haiku 額度
make bench bench-hook
```

MIT 授權。
