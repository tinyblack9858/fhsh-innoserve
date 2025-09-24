# fhsh-innoserve
資服競賽的東東!
這是一個可以以白名單的方式讓學生在考試的時候限制瀏覽哪些網頁的工具， 利用 ARP spoofing 去攔截他們傳出去的封包，再決定要不要傳出去。

## 完整流程

### 前置安裝與設定
`教師端`

安裝 node.js

使用指令「node -v」、「npm -v」確認是否安裝成功。

安裝 Git  

安裝 python

使用指令「python --version」確認是否安裝成功。

使用指令「pip install pyinstaller」安裝打包成 .exe 檔案的模組

使用指令「pip install scapy」安裝需要的 python 模組

至 Npcap 官方網站安裝 Npcap
    官方網站網址：https://npcap.com/#download
    安裝過程中務必勾選以下兩個選項
    
Support raw 802.11 traffic (and monitor mode) for wireless adapters

Install Npcap in WinPcap API-compatible Mode

—-----------------------------------------------------------------------------------------

`學生端`

為使監控系统可成功定位學生電腦，需事先為每台學生電腦設定

`防火牆規則:`

在學生電腦上透過WIN搜尋功能搜尋「防火牆與網路保護」，並找到「進階設定」。

在左側選單點「輸入規則 （Inbound Rules）」，並在右側選單中找到名為「檔案及印表機共用 (回應要求 - ICMPv4-In)」規則。

該規則上方單點右鍵，選擇「啟用規則」


—-----------------------------------------------------------------------------------------

`建立專案`

使用指令將專案下載下來。
「git clone https://github.com/tinyblack9858/fhsh-innoserve.git」

使用指令「cd fhsh-innoserve」進入專案資料夾內。

輸入「npm install」指令安裝套件。

使用指令「npm start」在本機運行該應用程式。在應用程式裡面按下開始監聽後，至此，ARP spoofing 攻擊已成功。

可使用指令「npm run dist」生成 .exe 檔案，亦可包裝成 APP。
