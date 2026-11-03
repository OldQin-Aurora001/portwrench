# 有窗监听夹具（fixture_windowed.ps1）
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File fixture_windowed.ps1 -Port 46001 [-IgnoreCloseCount 1]
# 行为：创建带标题的可见 WinForms 窗体 + 127.0.0.1 TcpListener；就绪后输出一行 READY；
#       收到 WM_CLOSE 正常退出；-IgnoreCloseCount N 时由 FormClosing 取消前 N 次关窗
#       （用于稳定构造 428 强杀确认路径）。只用于本测试：不写文件、不联网（仅回环）。
param(
    [int]$Port = 46001,
    [int]$IgnoreCloseCount = 0
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'PortConsole Test Window'
$form.Size = New-Object System.Drawing.Size(360, 220)
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(40, 40)

$script:IgnoreLeft = $IgnoreCloseCount
$form.add_FormClosing({
    param($sender, $e)
    if ($script:IgnoreLeft -gt 0) {
        $script:IgnoreLeft = $script:IgnoreLeft - 1
        $e.Cancel = $true
    }
})

$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
$listener.Start()

# 监听就绪后、进入消息循环前，主流程输出一行 READY
# （不可放 Add_Shown 事件里——事件回调的 Write-Output 不进 stdout 管道）
Write-Output 'READY'

try {
    [System.Windows.Forms.Application]::Run($form)
}
finally {
    $listener.Stop()
}
