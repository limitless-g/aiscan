#Requires -Version 5.1
<#
================================================================================
 aiscan 一键部署 —— 把这套工具链装到「这台电脑」上
================================================================================

 为什么需要它
 ---------------------------------------------------------------------------
 工具链原先只在本机跑得起来：Python 环境建在固定路径、nuclei / sqlmap 的
 位置写死在代码里。把它拷到另一台电脑，那些位置全都不成立 —— 工具会被
 判成「未安装」，而报告上只看得出「未安装」，看不出其实是路径没找对。

 这个脚本做四件事，把「另一台电脑」变成「能跑」：
   ① 找到一个可用的 Python（**装了 WorkBuddy 的机器上自带一个**，不用另装）
   ② 在包内建一个隔离 venv（.venv\）—— 不污染系统环境，删掉即卸载
   ③ 按 requirements.txt 装依赖
   ④ 探测工具链 + 跑离线自测，把「能不能用」当面告诉你

 用法
 ---------------------------------------------------------------------------
   PowerShell 下（推荐）：
       powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
   直接双击（会自动绕过执行策略）：
       install.cmd

 参数
 ---------------------------------------------------------------------------
   -Python <路径>   指定解释器（不想让它自动挑时用）
   -SkipDeps        跳过装依赖（离线、或依赖已装好）
   -QuickTest       装完只做轻量检查，不跑完整离线自测
   -NoPause         跑完不等回车（脚本化调用时用）

 设计约定（与项目里 Windows 部署脚本保持一致）
 ---------------------------------------------------------------------------
   · 阶段独立容错：某一步失败**不中断**后续步骤；最后统一输出诊断汇总，
     让人一次看到全貌，而不是修一个跑一次。
   · 只报告、不乱改：不动系统 PATH、不写注册表、不改系统 Python 环境。
   · 中文输出：本文件已存为 UTF-8 with BOM —— 否则 PowerShell 5.1 会把
     中文读成乱码（这是 Windows 部署脚本最经典的坑之一）。
================================================================================
#>

[CmdletBinding()]
param(
    [string]$Python = "",
    [switch]$SkipDeps,
    [switch]$QuickTest,
    [switch]$NoPause
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

# ---------------------------------------------------------------------------
# 控制台编码：把整条链路统一到 UTF-8
# ---------------------------------------------------------------------------
# 本脚本**自身**的中文靠「文件存为 UTF-8 with BOM」保住；但**子进程**（python）
# 的输出是另一条链路 —— aiscan 显式以 UTF-8 写出，而 Windows 控制台默认是
# GBK（代码页 936）。不切编码，工具链清单那一段就是一片乱码，用户看到会以为
# 脚本坏了（其实功能完全正常，只是字花了）。这三行把链路统一到 UTF-8。
try { $null = & cmd.exe /c "chcp 65001" 2>&1 } catch { }
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }
$env:PYTHONIOENCODING = "utf-8"

# ---------------------------------------------------------------------------
# 诊断收集：每步的结果都记下来，最后统一汇报
# ---------------------------------------------------------------------------
$script:Steps = New-Object System.Collections.ArrayList

function Add-Step {
    param([string]$Name, [string]$Status, [string]$Detail = "")
    [void]$script:Steps.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
}

function Write-Head {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
}

function Write-Info  { param([string]$T) Write-Host ("  · " + $T) }
function Write-Ok    { param([string]$T) Write-Host ("  + " + $T) -ForegroundColor Green }
function Write-Warn2 { param([string]$T) Write-Host ("  ! " + $T) -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# ① 找一个能用的 Python
# ---------------------------------------------------------------------------
function Find-PythonRuntime {
    # (a) 包内已经建好的 venv —— 重复执行本脚本时直接复用
    $inVenv = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $inVenv) {
        return @{ Exe = $inVenv; Args = @(); Kind = "包内 venv（此前已部署过）" }
    }

    # (b) 命令行显式指定
    if ($Python -ne "" -and (Test-Path $Python)) {
        return @{ Exe = $Python; Args = @(); Kind = "命令行 -Python 指定" }
    }

    # (c) WorkBuddy 自带 —— 装了 WorkBuddy 的电脑上就有，**不用另装 Python**
    $wbRoot = Join-Path $env:LOCALAPPDATA "Programs\WorkBuddy\resources\vendor\python"
    $wbExe  = Join-Path $wbRoot "python.exe"
    if (Test-Path $wbExe) {
        return @{ Exe = $wbExe; Args = @(); Kind = "WorkBuddy 自带（无需另装）" }
    }

    # (d) Windows py 启动器
    $pyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $pyCmd) {
        return @{ Exe = $pyCmd.Source; Args = @("-3"); Kind = "Windows py 启动器" }
    }

    # (e) PATH 上的 python
    $pyPath = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $pyPath) {
        return @{ Exe = $pyPath.Source; Args = @(); Kind = "PATH 上的 python" }
    }

    return $null
}

Write-Head "aiscan 一键部署"
Write-Info ("目标目录：" + $Root)
Write-Info ("PowerShell：" + $PSVersionTable.PSVersion.ToString())

$runtime = Find-PythonRuntime
if ($null -eq $runtime) {
    Write-Warn2 "没有找到任何 Python 解释器"
    Add-Step "定位 Python" "失败" "未找到解释器"
    Add-Step "建 venv" "跳过" "缺少 Python"
    Add-Step "装依赖" "跳过" "缺少 Python"
    Add-Step "工具链探测" "跳过" "缺少 Python"
    Add-Step "离线自测" "跳过" "缺少 Python"
} else {
    Write-Ok ("Python：" + $runtime.Exe + "   （" + $runtime.Kind + "）")
    Add-Step "定位 Python" "成功" $runtime.Kind

    $venvPython = Join-Path $Root ".venv\Scripts\python.exe"

    # -----------------------------------------------------------------------
    # ② 建隔离 venv
    # -----------------------------------------------------------------------
    Write-Head "建立隔离环境（.venv\）"
    if (Test-Path $venvPython) {
        Write-Ok "已存在，跳过创建"
        Add-Step "建 venv" "成功" "复用已有 .venv"
    } else {
        Write-Info "正在创建 .venv（需要十几秒）……"
        & $runtime.Exe @($runtime.Args) -m venv (Join-Path $Root ".venv") 2>&1 | ForEach-Object { Write-Info $_ }
        if (Test-Path $venvPython) {
            Write-Ok ".venv 创建成功"
            Add-Step "建 venv" "成功" ""
        } else {
            Write-Warn2 ".venv 创建失败（后面几步会跳过）"
            Add-Step "建 venv" "失败" ("退出码 " + $LASTEXITCODE)
        }
    }

    $haveVenv = Test-Path $venvPython
    $depsOk = $false

    # -----------------------------------------------------------------------
    # ③ 装依赖
    # -----------------------------------------------------------------------
    Write-Head "安装依赖（requirements.txt）"
    if (-not $haveVenv) {
        Write-Warn2 "跳过：没有可用的 venv"
        Add-Step "装依赖" "跳过" "无 venv"
    } elseif ($SkipDeps) {
        Write-Info "按 -SkipDeps 跳过"
        Add-Step "装依赖" "跳过" "命令行要求跳过"
        $depsOk = $true
    } else {
        $req = Join-Path $Root "requirements.txt"
        if (-not (Test-Path $req)) {
            Write-Warn2 "找不到 requirements.txt"
            Add-Step "装依赖" "失败" "缺少 requirements.txt"
        } else {
            Write-Info "正在安装（首次需要联网）……"
            & $venvPython -m pip install --disable-pip-version-check --quiet `
                --upgrade pip 2>&1 | ForEach-Object { Write-Info $_ }
            & $venvPython -m pip install --disable-pip-version-check `
                -r $req 2>&1 | ForEach-Object { Write-Info $_ }
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "依赖安装完成"
                Add-Step "装依赖" "成功" ""
                $depsOk = $true
            } else {
                Write-Warn2 ("依赖安装失败（退出码 " + $LASTEXITCODE + "）—— 检查网络，或用 -SkipDeps")
                Add-Step "装依赖" "失败" ("退出码 " + $LASTEXITCODE)
            }
        }
    }

    # -----------------------------------------------------------------------
    # ④ 工具链探测
    # -----------------------------------------------------------------------
    Write-Head "探测外部工具链"
    if (-not $haveVenv) {
        Write-Warn2 "跳过：没有可用的 venv"
        Add-Step "工具链探测" "跳过" "无 venv"
    } elseif (-not $depsOk) {
        Write-Warn2 "跳过：依赖未装好"
        Add-Step "工具链探测" "跳过" "依赖未装好"
    } else {
        & $venvPython (Join-Path $Root "aiscan.py") tools 2>&1 | ForEach-Object { Write-Host ("  " + $_) }
        Add-Step "工具链探测" "成功" "见上方清单（缺失的工具会自动降级）"
    }

    # -----------------------------------------------------------------------
    # ⑤ 离线自测 —— 「能不能跑」当面验证，不用等真扫一次
    # -----------------------------------------------------------------------
    Write-Head "离线自测（不外网）"
    if (-not $haveVenv -or -not $depsOk) {
        Write-Warn2 "跳过：环境没准备好"
        Add-Step "离线自测" "跳过" "环境未就绪"
    } elseif ($QuickTest) {
        Write-Info "按 -QuickTest 只做轻量编译检查"
        & $venvPython -c "import compileall,sys; sys.exit(0 if compileall.compile_dir('.', quiet=1) else 1)" 2>&1 |
            ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "全部模块编译通过"
            Add-Step "离线自测" "成功" "轻量检查（未跑完整自测）"
        } else {
            Write-Warn2 "存在编译错误"
            Add-Step "离线自测" "失败" "编译错误"
        }
    } else {
        Write-Info "正在跑完整离线自测（约 1-3 分钟）……"
        & $venvPython (Join-Path $Root "aiscan.py") selftest 2>&1 |
            Select-Object -Last 25 | ForEach-Object { Write-Host ("  " + $_) }
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "离线自测通过"
            Add-Step "离线自测" "成功" ""
        } else {
            Write-Warn2 ("离线自测未通过（退出码 " + $LASTEXITCODE + "）")
            Add-Step "离线自测" "失败" ("退出码 " + $LASTEXITCODE)
        }
    }
}

# ---------------------------------------------------------------------------
# 诊断汇总
# ---------------------------------------------------------------------------
Write-Head "DIAGNOSIS SUMMARY"
foreach ($s in $script:Steps) {
    $line = "  [{0,-4}] {1,-14} {2}" -f $s.Status, $s.Name, $s.Detail
    switch ($s.Status) {
        "成功" { Write-Host $line -ForegroundColor Green }
        "跳过" { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line -ForegroundColor Red }
    }
}

$failed = @($script:Steps | Where-Object { $_.Status -eq "失败" })
$venvPythonFinal = Join-Path $Root ".venv\Scripts\python.exe"

Write-Host ""
if ($failed.Count -eq 0 -and (Test-Path $venvPythonFinal)) {
    Write-Host "  部署完成。以后这样用：" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    .\.venv\Scripts\python.exe aiscan.py checklist          # 看全量检查项清单"
    Write-Host "    .\.venv\Scripts\python.exe aiscan.py ledger --register 目标域名 --name 名称 --authorizer 审批人 --ref 依据"
    Write-Host "    .\.venv\Scripts\python.exe aiscan.py scan --target 目标域名 --name 名称 --profile standard"
    Write-Host ""
    Write-Host "  注意：未登记授权的目标会被引擎拒绝 —— 这是合规闸门，不是故障。" -ForegroundColor Yellow
} else {
    Write-Host "  部署未完成，请按上面标红的步骤排查。" -ForegroundColor Red
    Write-Host "  最常见的原因：没联网（装依赖需要）、或杀毒软件拦住了子进程。" -ForegroundColor Yellow
}

if (-not $NoPause) {
    Write-Host ""
    Write-Host "  按回车关闭……" -ForegroundColor DarkGray
    [void](Read-Host)
}

if ($failed.Count -gt 0) { exit 1 }
exit 0
