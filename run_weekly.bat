@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

rem ============================================================
rem  公网暴露面巡检 · 一键执行(无界面, 供 Windows 任务计划程序调用)
rem  用法:  run_weekly.bat [all^|common^|web] [nopause]
rem  默认:  all 模式(全量 65535 端口), 扫描完成后发送邮件
rem
rem  说明:  日常手动跑建议双击「启动控制台.bat」用图形界面;
rem         本脚本是给定时任务/无人值守用的, 没有界面。
rem         两者共用同一套引擎、报告与基线, 结果完全互通。
rem ============================================================

if not defined PYEXE (
    where python >nul 2>nul && set "PYEXE=python"
)
if not defined PYEXE (
    where py >nul 2>nul && set "PYEXE=py"
)
if not defined PYEXE (
    echo.
    echo   [!] 未找到 Python。请先安装 Python 3.8 以上版本。
    echo.
    pause
    exit /b 1
)

set "MODE=%~1"
if "%MODE%"=="" set "MODE=all"

echo ============================================================
echo   Public Exposure Scan   mode=%MODE%
echo   python: %PYEXE%
echo   start : %date% %time%
echo ============================================================

"%PYEXE%" scanner.py --mode %MODE% --mail
set "RC=%ERRORLEVEL%"

echo.
echo ------------------------------------------------------------
echo   finished: %date% %time%   exit code = %RC%
echo   (0=无变化  2=发现新增端口  3=邮件发送失败  130=被中断)
echo ------------------------------------------------------------

if /i not "%~2"=="nopause" pause
exit /b %RC%
