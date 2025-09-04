//go:build gui
// +build gui

// GUI 窗口：实时显示日志并指示启动状态
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net"
    "net/url"
    "os"
    "path/filepath"
    "strings"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/driver/desktop"
    "fyne.io/fyne/v2/widget"
    "golang.org/x/sys/windows/registry"

)

// 列出本机所有非回环 IPv4 地址
func listIPv4() []string {
	addrs := []string{"localhost"}
	ifaces, err := net.Interfaces()
	if err != nil {
		return addrs
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		ia, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ia {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			addrs = append(addrs, ip.String())
		}
	}
	// 去重
	seen := map[string]struct{}{}
	out := make([]string, 0, len(addrs))
	for _, s := range addrs {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// 解析 config.json 路径：优先当前工作目录，其次可执行文件所在目录
func resolveConfigPath() string {
	// 1) CWD
	cwdPath := filepath.Join(".", "config.json")
	if _, err := os.Stat(cwdPath); err == nil {
		return cwdPath
	}
	// 2) EXE dir
	if exe, err := os.Executable(); err == nil {
		exePath := filepath.Join(filepath.Dir(exe), "config.json")
		return exePath
	}
	return cwdPath
}

// 保存所选主机到 config.json（仅更新 server.host）
func saveSelectedHostToConfig(newHost string) error {
	appConfig.Server.Host = newHost
	b, err := json.MarshalIndent(appConfig, "", "  ")
	if err != nil {
		return err
	}
	cfg := resolveConfigPath()
	return os.WriteFile(cfg, b, 0644)
}

// Windows 开机自启动（注册表）支持
const runKeyPath = `Software\\Microsoft\\Windows\\CurrentVersion\\Run`
const runValueName = "HaCloud"

func isAutoStartEnabled() (bool, string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, "", nil
		}
		return false, "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue(runValueName)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, "", nil
		}
		return false, "", err
	}
	if strings.TrimSpace(v) == "" {
		return false, v, nil
	}
	return true, v, nil
}

func setAutoStartEnabled(enabled bool) error {
	if enabled {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		// 引号包裹，防止路径中有空格
		val := "\"" + exe + "\""
		k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		return k.SetStringValue(runValueName, val)
	}
	// 关闭自启动：删除注册表值
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(runValueName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// 由 main 显式调用，必须在主 goroutine 执行 a.Run()
func startGUI() {
	a := app.New()

	var w fyne.Window
	var statusLabel *widget.Label
	var logView *widget.Entry
	var scroller *container.Scroll
	var buffer string
	logsCh := make(chan string, 200)
	readyCh := make(chan struct{})

	// 先创建窗口与控件，确保在进入事件循环前已有可显示的窗口
	w = a.NewWindow("HaCloud 服务")

	// 设置应用与窗口图标（任务栏与左上角），从可执行文件同目录加载 logo.ico
	// 以避免工作目录不同导致找不到资源
	var appIcon fyne.Resource
	if exePath, err := os.Executable(); err == nil {
		icoPath := filepath.Join(filepath.Dir(exePath), "logo.ico")
		if data, err := os.ReadFile(icoPath); err == nil {
			res := fyne.NewStaticResource("logo.ico", data)
			appIcon = res
			a.SetIcon(res)
			w.SetIcon(res)
		} else {
			log.Printf("[GUI] 未能读取图标 %s: %v", icoPath, err)
		}
	}

	// 计算服务访问地址（协议/主机/端口）
	host := strings.TrimSpace(appConfig.Server.Host)
	if host == "" {
		host = "localhost"
	}
	cfgPort := strings.TrimSpace(appConfig.Server.Port)
	if cfgPort == "" {
		if v := strings.TrimSpace(os.Getenv("PORT")); v != "" {
			cfgPort = v
		} else {
			cfgPort = "8080"
		}
	}
	scheme := "http"
	if (strings.TrimSpace(appConfig.Server.CertFile) != "" && strings.TrimSpace(appConfig.Server.KeyFile) != "") || (appConfig.Server.AutoTLS && host != "") {
		scheme = "https"
	}
	linkPort := cfgPort
	if appConfig.Server.AutoTLS {
		// AutoTLS 服务监听 443
		linkPort = "443"
	}

	// 地址列表（包含 localhost + 所有非回环 IPv4）
	addrOptions := listIPv4()
	// 默认选择：优先 config 中 host，其次 localhost
	selectedHost := host
	// 若配置的 host 不是 IP/localhost 且不在列表中，也允许使用它
	found := false
	for _, v := range addrOptions {
		if v == selectedHost {
			found = true
			break
		}
	}
	if !found && selectedHost != "" {
		addrOptions = append([]string{selectedHost}, addrOptions...)
	}

	// 根据当前选择构建 URL
	currentURL := func() *url.URL {
		u, _ := url.Parse(fmt.Sprintf("%s://%s:%s", scheme, selectedHost, linkPort))
		return u
	}

	// 设置系统托盘菜单与图标，拦截关闭为隐藏，实现常驻托盘
	var openWeb *fyne.MenuItem
	if desk, ok := a.(desktop.App); ok {
		openWin := fyne.NewMenuItem("打开窗口", func() {
			w.Show()
			w.RequestFocus()
		})
		openWeb = fyne.NewMenuItem("打开 Web 控制台", func() {
			_ = a.OpenURL(currentURL())
		})
		quit := fyne.NewMenuItem("退出", func() { a.Quit() })
		m := fyne.NewMenu("HaCloud", openWin, openWeb, fyne.NewMenuItemSeparator(), quit)
		desk.SetSystemTrayMenu(m)
		if appIcon != nil {
			desk.SetSystemTrayIcon(appIcon)
		}
		// 拦截关闭按钮：隐藏窗口而不是退出
		w.SetCloseIntercept(func() {
			w.Hide()
		})
	}

	statusLabel = widget.NewLabel("启动中…")
	logView = widget.NewMultiLineEntry()
	logView.Wrapping = fyne.TextWrapWord // 更易读的换行

	if buffer != "" {
		logView.SetText(buffer)
	}

	// 顶部信息：状态 + 服务地址选择（下拉）+ 可点击链接 + 复制按钮
	srvText := widget.NewLabel("服务地址：")
	var srvLink *widget.Hyperlink
	hostSelect := widget.NewSelect(addrOptions, func(s string) {
		if s == "" {
			return
		}
		selectedHost = s
		// 更新超链接文本与目标
		if srvLink != nil {
			srvLink.SetText(selectedHost + ":" + linkPort)
			srvLink.SetURL(currentURL())
		}
		// 更新托盘菜单动作
		if openWeb != nil {
			openWeb.Action = func() { _ = a.OpenURL(currentURL()) }
		}
		// 写入 config.json 记住选择
		if err := saveSelectedHostToConfig(selectedHost); err != nil {
			log.Printf("[GUI] 保存 server.host 失败: %v", err)
			statusLabel.SetText("保存失败: " + err.Error())
		} else {
			statusLabel.SetText("已保存地址到 config.json")
		}
	})
	hostSelect.PlaceHolder = selectedHost

	srvLink = widget.NewHyperlink(selectedHost+":"+linkPort, currentURL())
	copyBtn := widget.NewButton("复制地址", func() {
		u := currentURL()
		if u != nil {
			w.Clipboard().SetContent(u.String())
			statusLabel.SetText("已复制: " + u.String())
		}
	})

	// 开机自启动复选框
	autoOn, _, err := isAutoStartEnabled()
	if err != nil {
		log.Printf("[GUI] 读取开机自启状态失败: %v", err)
	}
	initializingAuto := true
	var autoStartCheck *widget.Check
	autoStartCheck = widget.NewCheck("开机自启动", func(v bool) {
		if initializingAuto {
			return
		}
		if err := setAutoStartEnabled(v); err != nil {
			statusLabel.SetText("开机自启设置失败: " + err.Error())
			// 回退 UI 状态
			initializingAuto = true
			autoStartCheck.SetChecked(!v)
			initializingAuto = false
		} else {
			if v {
				statusLabel.SetText("已启用开机自启动")
			} else {
				statusLabel.SetText("已禁用开机自启动")
			}
		}
	})
	autoStartCheck.SetChecked(autoOn)
	initializingAuto = false

	topBar := container.NewVBox(
		statusLabel,
		container.NewHBox(srvText, hostSelect, srvLink, copyBtn),
		container.NewHBox(autoStartCheck),
	)

	// 使用滚动容器承载日志，并作为中心内容填充剩余空间
	scroller = container.NewVScroll(logView)
	w.SetContent(container.NewBorder(topBar, nil, nil, nil, scroller))
	w.Resize(fyne.NewSize(800, 560))

	// 记录窗口关闭事件，便于定位 GUI 消失原因
	w.SetOnClosed(func() {
		log.Println("[GUI] 主窗口已关闭")
	})

	// 运行时启动回调：仅负责切换状态与标记就绪
	a.Lifecycle().SetOnStarted(func() {
		statusLabel.SetText("运行中")
		close(readyCh)
	})

	w.Show()

	// 管道转接日志输出（先启动读取，再切换输出，避免阻塞）
	pr, pw := io.Pipe()

	// 读取日志：写入 channel，错误则关闭 channel
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				txt := string(buf[:n])
				select {
				case logsCh <- txt:
				default:
					// 若通道已满，退化为直接累加避免阻塞
					buffer += txt
				}
			}
			if err != nil {
				close(logsCh)
				return
			}
		}
	}()

	// 切换日志输出到管道（不再写入 stderr，避免控制台输出）
	log.SetOutput(pw)
	// 首条日志单独放在 goroutine，避免在极端情况下阻塞主线程
	go func() {
		log.Printf("[GUI] HaCloud GUI 已启动，日志输出已连接\n")
	}()

	// UI 更新器：在 UI 未就绪时先缓冲，UI 就绪后在主线程追加
	go func() {
		uiReady := false
		for txt := range logsCh {
			if !uiReady {
				select {
				case <-readyCh:
					uiReady = true
				default:
				}
			}
			if !uiReady {
				buffer += txt
				continue
			}
			fyne.Do(func() {
				logView.SetText(logView.Text + txt)
				statusLabel.SetText("运行中")
				if scroller != nil {
					scroller.ScrollToBottom()
				}
			})
		}
	}()

	// 进入 Fyne 事件循环（必须在主 goroutine 调用）
	a.Run()

	// 事件循环结束时记录日志，帮助定位非正常退出
	log.Println("[GUI] GUI 事件循环已退出")
}
