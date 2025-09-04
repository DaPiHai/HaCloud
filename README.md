# HaCloud

轻量、自托管的本地网盘与文件管理服务，内置 Web 前端与 Windows GUI 外壳，支持系统托盘常驻、分片上传、版本管理、回收站、分享链接与审计日志等功能。

## 主要特性
- Web 前端：文件浏览、上传/下载、重命名、移动、删除、回收站、版本管理、搜索、外链分享
- 认证与管理：注册/登录、管理员审核、禁用/启用/删除用户、更改密码
- 上传下载：支持分片上传与批量下载
- 安全合规：JWT 授权、可选 HTTPS（手动证书或 AutoTLS）、操作审计日志
- Windows 图形外壳：应用窗口日志、系统托盘常驻、窗口/任务栏/文件图标
- 即插即用的数据目录：默认使用项目 data/storage，自动创建必要的元数据目录

## 快速开始（用户运行）
1. 解压发布包。
2. 双击运行 HaCloud.exe（发布版，无控制台窗口）。
3. 浏览器访问：http://localhost:8080/
4. 首次登录：管理员账户 admin / admin123（提示：密码仅在首次初始化生效，进入后请立即修改密码）。
5. 开始上传与管理文件。默认存储目录：data/storage。

提示：关闭主窗口会最小化到系统托盘，右键托盘图标可选择“打开窗口 / 打开 Web 控制台 / 退出”。

## 发布包建议内容
- HaCloud.exe（发布版可执行文件）
- config.json（可选修改配置项）
- public/（前端静态资源）
- logo.ico（窗口/托盘图标源文件）
- data/（可选，首次运行会自动创建所需目录）

不建议随发布包包含：源代码、go.mod/go.sum、*.syso、编译脚本等开发产物。

## 配置说明（config.json）
示例：
```json
{
  "server": {
    "port": "8080",
    "host": "localhost",
    "certFile": "",
    "keyFile": "",
    "autoTLS": false,
    "acmeEmail": "",
    "auditFile": ""
  },
  "admin": {
    "username": "admin",
    "password": "admin123",
    "comment": "默认管理员账号（用户名固定为 admin），密码仅在首次初始化生效"
  },
  "jwt": {
    "expiryHours": 24,
    "comment": "JWT Token 有效期（小时）"
  },
  "storage": {
    "root": "data/storage",
    "comment": "文件存储根目录，相对于程序当前工作目录"
  },
  "features": {
    "autoCleanTrash": true,
    "trashRetentionDays": 30,
    "maxUploadSize": "100MB",
    "comment": "功能开关和限制配置"
  }
}
```
- server.port：HTTP 服务端口（默认 8080）
- server.host：域名（用于日志和 AutoTLS）
- server.certFile / server.keyFile：启用手动 HTTPS 的证书与私钥路径
- server.autoTLS / server.acmeEmail：启用 Let's Encrypt 自动证书（需将 server.host DNS 指向机器公网 IP，并放通 80/443）
- server.auditFile：审计日志文件路径（若留空，将使用内部默认路径）
- admin.username：固定为 admin；admin.password 仅在首次初始化有效
- jwt.expiryHours：登录令牌有效期（小时）
- storage.root：文件存储根目录（默认 data/storage）
- features.*：回收站自动清理、保留天数、最大上传大小等

程序会自动创建并维护必要的元数据目录：
- .meta、.users、.versions、.trash、.uploads、.convert-cache 等（位于 storage.root 下）
- 审计日志 audit.log 默认写入内部元数据目录，或使用 server.auditFile 指定路径

## 系统托盘与退出
- 关闭窗口将隐藏到系统托盘，不会退出进程。
- 通过托盘菜单可以：
  - 打开窗口（显示 GUI 日志与控制）
  - 打开 Web 控制台（浏览器访问 http://localhost:8080/）
  - 退出（真正结束进程）

![系统托盘菜单示例](https://github.com/DaPiHai/HaCloud/blob/main/md_img/1.png)

## 日志
- 应用运行日志显示在 GUI 窗口的日志区域（自动滚动到底部）。
- 审计日志（操作轨迹）写入 audit.log（路径由配置决定）。
- 发布版 HaCloud.exe 使用 Windows GUI 子系统构建，不会打开控制台也不会向控制台输出。
- 若需要在控制台查看运行日志，使用调试版 HaCloud_dbg.exe 启动。

![系统托盘菜单示例](https://github.com/DaPiHai/HaCloud/blob/main/md_img/2.png)

## 本地开发与构建
前置要求：Go 1.21+

拉取依赖：
```bash
go mod tidy
```

构建调试版（带控制台输出）：
```bash
go build -tags gui -o HaCloud_dbg.exe
```

构建发布版（无控制台窗口）：
```bash
go build -tags gui -ldflags "-H=windowsgui" -o HaCloud.exe
```

文件图标（Explorer 缩略图）嵌入：本仓库已提供 rsrc_windows_amd64.syso（以及 386 版）用于将 logo.ico 嵌入可执行文件。若需重新生成：
```bash
# 64 位
rsrc -arch amd64 -ico logo.ico -o rsrc_windows_amd64.syso
# 32 位（可选）
rsrc -arch 386   -ico logo.ico -o rsrc_windows_386.syso
```
然后重新构建发布版。

![系统托盘菜单示例](https://github.com/DaPiHai/HaCloud/blob/main/md_img/3.png)

## 访问与部署要点
- 本机访问：http://localhost:8080/
- 局域网访问：将 server.host 配置为当前主机名或局域网 IP，并在防火墙放行端口。
- 公网访问：建议配置域名 + HTTPS（手动证书或 AutoTLS），并在路由器/云主机放通 80/443。
- 首次登录使用 admin/admin123，登录后请立即修改管理员密码。

![系统托盘菜单示例](https://github.com/DaPiHai/HaCloud/blob/main/md_img/4.png)
![系统托盘菜单示例](https://github.com/DaPiHai/HaCloud/blob/main/md_img/5.png)

## 常见问题（FAQ）
- 8080 端口被占用？修改 config.json 中的 server.port 或释放占用端口。
- 文件图标未更新为 logo？重建可执行文件或刷新 Windows 图标缓存（重启资源管理器或清理图标缓存）。
- 无法访问 8080？检查本机防火墙与杀软拦截，或端口是否被占用。
- AutoTLS 无法签发？确认域名解析正确、80/443 端口对外放通，server.host 与 acmeEmail 填写有效。

## 目录结构（发布包示例）
```
HaCloud/
├─ HaCloud.exe
├─ config.json
├─ public/
├─ logo.ico
└─ data/          # 可选，首次运行会自动创建内部目录
```

—— 完 ——
