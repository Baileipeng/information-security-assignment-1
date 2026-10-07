# 第 4 关演示视频

| 文件 | 说明 |
|------|------|
| `关卡4_暴力破解演示.mp4` | 完整演示，14 秒，331 KB，含阶段字幕与时间戳 |
| `关卡4_暴力破解演示.gif` | 同内容动图，525 KB，**GitHub 页面内可直接播放** |

## 怎么在 GitHub 上观看 MP4

GitHub 的仓库文件页对 `.mp4` **不提供播放器**：点开文件只有 `Download` 和 `Raw` 两个按钮，
而且 `raw.githubusercontent.com` 返回的响应头是

```
Content-Type: application/octet-stream
```

浏览器看到这个类型只会**下载**，不会播放（已用 `curl -I` 实测）。所以想直接看，用下面任一方式：

### 1. 在线播放（推荐）

打开下面任意一个链接，浏览器里点开即播，可拖动进度：

```
https://cdn.jsdelivr.net/gh/Baileipeng/information-security-assignment-1@main/video/关卡4_暴力破解演示.mp4
```

备用镜像（路径相同，只换域名）：`gcore.jsdelivr.net`、`testingcf.jsdelivr.net`。
三者实测均返回 `Content-Type: video/mp4`。

> 中文文件名的百分号编码形式：
> `https://cdn.jsdelivr.net/gh/Baileipeng/information-security-assignment-1@main/video/%E5%85%B3%E5%8D%A14_%E6%9A%B4%E5%8A%9B%E7%A0%B4%E8%A7%A3%E6%BC%94%E7%A4%BA.mp4`

### 2. 下载到本地播放

在本页点开 `关卡4_暴力破解演示.mp4` → 点右上角 **Download**，用本地播放器打开（文件仅 331 KB）。

### 3. 让 README 里出现原生播放器

1. 新建一个 Issue（或任意 PR 评论），把 mp4 文件**拖进评论输入框**上传；
2. GitHub 会返回形如 `https://github.com/user-attachments/assets/<uuid>` 的链接；
3. 把该链接**单独占一行**贴进 README —— GitHub 会渲染成内嵌播放器。

只有 `user-attachments` 形式的链接会触发播放器渲染；仓库内相对路径、Release 附件 URL
都只会显示为普通下载链接。

### 4. 只想"看到画面动"

直接用 `关卡4_暴力破解演示.gif`：GIF 是仓库内唯一能被 GitHub 渲染成动画的视频格式，
在 README 里写 `![演示](video/关卡4_暴力破解演示.gif)` 即可在本页自动循环播放。

## 复现录制与合成

```bash
# 1) 录屏：GUI 自动演示第 4 关（单次破解 + 压力测试），按帧落盘到 frames/
sdes_gui --record frames

# 2) 合成：叠加阶段字幕与时间戳 -> MP4 + GIF
python tools/make_video.py "<仓库根目录的绝对路径>/frames"
```

依赖 `Pillow` 与 `imageio-ffmpeg`（`pip install pillow imageio-ffmpeg`）。
