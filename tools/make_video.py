# -*- coding: utf-8 -*-
"""把 --record 模式抓取的帧合成为第 4 关暴力破解演示视频 (MP4) 与动图 (GIF)。

流程:
  1. 读取 frames/frame_*.jpg
  2. 逐帧叠加阶段字幕与时间戳（Pillow 绘制）
  3. ffmpeg (imageio-ffmpeg 自带) 合成 MP4 (H.264, yuv420p)
  4. Pillow 抽帧缩放合成 GIF 预览

用法: python make_video.py [frames_dir]
"""
import glob
import math
import os
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(os.path.dirname(HERE))  # 项目根目录（tools/ 的上一级）

FRAMES_DIR = sys.argv[1] if len(sys.argv) > 1 else "frames"
RECORD_SECONDS = 14.3          # --record 流程总时长（schedule 最后一步 quit）
OUT_MP4 = os.path.join("video", "关卡4_暴力破解演示.mp4")
OUT_GIF = os.path.join("video", "关卡4_暴力破解演示.gif")
TMP_ANNO = "frames_annotated"

# 阶段字幕（按帧时间切换）
PHASES = [
    (0.0,  2.0,  "第 4 关 暴力破解 | 输入两组已知明密文对"),
    (2.0,  6.0,  "阶段 1：单次暴力破解 - 24 线程并行遍历 1024 个密钥（约 10 ms 完成）"),
    (6.0,  9.2,  "阶段 2：压力测试 - 连续遍历密钥空间 1,000,000 次（共 10.24 亿次加密）"),
    (9.2, 99.0,  "完成：100 万次全空间遍历仅 2.8 s，吞吐 363 M 次加密/秒，并发加速 19.6x"),
]

FONT_PATH = r"C:\Windows\Fonts\msyh.ttc"


def main():
    frame_files = sorted(glob.glob(os.path.join(FRAMES_DIR, "frame_*.jpg")))
    if not frame_files:
        print("未找到帧文件:", FRAMES_DIR)
        sys.exit(1)
    n = len(frame_files)
    fps = n / RECORD_SECONDS          # 实际平均帧率
    print(f"帧数 {n}, 实际帧率 {fps:.2f} fps, 时长 {RECORD_SECONDS:.1f} s")

    os.makedirs(TMP_ANNO, exist_ok=True)
    font = ImageFont.truetype(FONT_PATH, 24)
    small_font = ImageFont.truetype(FONT_PATH, 18)

    for i, path in enumerate(frame_files):
        img = Image.open(path).convert("RGB")
        w, h = img.size
        t = (i + 1) / fps  # 该帧的大致时间戳

        # 顶部字幕条（半透明）
        overlay = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        phase = next((text for (t0, t1, text) in PHASES if t0 <= t < t1), "")
        if phase:
            tw = od.textlength(phase, font=font)
            od.rounded_rectangle([8, 8, tw + 28, 46], radius=8, fill=(15, 40, 80, 200))
            od.text((22, 13), phase, font=font, fill=(255, 255, 255, 255))
        # 右上角时间戳
        ts = f"t = {t:5.2f} s"
        od.rounded_rectangle([w - 118, 8, w - 8, 36], radius=6, fill=(15, 40, 80, 170))
        od.text((w - 108, 11), ts, font=small_font, fill=(255, 255, 255, 255))
        img = Image.alpha_composite(img.convert("RGBA"), overlay).convert("RGB")

        # MP4 要求宽高为偶数
        if w % 2 or h % 2:
            img = img.crop((0, 0, w - w % 2, h - h % 2))
        img.save(os.path.join(TMP_ANNO, f"anno_{i:05d}.png"))
    print("字幕叠加完成")

    # ---- 合成 MP4 ----
    import imageio_ffmpeg
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    os.makedirs("video", exist_ok=True)
    cmd = [
        ffmpeg, "-y",
        "-framerate", f"{fps:.3f}",
        "-i", os.path.join(TMP_ANNO, "anno_%05d.png"),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "22",
        "-movflags", "+faststart",
        OUT_MP4,
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    print("MP4 完成:", OUT_MP4, f"({os.path.getsize(OUT_MP4)/1e6:.2f} MB)")

    # ---- 合成 GIF（抽帧一半 + 缩放，控制体积） ----
    gif_frames = []
    step = 2  # 每隔一帧取一帧 -> 约 fps/2
    target_w = 720
    for i in range(0, n, step):
        im = Image.open(os.path.join(TMP_ANNO, f"anno_{i:05d}.png"))
        ratio = target_w / im.width
        im = im.resize((target_w, int(im.height * ratio)), Image.LANCZOS)
        gif_frames.append(im.quantize(colors=128, method=Image.MEDIANCUT))
    duration = int(round(1000 * step / fps))
    gif_frames[0].save(
        OUT_GIF, save_all=True, append_images=gif_frames[1:],
        duration=duration, loop=0, optimize=True,
    )
    print("GIF 完成:", OUT_GIF, f"({os.path.getsize(OUT_GIF)/1e6:.2f} MB, {len(gif_frames)} 帧)")

    shutil.rmtree(TMP_ANNO, ignore_errors=True)
    print("全部完成")


if __name__ == "__main__":
    main()
