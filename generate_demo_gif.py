"""Renders assets/demo.gif from the REAL output of demo.py (so the GIF can never drift from the product)."""
import os, subprocess, sys
from PIL import Image, ImageDraw, ImageFont

W, H, FS, LH = 900, 560, 15, 20
BG, BAR, DIM, FG = (15, 23, 42), (30, 41, 59), (148, 163, 184), (226, 232, 240)
RED, GRN, AMB, CYN = (248, 113, 113), (74, 222, 128), (251, 191, 36), (56, 189, 248)
FONTS = ["C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc"]

def color(line):
    if "TAMPERED" in line or "Blocked" in line: return RED
    if "intact" in line: return GRN
    if "withheld" in line or "removed" in line: return AMB
    if line.startswith("["): return CYN
    return FG

def main(out="assets/demo.gif"):
    here = os.path.dirname(os.path.abspath(__file__))
    text = subprocess.run([sys.executable, os.path.join(here, "demo.py")], capture_output=True, text=True, cwd=here).stdout.splitlines()
    font = next((ImageFont.truetype(f, FS) for f in FONTS if os.path.exists(f)), ImageFont.load_default())
    os.makedirs(os.path.join(here, os.path.dirname(out)), exist_ok=True)
    frames, durs, shown = [], [], []
    def frame(typed=None):
        im = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(im)
        d.rectangle([0, 0, W, 34], fill=BAR)
        for i, c in enumerate([(239, 68, 68), (245, 158, 11), (16, 185, 129)]): d.ellipse([14 + i * 22, 11, 26 + i * 22, 23], fill=c)
        d.text((W // 2 - 60, 9), "sealwall demo", font=font, fill=DIM)
        y = 48
        d.text((20, y), "$ " + (typed if typed is not None else "python demo.py"), font=font, fill=FG); y += LH + 4
        for l in shown[-(H - 90) // LH:]:
            d.text((20, y), l, font=font, fill=color(l)); y += LH
        return im
    for n in range(0, len("python demo.py") + 1, 3):
        frames.append(frame("python demo.py"[:n])); durs.append(60)
    for l in text:
        shown.append(l); frames.append(frame()); durs.append(700 if l.startswith("[") else 450 if l.strip() else 150)
    durs[-1] = 4000
    frames[0].save(os.path.join(here, out), save_all=True, append_images=frames[1:], duration=durs, loop=0, optimize=True)
    print(f"wrote {out} ({len(frames)} frames)")

if __name__ == "__main__": main()
