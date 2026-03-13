import os
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import sys

class NetworkTrafficGUI:

    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("网络流量分析与异常检测系统")
        self.process: subprocess.Popen | None = None
        self.is_running = False

        BG, BTN, BTN_H = "#f5f5f5", "#4a7abc", "#3a5a8c"
        self.master.configure(bg=BG)
        self.master.option_add("*Font", ("Microsoft YaHei", 10))

        #顶部按钮区
        top = tk.Frame(master, bg=BG)
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(8, 4))

        BUTTONS = [
            ("读取数据并构建图", "1", "请输入文件路径，可选CSV或pcap类型"),
            ("展示子图",       "2", "输入IP地址，可视化该节点所在连通子图"),
            ("节点流量排序",   "3", "输入TOP N数量（0=全部）"),
            ("HTTPS节点排序",  "4", "输入TOP N数量（0=全部）"),
            ("单向流量节点",   "5", "先输入阈值（默认0.8），再输入TOP N"),
            ("路径查找与对比", "6", "依次输入源IP和目标IP"),
            ("星型拓扑检测",   "7", "自动检测，无需额外输入"),
            ("安全规则检查",   "8", "依次输入源IP、IP范围起始、结束、动作（1=DENY/0=ALLOW）"),
            ("退出系统",       "0", "退出C程序"),
        ]

        btn_frame = tk.Frame(top, bg=BG)
        btn_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for i, (text, cmd, tip) in enumerate(BUTTONS):
            wrap = tk.Frame(btn_frame, relief=tk.RAISED, bd=1, bg=BTN)
            wrap.grid(row=i // 4, column=i % 4, padx=2, pady=2, sticky='ew')
            b = tk.Button(wrap, text=text, width=16, bg=BTN, fg="white",
                          relief=tk.FLAT, activebackground=BTN_H, activeforeground="white",
                          command=lambda c=cmd, t=tip: self._send_choice(c, t))
            b.pack(fill=tk.BOTH, expand=True)
            b.bind("<Enter>", lambda e, t=tip: self._set_tip(f"提示：{t}"))
            b.bind("<Leave>", lambda e: self._set_tip("就绪：请点击上方按钮选择操作"))
        for j in range(4):
            btn_frame.columnconfigure(j, weight=1)

        tip_frame = tk.Frame(top, bg=BG, width=400, height=60)
        tip_frame.pack_propagate(False)
        tip_frame.pack(side=tk.RIGHT, padx=20)
        self.tip_text = tk.Text(tip_frame, wrap=tk.WORD, state=tk.DISABLED,
                                width=50, height=3, font=("Microsoft YaHei", 9, "bold"),
                                bg=BG, fg="#2c5aa0", relief=tk.FLAT, padx=5, pady=5)
        self.tip_text.pack(fill=tk.BOTH, expand=True)
        self._set_tip("就绪：请点击上方按钮选择操作")

        #中部输出区
        mid = tk.Frame(master, bg=BG)
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.output = scrolledtext.ScrolledText(
            mid, wrap=tk.WORD, state=tk.DISABLED, width=120, height=35,
            font=("Consolas", 10), bg="#ffffff", fg="#333333",
            relief=tk.SUNKEN, bd=1, padx=10, pady=10)
        self.output.pack(fill=tk.BOTH, expand=True)

        #底部输入区
        bot = tk.Frame(master, bg=BG)
        bot.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(4, 8))
        tk.Label(bot, text="用户输入：", bg=BG).pack(side=tk.LEFT)
        self.input_var = tk.StringVar()
        self.entry = tk.Entry(bot, textvariable=self.input_var,
                              font=("Consolas", 10), relief=tk.SUNKEN, bd=1)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry.bind("<Return>", self.send_text)
        self.entry.focus_set()

        for text, cmd, color in [("发送(Enter)", self.send_text,   "#4CAF50"),
                                  ("重启C程序",   self.start_c,     "#FF9800"),
                                  ("清空输出",    self.clear_output, "#f44336")]:
            tk.Button(bot, text=text, command=cmd, bg=color, fg="white",
                      relief=tk.FLAT).pack(side=tk.LEFT, padx=2)

        self.start_c()

    #提示文本
    def _set_tip(self, text):
        self.tip_text.configure(state=tk.NORMAL)
        self.tip_text.delete(1.0, tk.END)
        self.tip_text.insert(tk.END, text)
        self.tip_text.configure(state=tk.DISABLED)

    #C程序进程管理
    def start_c(self):
        """启动/重启 ntas.exe"""
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self._log("[INFO] 已终止原有C程序进程\n")
            except Exception as e:
                self._log(f"[ERROR] 终止进程失败：{e}\n")

        exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntas.exe")
        if not os.path.exists(exe):
            messagebox.showerror("错误", f"未找到：ntas.exe\n请先编译：g++ -std=c++17 -O2 -o ntas src/*.cpp -Iinclude")
            self.is_running = False
            return

        try:
            self.process = subprocess.Popen(
                [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                errors='replace', bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW)
            self.is_running = True
            self._log(f"[SUCCESS] 启动C程序：{exe}\n")
            self._set_tip("C程序已启动：请选择上方操作按钮")
            threading.Thread(target=self._read_loop, daemon=True).start()
        except Exception as e:
            messagebox.showerror("错误", f"启动失败：{e}")
            self.is_running = False

    def _read_loop(self):
        """持续读取C程序输出（逐字符，确保实时）"""
        buf = ""
        while self.is_running and self.process.poll() is None:
            try:
                ch = self.process.stdout.read(1)
                if not ch:
                    break
                buf += ch
                if ch == '\n':
                    line = buf.rstrip()
                    if line.startswith("SUBGRAPH_READY:"):
                        ip = line.split(":", 1)[1].strip()
                        self._log("[INFO] 子图数据已导出，正在启动可视化...\n")
                        self.master.after(300, lambda i=ip: self._launch_vis(i))
                    else:
                        self._log(line + '\n')
                    buf = ""
            except Exception as e:
                self._log(f"[ERROR] 读取失败：{e}\n")
                break
        if buf:
            self._log(buf.rstrip() + '\n')
        self.is_running = False
        self._log("\n[INFO] C程序已退出，请点击【重启C程序】重新启动\n")
        self._set_tip("C程序已退出：请重启后再操作")

    #可视化子图
    def _launch_vis(self, query_ip: str):
        """在后台线程中调用 visualize_subgraph.py"""
        d = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(d, "visualize_subgraph.py")
        json_f = os.path.join(d, "subgraph_data.json")
        for path, label in [(script, "可视化脚本"), (json_f, "子图数据文件")]:
            if not os.path.exists(path):
                self._log(f"[ERROR] 找不到{label}：{path}\n"); return

        def run():
            try:
                r = subprocess.run([sys.executable, script, json_f],
                                   capture_output=True, text=True,
                                   encoding='utf-8', timeout=30)
                if r.returncode == 0:
                    self._log(f"[SUCCESS] 子图可视化已在浏览器打开（查询节点：{query_ip}）\n")
                else:
                    self._log(f"[ERROR] 可视化出错：{r.stderr}\n")
            except Exception as e:
                self._log(f"[ERROR] 启动可视化失败：{e}\n")

        threading.Thread(target=run, daemon=True).start()

    #输出/输入
    def _log(self, text: str):
        """线程安全地追加文本到输出区"""
        def _do():
            self.output.configure(state=tk.NORMAL)
            self.output.insert(tk.END, text)
            self.output.see(tk.END)
            self.output.configure(state=tk.DISABLED)
        self.master.after(0, _do)

    def clear_output(self):
        self.output.configure(state=tk.NORMAL)
        self.output.delete(1.0, tk.END)
        self.output.configure(state=tk.DISABLED)

    def _send(self, text: str) -> bool:
        """向C程序stdin写一行，返回是否成功"""
        if not self.is_running or self.process.poll() is not None:
            messagebox.showwarning("提示", "C程序未运行，请先点击【重启C程序】")
            return False
        try:
            self.process.stdin.write(text + "\n")
            self.process.stdin.flush()
            return True
        except Exception as e:
            messagebox.showerror("错误", f"发送失败：{e}")
            self.is_running = False
            return False

    def _send_choice(self, choice: str, tip: str):
        """按钮点击：发送菜单序号"""
        if self._send(choice):
            self._log(f"\n[用户操作] {choice} → {tip}\n")
            self._set_tip(f"当前操作：{tip}（请在下方输入框填写）")
            self.entry.focus_set()

    def send_text(self, event=None):
        """发送输入框内容；若内容是 pcap/pcapng 路径则先转换为 csv 再发送"""
        text = self.input_var.get().strip()
        if not text:
            return
        if text.lower().endswith(('.pcap', '.pcapng')):
            self.input_var.set("")
            threading.Thread(target=self._convert_and_send, args=(text,), daemon=True).start()
            return
        if self._send(text):
            self._log(f"> 你输入：{text}\n")
            self.input_var.set("")

    def _convert_and_send(self, pcap_path: str):
        """后台线程：调用 pcap_to_csv.py 转换，完成后自动把 csv 路径发给 C 程序"""
        d = os.path.dirname(os.path.abspath(__file__))
        base = os.path.splitext(os.path.basename(pcap_path))[0]
        csv_path = os.path.join(d, "data", f"{base}.csv")
        os.makedirs(os.path.join(d, "data"), exist_ok=True)
        self._log(f"[INFO] 检测到 pcap 文件，正在转换 → {csv_path}\n")
        try:
            r = subprocess.run([sys.executable, os.path.join(d, "pcap_to_csv.py"), pcap_path, csv_path],
                               capture_output=True, text=True, encoding="utf-8", timeout=60)
            if r.returncode != 0:
                self._log(f"[ERROR] 转换失败：{r.stderr}\n"); return
            self._log(f"[SUCCESS] 转换完成，自动加载：{csv_path}\n")
        except Exception as e:
            self._log(f"[ERROR] 转换异常：{e}\n"); return
        if self._send(csv_path):
            self._log(f"> 自动发送路径：{csv_path}\n")

def main():
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    root = tk.Tk()
    root.geometry("1200x800")
    root.minsize(1000, 600)
    NetworkTrafficGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()