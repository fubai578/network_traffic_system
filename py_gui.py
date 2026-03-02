import os
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

class NetworkTrafficGUI:

    def __init__(self, master: tk.Tk):
        self.master = master
        self.master.title("网络流量分析与异常检测系统")
        self.process: subprocess.Popen | None = None

        top_frame = tk.Frame(master)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(8, 4))

        buttons = [
            ("读取CSV并构建图", "1"),
            ("展示图结构", "2"),
            ("节点流量排序", "3"),
            ("HTTPS节点排序", "4"),
            ("单向流量节点", "5"),
            ("路径查找与对比", "6"),
            ("星型拓扑检测", "7"),
            ("安全规则检查", "8"),
            ("退出系统", "0"),
        ]

        for text, cmd in buttons:
            b = tk.Button(
                top_frame,
                text=text,
                width=16,
                command=lambda c=cmd: self.send_menu_choice(c),
            )
            b.pack(side=tk.LEFT, padx=2, pady=2)

        #中部：输出区
        middle_frame = tk.Frame(master)
        middle_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=4)

        self.output = scrolledtext.ScrolledText(
            middle_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            width=100,
            height=30,
        )
        self.output.pack(fill=tk.BOTH, expand=True)

        #底部：输入区
        bottom_frame = tk.Frame(master)
        bottom_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(4, 8))

        label = tk.Label(bottom_frame, text="用户输入：")
        label.pack(side=tk.LEFT)

        self.input_var = tk.StringVar()
        self.entry = tk.Entry(bottom_frame, textvariable=self.input_var)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry.bind("<Return>", self.send_text)

        send_btn = tk.Button(bottom_frame, text="发送(Enter)", command=self.send_text)
        send_btn.pack(side=tk.LEFT, padx=4)

        restart_btn = tk.Button(
            bottom_frame, text="重启 C 程序", command=self.start_c_program
        )
        restart_btn.pack(side=tk.LEFT)

        # 启动 C 程序
        self.start_c_program()

    # ============ C 程序进程管理 ============
    def start_c_program(self):
        """启动或重启 C 可执行程序ntas.exe。"""
        # 若已有进程，先终止
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

        exe_name = "ntas.exe"
        exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), exe_name)

        if not os.path.exists(exe_path):
            messagebox.showerror(
                "错误",
                f"未找到 C 可执行文件：{exe_name}\n"
                f"请先在本目录下编译生成 {exe_name}\n"
                f"例如：g++ -std=c++17 -O2 -o ntas src/*.cpp -Iinclude",
            )
            return

        try:
            self.process = subprocess.Popen(
                [exe_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            messagebox.showerror("错误", f"启动 C 程序失败：\n{e}")
            return

        self._append_output("已启动 C 主程序 ntas.exe。\n")

        # 后台线程持续读取 stdout
        t = threading.Thread(target=self._read_stdout_loop, daemon=True)
        t.start()

    def _read_stdout_loop(self):
        """持续读取 C 程序的标准输出，并追加到输出区。"""
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            self._append_output(line)
        self._append_output("\n[C 程序已退出]\n")

    #交互
    def _append_output(self, text: str):
        """线程安全地向输出区域追加文本。"""

        def inner():
            self.output.configure(state=tk.NORMAL)
            self.output.insert(tk.END, text)
            self.output.see(tk.END)
            self.output.configure(state=tk.DISABLED)

        self.master.after(0, inner)

    def send_menu_choice(self, choice: str):
        """点击顶部按钮时，发送对应菜单数字到 C 程序。"""
        if not self.process or self.process.poll() is not None:
            messagebox.showwarning("提示", "C 程序未运行，请先点击“重启 C 程序”。")
            return
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(choice + "\n")
            self.process.stdin.flush()
            self._append_output(f">>> 菜单选择: {choice}\n")
        except Exception as e:
            messagebox.showerror("错误", f"发送菜单选项失败：\n{e}")

    def send_text(self, event=None):
        """底部输入框发送任意一行文本到 C 程序（处理如 CSV 路径、IP 地址等）。"""
        text = self.input_var.get()
        if not text:
            return
        if not self.process or self.process.poll() is not None:
            messagebox.showwarning("提示", "C 程序未运行，请先点击“重启 C 程序”。")
            return
        try:
            assert self.process.stdin is not None
            self.process.stdin.write(text + "\n")
            self.process.stdin.flush()
            self._append_output(f">>> 输入: {text}\n")
            self.input_var.set("")
        except Exception as e:
            messagebox.showerror("错误", f"发送输入失败：\n{e}")

def main():
    root = tk.Tk()
    app = NetworkTrafficGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()