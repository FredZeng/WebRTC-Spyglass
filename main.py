import os
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import Toplevel, Radiobutton, IntVar, Button, Label
from tkinter import messagebox
import datetime

from rtp_scapy import replace_rtp_payloads


class WebRTCSpyglassApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('WebRTC-Spyglass')
        self.root.geometry('300x150')
        self.tshark_process = None
        self.session_dir = None
        self.start_button = tk.Button(self.root, text='开始', command=self.on_start)
        self.start_button.pack(pady=20)
        self.end_button = tk.Button(self.root, text='结束', state=tk.DISABLED, command=self.on_end)
        self.end_button.pack(pady=10)

    def find_chrome_path(self):
        if sys.platform == 'darwin':
            paths = [
                '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                os.path.expanduser('~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
            ]
            for path in paths:
                if os.path.exists(path):
                    return path
            chrome_path = shutil.which('google-chrome') or shutil.which('chrome')
            if chrome_path:
                return chrome_path
        elif sys.platform == 'win32':
            paths = [
                os.path.join(os.environ.get('PROGRAMW6432', ''), 'Google/Chrome/Application/chrome.exe'),
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Google/Chrome/Application/chrome.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Google/Chrome/Application/chrome.exe'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google/Chrome/Application/chrome.exe')
            ]
            for path in paths:
                if os.path.exists(path):
                    return path
            chrome_path = shutil.which('chrome')
            if chrome_path:
                return chrome_path
        return None

    def find_tshark_path(self):
        tshark_path = shutil.which('tshark')
        if tshark_path:
            return tshark_path
        if sys.platform == 'win32':
            possible = [
                os.path.join(os.environ.get('PROGRAMW6432', ''), 'Wireshark/tshark.exe'),
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Wireshark/tshark.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Wireshark/tshark.exe')
            ]
            for path in possible:
                if os.path.exists(path):
                    return path
        if sys.platform == 'darwin':
            possible = [
                '/usr/local/bin/tshark',
                '/opt/homebrew/bin/tshark',
                '/Applications/Wireshark.app/Contents/MacOS/tshark',
            ]
            for path in possible:
                if os.path.exists(path):
                    return path
        return None

    def kill_chrome_processes(self):
        try:
            print('尝试关闭 Chrome 进程...')
            if sys.platform == 'darwin':
                subprocess.run(['pkill', '-f', 'Google Chrome'], check=False)
            elif sys.platform == 'win32' and self.is_chrome_running_windows():
                subprocess.run(['taskkill', '/F', '/IM', 'chrome.exe'], check=False)

            print('Chrome 进程已关闭')
        except Exception as e:
            print(f'关闭 Chrome 进程时出错: {e}')

    def start_chrome_process(self, chrome_path):
        if chrome_path:
            try:
                subprocess.Popen(
                    [chrome_path, '--enable-logging',
                     '--vmodule=*/ui/*=-3,*/blink/*=-3,*/trees/*=-3,*/content_settings/*=-3,*/enterprise/*=-3,*/component_updater/*=-3,*/webrtc/*=5',
                     '-v=3', '--force-fieldtrials=WebRTC-Debugging-RtpDump/Enabled/',
                     '--no-sandbox'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print('已启动 Chrome 浏览器')
                return True
            except Exception as e:
                print(f'启动 Chrome 浏览器失败: {e}')
                return False
        else:
            print('未找到 Chrome 可执行文件，无法启动 Chrome 浏览器')
            return False

    def list_tshark_interfaces(self, tshark_path):
        try:
            if not tshark_path:
                return []
            result = subprocess.run([tshark_path, '-D'], capture_output=True, text=True, encoding='utf-8')
            interfaces = []
            for line in result.stdout.splitlines():
                if line.strip():
                    idx, rest = line.split('.', 1)
                    interfaces.append(line.strip())
            return interfaces
        except Exception as e:
            print(f'获取 tshark 网卡列表失败: {e}')
            return []

    def ask_interface(self, interfaces):
        if not interfaces or len(interfaces) == 0:
            messagebox.showerror('错误', '未检测到可用的抓包网卡接口')
            return None
        selected = {'value': None}

        def on_ok():
            idx = var.get()
            if 0 <= idx < len(interfaces):
                selected['value'] = interfaces[idx]
            top.destroy()

        top = Toplevel(self.root)
        top.title('选择抓包网卡')
        Label(top, text='请选择要抓包的接口:').pack(anchor='w', padx=10, pady=5)
        var = IntVar(value=0)
        for i, iface in enumerate(interfaces):
            Radiobutton(top, text=iface, variable=var, value=i).pack(anchor='w', padx=20)
        Button(top, text='确定', command=on_ok).pack(pady=10)
        top.grab_set()
        self.root.wait_window(top)
        return selected['value']

    def start_tshark_capture(self, tshark_path, interface):
        if not tshark_path or not interface:
            return None
        try:
            now = datetime.datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
            desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
            self.session_dir = save_dir = os.path.join(desktop, now)
            os.makedirs(save_dir, exist_ok=True)
            pcap_path = os.path.join(save_dir, 'capture.pcap')
            proc = subprocess.Popen([tshark_path, '-i', interface.split('.')[0], '-w', pcap_path],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f'tshark 已启动，抓包接口: {interface}，文件保存于: {pcap_path}')
            return proc
        except Exception as e:
            print(f'tshark 启动失败: {e}')
            return None

    def find_chrome_debug_log(self):
        log_path = None
        if sys.platform == 'darwin':
            log_path = os.path.expanduser('~/Library/Application Support/Google/Chrome/chrome_debug.log')
        elif sys.platform == 'win32':
            log_path = os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google/Chrome/User Data', 'chrome_debug.log')
        if log_path and os.path.exists(log_path):
            return log_path
        return None

    def on_start(self):
        self.start_button.config(state=tk.DISABLED)
        self.end_button.config(state=tk.NORMAL)
        chrome_path = self.find_chrome_path()
        tshark_path = self.find_tshark_path()
        msg = f"Chrome 路径: {chrome_path if chrome_path else '未找到'}\nTshark 路径: {tshark_path if tshark_path else '未找到'}"
        print(msg)
        self.kill_chrome_processes()
        interfaces = self.list_tshark_interfaces(tshark_path)
        interface = self.ask_interface(interfaces)
        print(f'选择的抓包接口: {interface if interface else "未选择"}')
        if not self.start_chrome_process(chrome_path):
            self.on_end()
            return
        if not interface:
            self.on_end()
            return
        self.tshark_process = self.start_tshark_capture(tshark_path, interface)

    def on_end(self):
        self.end_button.config(state=tk.DISABLED, text='处理中...')
        self.start_button.config(state=tk.DISABLED)
        self.root.update()

        self.kill_chrome_processes()
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process.wait(timeout=5)
                print('tshark 已停止')
            except subprocess.TimeoutExpired:
                print('tshark 停止超时，强制终止')
                self.tshark_process.kill()
            except Exception as e:
                print(f'停止 tshark 时出错: {e}')
        if self.session_dir:
            log_path = self.find_chrome_debug_log()
            if log_path:
                try:
                    shutil.copy(log_path, self.session_dir)
                    print(f'已将 Chrome 调试日志复制到: {self.session_dir}')

                    print('正在提取 RTP Dump...')
                    self.grep_rtp_dump(os.path.join(self.session_dir, 'chrome_debug.log'))

                    print('正在处理 RTP Dump...')
                    self.convert_text_to_pcap(os.path.join(self.session_dir, 'rtp-dump.txt'))

                    print('正在合并 rtp-dump.pcap 到 capture.pcap...')
                    replace_rtp_payloads(os.path.join(self.session_dir, 'capture.pcap'),
                                         os.path.join(self.session_dir, 'rtp-dump.pcap'), self.session_dir)

                    print('处理完成，所有文件已保存到:', self.session_dir)
                except Exception as e:
                    print(f'复制 Chrome 调试日志失败: {e}')
            else:
                print('未找到 Chrome 调试日志文件')
                pass
            pass

        self.end_button.config(state=tk.DISABLED, text='结束')
        self.start_button.config(state=tk.NORMAL)
        self.root.update()

    def grep_rtp_dump(self, log_path):
        with open(log_path, 'r', encoding='utf-8') as f:
            with open(os.path.join(self.session_dir, 'rtp-dump.txt'), 'w', encoding='utf-8') as out_f:
                for line in f:
                    if 'RTP_DUMP' in line:
                        out_f.write(line)
            pass
        pass

    def convert_text_to_pcap(self, text_path):
        if not os.path.exists(text_path):
            print(f'未找到 RTP Dump 文本文件: {text_path}')
            return

        text2pcap_path = self.find_text2pcap_path()

        if not text2pcap_path:
            print('未找到 text2pcap 可执行文件，请确保已安装 Wireshark 或相关工具')
            return

        subprocess.run([text2pcap_path, '-D', '-u', '5443,62132', '-t', '%H:%M:%S.%f', text_path,
                        os.path.join(self.session_dir, 'rtp-dump.pcap')], check=False)
        pass

    def find_text2pcap_path(self):
        text2pcap_path = shutil.which('text2pcap')
        if text2pcap_path:
            return text2pcap_path
        if sys.platform == 'win32':
            possible = [
                os.path.join(os.environ.get('PROGRAMW6432', ''), 'Wireshark/text2pcap.exe'),
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Wireshark/text2pcap.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Wireshark/text2pcap.exe')
            ]
            for path in possible:
                if os.path.exists(path):
                    return path
        if sys.platform == 'darwin':
            possible = [
                '/usr/local/bin/text2pcap',
                '/opt/homebrew/bin/text2pcap',
                '/Applications/Wireshark.app/Contents/MacOS/text2pcap',
            ]
            for path in possible:
                if os.path.exists(path):
                    return path
        return None

    def is_chrome_running_windows(self):
        """
        判断 Windows 上 chrome.exe 进程是否存在
        """
        if sys.platform != 'win32':
            print('当前不是 Windows 平台，无法检测 chrome.exe 进程')
            return False
        try:
            result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq chrome.exe'], capture_output=True, text=True)
            return 'chrome.exe' in result.stdout
        except Exception as e:
            print(f'检测 chrome.exe 进程时出错: {e}')
            return False

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    print('WebRTC-Spyglass 启动中...')
    print('当前操作系统:', sys.platform)
    app = WebRTCSpyglassApp()
    app.run()
