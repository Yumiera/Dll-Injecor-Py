import flet as ft
import psutil
import os
import ctypes
from ctypes import wintypes

# 定义必要的常量
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

# 加载必要的Windows API函数
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = wintypes.LPVOID
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

GetModuleHandle = kernel32.GetModuleHandleW
GetModuleHandle.restype = wintypes.HMODULE
GetModuleHandle.argtypes = [wintypes.LPCWSTR]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = wintypes.LPVOID
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = wintypes.HANDLE
CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.restype = wintypes.BOOL
VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]

def inject_dll(pid, dll_path):
    # 打开目标进程
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"Failed to open process with PID {pid}")
        return False

    # 分配内存以存储DLL路径
    dll_path_bytes = dll_path.encode('utf-8')
    remote_memory = VirtualAllocEx(process_handle, None, len(dll_path_bytes) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote_memory:
        print("Failed to allocate memory in target process")
        CloseHandle(process_handle)
        return False

    # 将DLL路径写入分配的内存
    written = ctypes.c_size_t(0)
    if not WriteProcessMemory(process_handle, remote_memory, dll_path_bytes, len(dll_path_bytes), ctypes.byref(written)):
        print("Failed to write memory to target process")
        VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
        CloseHandle(process_handle)
        return False

    # 获取LoadLibraryA函数地址
    load_library = GetProcAddress(GetModuleHandle("kernel32.dll"), b"LoadLibraryA")
    if not load_library:
        print("Failed to get address of LoadLibraryA")
        VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
        CloseHandle(process_handle)
        return False

    # 创建远程线程以执行LoadLibraryA
    thread_handle = CreateRemoteThread(process_handle, None, 0, load_library, remote_memory, 0, None)
    if not thread_handle:
        print("Failed to create remote thread")
        VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
        CloseHandle(process_handle)
        return False

    print(f"DLL injection initiated for process {pid} with DLL path {dll_path}")

    # 清理资源
    CloseHandle(thread_handle)
    VirtualFreeEx(process_handle, remote_memory, 0, 0x8000)
    CloseHandle(process_handle)

    return True

def list_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        processes.append((proc.info['pid'], proc.info['name']))
    return processes

def main(page: ft.Page):
    # 设置页面属性
    page.title = "DLL Injector"
    page.window_width = 600
    page.window_height = 400
    page.window_resizable = False
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    # 控件定义
    dll_path = ft.TextField(label="Select DLL", width=400, disabled=True, hint_text="Choose a DLL file")
    pid_dropdown = ft.Dropdown(label="Select Process", width=400, disabled=True, hint_text="Choose a process")
    status_text = ft.Text("", size=14, color="green")

    def on_select_file(e):
        file_picker = ft.FilePicker(on_result=lambda result: on_file_selected(result))
        page.overlay.append(file_picker)
        page.update()
        file_picker.pick_files(allow_multiple=False, allowed_extensions=["dll"])

    def on_file_selected(result):
        if result.files and result.files[0]:
            dll_path.value = result.files[0].path
            status_text.value = f"Selected DLL: {result.files[0].name}"
            page.update()

    def on_refresh(e):
        refresh_processes()

    def on_inject(e):
        selected_pid = int(pid_dropdown.value.split(":")[0])
        if os.path.exists(dll_path.value):
            if inject_dll(selected_pid, dll_path.value):
                status_text.value = "DLL injection successful."
            else:
                status_text.value = "DLL injection failed."
        else:
            status_text.value = "The specified DLL file does not exist."
        page.update()

    def refresh_processes():
        pid_dropdown.options.clear()
        for pid, name in list_processes():
            pid_dropdown.options.append(ft.dropdown.Option(f"{pid}: {name}"))
        pid_dropdown.disabled = False
        page.update()

    # 按钮定义
    select_file_button = ft.ElevatedButton(text="Select DLL", on_click=on_select_file, width=150)
    inject_button = ft.ElevatedButton(text="Inject", on_click=on_inject, width=150, disabled=True)
    refresh_button = ft.ElevatedButton(text="Refresh", on_click=on_refresh, width=150)

    # 绑定控件状态更新
    def update_controls(e):
        if dll_path.value and pid_dropdown.value:
            inject_button.disabled = False
        else:
            inject_button.disabled = True
        page.update()

    # 监听文本字段变化
    dll_path.on_change = update_controls
    pid_dropdown.on_change = update_controls

    # 初始化进程列表
    refresh_processes()

    # 美化布局
    page.add(
        ft.Column(
            [
                ft.Text("DLL Injector", size=24, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                ft.Divider(height=5, thickness=2),
                dll_path,
                pid_dropdown,
                ft.Row(
                    [
                        select_file_button,
                        inject_button,
                        refresh_button
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=10
                ),
                ft.Divider(height=5, thickness=2),
                status_text
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20,
            tight=True
        )
    )

if __name__ == "__main__":
    ft.app(target=main,assets_dir="assets")