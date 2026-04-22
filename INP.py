# ida_export_for_ai.py
# IDA Plugin to export decompiled functions with disassembly fallback, strings, memory, imports and exports for AI analysis

import os
import time
import logging
try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import ida_lines
import ida_auto
import ida_kernwin
import ida_idaapi
import ida_ida
import ida_name
import ida_pro
import gc
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("INP")


WORKER_COUNT = max(1, (os.cpu_count() or 2) - 1)
TASK_BATCH_SIZE = 50

# 反编译控制参数
MAX_FUNC_SIZE_FOR_DECOMPILE = 16 * 1024   # 超过此字节数的函数跳过反编译，回退到反汇编（16KB — 超大函数易导致 Hex-Rays 卡死/崩溃）
MAX_FUNC_INSN_COUNT = 3000               # 超过此指令数的函数跳过反编译（对 Go 二进制更精准，降低阈值防止反编译器卡死）
DECOMPILE_TIME_LIMIT = 15                # 单个函数反编译超时（秒），超时自动加入黑名单

# 从模块中读取反编译标志常量（带硬编码回退，兼容各版本 IDA）
# DECOMP_NO_WAIT(0x1): 禁止反编译器显示内部等待框（macOS 上该对话框会触发嵌套事件循环导致卡死）
# DECOMP_NO_CACHE(0x4): 不使用反编译缓存（支持 patch 后重新导出正确伪代码）
_DECOMP_NO_WAIT  = getattr(ida_hexrays, 'DECOMP_NO_WAIT',  0x0001) if ida_hexrays else 0x0001
_DECOMP_NO_CACHE = getattr(ida_hexrays, 'DECOMP_NO_CACHE', 0x0004) if ida_hexrays else 0x0004
DECOMPILE_FLAGS_BASE = _DECOMP_NO_WAIT  # 基础标志：始终禁止等待框
DECOMPILE_FLAGS_NOCACHE = _DECOMP_NO_WAIT | _DECOMP_NO_CACHE  # patch 后重新导出时使用


def get_worker_count():
    """获取用户配置的并行工作线程数"""
    return WORKER_COUNT


def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return os.path.dirname(idb_path) if idb_path else os.getcwd()


def get_default_export_dir():
    """默认导出目录：`原文件名.扩展名_export_for_ai`。"""
    input_path = ida_nalt.get_input_file_path()
    if not input_path:
        try:
            import ida_loader
            input_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except Exception:
            input_path = None

    base_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    file_name = os.path.basename(input_path) if input_path else "input.bin"
    return os.path.join(base_dir, "{}_export_for_ai".format(file_name))


def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)


def clear_undo_buffer():
    """清理缓存，释放内存（IDA 9.x 已移除 undo API，仅做 gc）"""
    try:
        gc.collect()
    except Exception:
        pass


def disable_undo():
    """禁用撤销功能 - IDA 9.x 已移除此 API，保留为空操作以兼容调用点"""
    pass


def enable_undo():
    """启用撤销功能 - IDA 9.x 已移除此 API，保留为空操作以兼容调用点"""
    pass


def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if ida_bytes.is_code(ida_bytes.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))


def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))


def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])


def sanitize_filename(name):
    """清理函数名，使其适合作为文件名"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.replace('.', '_')
    if len(name) > 200:
        name = name[:200]
    return name


def get_function_output_filename(func_ea, export_type):
    """根据导出类型生成函数输出文件名"""
    if export_type == "disassembly-fallback":
        return "{:X}.asm".format(func_ea)
    return "{:X}.c".format(func_ea)


def get_function_output_subdir(export_type):
    """根据导出类型返回函数输出子目录"""
    if export_type == "disassembly-fallback":
        return "disassembly"
    return "decompile"


def get_function_output_relative_path(func_ea, export_type):
    """获取函数导出文件的相对路径"""
    return "{}/{}".format(
        get_function_output_subdir(export_type),
        get_function_output_filename(func_ea, export_type)
    )


def get_function_output_path(export_dir, func_ea, export_type):
    """获取函数导出文件的绝对路径"""
    output_dir = os.path.join(export_dir, get_function_output_subdir(export_type))
    output_filename = get_function_output_filename(func_ea, export_type)
    return os.path.join(output_dir, output_filename)


def find_existing_function_output(export_dir, func_ea):
    """查找函数已有的导出文件"""
    for export_type in ("decompile", "disassembly-fallback"):
        output_filename = get_function_output_relative_path(func_ea, export_type)
        output_path = get_function_output_path(export_dir, func_ea, export_type)
        if os.path.exists(output_path):
            return output_filename, output_path
    return None, None


def build_function_output_lines(func_ea, func_name, source_type, callers, callees, body, fallback_reason=None):
    """构建函数导出文件内容"""
    output_lines = []
    output_lines.append("/*")
    output_lines.append(" * func-name: {}".format(func_name))
    output_lines.append(" * func-address: {}".format(hex(func_ea)))
    output_lines.append(" * export-type: {}".format(source_type))
    output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
    output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
    if fallback_reason:
        output_lines.append(" * fallback-reason: {}".format(fallback_reason))
    output_lines.append(" */")
    output_lines.append("")
    output_lines.append(body)
    return output_lines


def generate_function_disassembly(func_ea):
    """生成函数的反汇编文本，用于反编译失败时回退"""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None, "not a valid function"

    disasm_lines = []
    for item_ea in idautils.FuncItems(func_ea):
        disasm_line = ida_lines.generate_disasm_line(
            item_ea,
            ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS
        )
        if disasm_line is None:
            disasm_line = ""
        else:
            disasm_line = ida_lines.tag_remove(disasm_line).rstrip()
        if not disasm_line:
            disasm_line = "<unable to render disassembly>"
        disasm_lines.append("{:X}: {}".format(item_ea, disasm_line))

    if not disasm_lines:
        return None, "function has no items"

    return "\n".join(disasm_lines), None


def save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs):
    """保存当前进度到文件"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/fallback/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{:X}|fallback|{}|{}|{}\n".format(addr, name, reason, output_filename))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        logger.error("Failed to save progress: %s", str(e))


def load_progress(export_dir):
    """从文件加载进度"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    fallback = []
    failed = []
    skipped = []

    if not os.path.exists(progress_file):
        return processed, fallback, failed, skipped

    try:
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == 'done':
                        processed.add(addr)
                    elif status == 'fallback' and len(parts) >= 5:
                        fallback.append((addr, parts[2], parts[3], parts[4]))
                    elif status == 'failed' and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == 'skipped' and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        logger.info("Loaded progress: %d functions already processed", len(processed))
    except Exception as e:
        logger.error("Failed to load progress: %s", str(e))

    return processed, fallback, failed, skipped


def mark_processing(export_dir, func_ea):
    """标记当前正在反编译的函数（用于崩溃/卡死恢复）"""
    try:
        with open(os.path.join(export_dir, ".currently_processing"), 'w') as f:
            f.write("{:X}\n".format(func_ea))
    except:
        pass


def clear_processing(export_dir):
    """清除处理标记"""
    path = os.path.join(export_dir, ".currently_processing")
    try:
        if os.path.exists(path):
            os.remove(path)
    except:
        pass


def load_crash_blacklist(export_dir):
    """加载导致崩溃/卡死的函数黑名单

    如果上次导出时某个函数导致 IDA 崩溃或卡死，.currently_processing 文件会残留，
    该函数会被自动加入黑名单，后续导出自动跳过反编译，使用反汇编回退。
    """
    blacklist = set()
    # 检查上次崩溃时正在处理的函数
    processing_file = os.path.join(export_dir, ".currently_processing")
    if os.path.exists(processing_file):
        try:
            with open(processing_file, 'r') as f:
                for line in f:
                    addr_str = line.strip()
                    if addr_str:
                        addr = int(addr_str, 16)
                        blacklist.add(addr)
                        logger.warning("Function at %s caused a previous crash/hang, adding to blacklist", hex(addr))
        except:
            pass
        # 将崩溃函数加入持久黑名单
        for addr in blacklist:
            _add_to_blacklist(export_dir, addr)
        clear_processing(export_dir)

    # 加载持久黑名单
    blacklist_file = os.path.join(export_dir, ".decompile_blacklist")
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            blacklist.add(int(line, 16))
                        except:
                            pass
        except:
            pass

    if blacklist:
        logger.info("%d functions in decompile blacklist (will use disassembly fallback)", len(blacklist))
    return blacklist


def _add_to_blacklist(export_dir, func_ea):
    """将函数添加到反编译黑名单"""
    try:
        with open(os.path.join(export_dir, ".decompile_blacklist"), 'a') as f:
            f.write("{:X}\n".format(func_ea))
    except:
        pass


def _decompile_safe(func_ea, flags):
    """安全反编译调用（已移除 SIGALRM，避免 macOS Cocoa NSRunLoop 冲突）。

    macOS 上 SIGALRM 会干扰 Cocoa 事件循环的信号处理机制，
    可能导致 NSRunLoop 嵌套或不可恢复的 UI 死锁。
    改为依赖函数大小/指令数限制 + 崩溃黑名单来防止卡死。
    """
    if ida_hexrays is None:
        return None
    # 清除可能残留的 Hex-Rays 等待框（macOS 上残留等待框会触发嵌套事件循环死锁）
    try:
        ida_hexrays.close_hexrays_waitbox()
    except Exception:
        pass
    try:
        result = ida_hexrays.decompile(func_ea, None, flags)
        return result
    except TypeError:
        # IDA 版本不支持 flags 参数
        result = ida_hexrays.decompile(func_ea)
        return result


# 模块级别保存活跃的导出作业（防止被 GC）
_active_export_job = None


class _FuncExportJob(object):
    """计时器回调驱动的函数导出作业。

    一切 IDA API 调用都在 IDA 主线程的定时器回调中执行，
    两次回调之间 IDA 事件循环正常运行：UI 始终响应，Cancel 有效。
    文件写入通过单独的 I/O 线程池并行执行（纯文件 I/O，不调用 IDA API）。

    使用延迟初始化：__init__ 不调用任何 IDA API，首次 tick 时才加载
    函数列表和进度。这样可以安全地从 pipeline tick 中创建并注册定时器，
    无需额外的 setup timer。
    """

    TIMER_INTERVAL_MS = 5      # tick 间隔（ms）；5ms 在函数间快速切换，macOS 事件循环仍正常响应

    def __init__(self, export_dir, skip_existing=True, force_reexport=False):
        # 延迟初始化：构造函数不调用任何 IDA API，也不创建线程池
        # ThreadPoolExecutor 延迟到 _lazy_init() 中创建，避免在 pipeline timer
        # 回调中创建线程导致 macOS Cocoa NSRunLoop 死锁
        self.export_dir = export_dir
        self.skip_existing = skip_existing
        self.force_reexport = force_reexport

        self.remaining_funcs = []  # 在 _lazy_init 中填充
        self.total_funcs = 0
        self.processed_addrs = set()
        self.crash_blacklist = set()

        self.idx = 0
        self.exported_funcs = 0
        self.fallback_funcs = []
        self.failed_funcs = []
        self.skipped_funcs = []
        self.function_index = []
        self.addr_to_info = {}

        # ThreadPoolExecutor 延迟到 _lazy_init() 中创建
        self.io_executor = None
        self.pending_futures = []

        self._tick_count = 0
        self._timer = None
        self._decompile_flags = DECOMPILE_FLAGS_NOCACHE if force_reexport else DECOMPILE_FLAGS_BASE
        self._wait_box_active = False

        self._job_start_time = 0
        self._current_func_name = None
        self._current_func_ea = None
        self._current_func_start_time = 0
        self._last_func_name = None
        self._last_func_time = 0
        self._last_func_status = None
        self._last_error_msg = None
        self._recent_errors = 0

        self._initialized = False  # 延迟初始化标志
        self._start_time = 0       # pipeline 起始时间，由 _tick_decompile 设置

    # ------------------------------------------------------------------
    # 定时器回调（在 IDA 主线程中执行）
    # ------------------------------------------------------------------

    def _build_status_msg(self, stage_hint=None):
        """构建包含详细进度信息的等待框文本。"""
        total = len(self.remaining_funcs)
        elapsed = time.time() - self._job_start_time
        elapsed_str = "{:02d}:{:02d}".format(int(elapsed) // 60, int(elapsed) % 60)

        # 速率和预估
        if self.idx > 0 and elapsed > 0:
            rate = self.idx / elapsed
            eta_sec = int((total - self.idx) / rate) if rate > 0 else 0
            eta_str = "{:02d}:{:02d}".format(eta_sec // 60, eta_sec % 60)
        else:
            eta_str = "--:--"

        lines = []
        # 第一行：阶段 + 总进度
        lines.append("[Stage 6/6] Decompile: {}/{} ({:.0f}%)".format(
            self.idx, total, (self.idx / total * 100) if total else 0))

        # 第二行：统计
        lines.append("OK={} | Fallback={} | Failed={} | Skip={}".format(
            self.exported_funcs, len(self.fallback_funcs),
            len(self.failed_funcs), len(self.skipped_funcs)))

        # 第三行：当前函数
        if self._current_func_name:
            func_time = time.time() - self._current_func_start_time
            func_label = self._current_func_name
            if len(func_label) > 40:
                func_label = func_label[:37] + "..."
            status_icon = stage_hint or "decompiling"
            lines.append(">> {} @ {} ({:.1f}s)".format(
                status_icon, func_label, func_time))

        # 第四行：上一个函数结果
        if self._last_func_name:
            last_label = self._last_func_name
            if len(last_label) > 35:
                last_label = last_label[:32] + "..."
            if self._last_func_status == "ok":
                lines.append("<< OK: {} ({:.1f}s)".format(last_label, self._last_func_time))
            elif self._last_func_status == "fallback":
                lines.append("<< FALLBACK: {} ({:.1f}s)".format(last_label, self._last_func_time))
            elif self._last_func_status == "failed":
                err = self._last_error_msg or "unknown"
                if len(err) > 40:
                    err = err[:37] + "..."
                lines.append("<< FAILED: {} - {}".format(last_label, err))
            elif self._last_func_status == "skipped":
                lines.append("<< SKIP: {}".format(last_label))

        # 第五行：时间
        lines.append("Elapsed: {} | ETA: {} | Cancel to abort".format(elapsed_str, eta_str))

        return "\n".join(lines)

    def _update_wait_box(self, msg=None):
        """更新等待框显示。

        macOS 上不能连续调用 show_wait_box()，否则会创建嵌套模态对话框导致死锁。
        策略：先尝试 replace_wait_box（接管已有的等待框），仅在 replace 失败时
        才调用 show_wait_box。避免两者都成功导致双层等待框。
        """
        if msg is None:
            msg = self._build_status_msg()
        try:
            if not self._wait_box_active:
                # pipeline 可能留下了可见的等待框，先尝试 replace 接管它
                replaced = False
                try:
                    ida_kernwin.replace_wait_box(msg)
                    replaced = True
                except Exception:
                    pass
                # 只有 replace 失败时才创建新的等待框
                if not replaced:
                    try:
                        ida_kernwin.show_wait_box(msg)
                    except Exception:
                        pass
                self._wait_box_active = True
            else:
                ida_kernwin.replace_wait_box(msg)
        except Exception:
            pass

    def _lazy_init(self):
        """延迟初始化：加载进度、黑名单、函数列表。在首次 tick 中调用。

        将这些 IDA API 调用延迟到 timer tick 中，避免在 __init__ 或 pipeline tick
        中阻塞。此时 pipeline 已完全结束，不会有定时器冲突。
        """
        ensure_dir(os.path.join(self.export_dir, "decompile"))
        ensure_dir(os.path.join(self.export_dir, "disassembly"))

        if self.force_reexport:
            processed_addrs, prev_fallback, prev_failed, prev_skipped = set(), [], [], []
            logger.info("Force re-export mode")
        else:
            processed_addrs, prev_fallback, prev_failed, prev_skipped = load_progress(self.export_dir)

        self.crash_blacklist = load_crash_blacklist(self.export_dir)

        all_funcs = list(idautils.Functions())

        self.total_funcs = len(all_funcs)
        self.remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]
        self.processed_addrs = processed_addrs
        self.fallback_funcs = list(prev_fallback)
        self.failed_funcs = list(prev_failed)
        self.skipped_funcs = list(prev_skipped)

        total_remaining = len(self.remaining_funcs)
        logger.info("Found %d functions total, %d remaining", self.total_funcs, total_remaining)

        if total_remaining == 0:
            logger.info("All functions already exported!")
            return False  # 无需处理

        self._job_start_time = time.time()

        # 测试反编译是否可用：尝试反编译第一个函数
        test_ea = self.remaining_funcs[0]
        try:
            if ida_hexrays:
                _decompile_safe(test_ea, self._decompile_flags)
        except Exception:
            pass

        # 在 lazy init 中创建线程池（而非 __init__），避免在 pipeline timer 回调中
        # 创建线程导致 macOS Cocoa NSRunLoop 死锁
        if self.io_executor is None:
            io_workers = max(2, int((os.cpu_count() or 2) * 0.7))
            self.io_executor = ThreadPoolExecutor(max_workers=io_workers, thread_name_prefix="INP-IO")

        return True

    def tick(self):
        """每次由 IDA 定时器调用，处理一个函数。返回下次间隔（ms）或 -1 停止。

        每次 tick 只处理一个函数，确保在两次 tick 之间 IDA 事件循环有机会处理
        UI 事件（包括 Cancel 按钮点击）。即使单个 decompile() 调用耗时较长，
        下一次 tick 开始时用户仍可通过 Cancel 中止。
        """
        self._tick_count += 1

        # 延迟初始化：首次 tick 时加载函数列表和进度
        if not self._initialized:
            try:
                if not self._lazy_init():
                    # 所有函数已导出，直接完成
                    enable_undo()
                    elapsed = time.time() - self._start_time if hasattr(self, '_start_time') else 0
                    ida_kernwin.info("All functions already exported!")
                    return -1
            except Exception as e:
                logger.error("Lazy init failed: %s", e, exc_info=True)
                ida_kernwin.warning("Decompile init failed!\n\n{}".format(str(e)))
                enable_undo()
                return -1
            self._initialized = True

        # 收集已完成的写入（非阻塞）
        self._collect_done_futures()

        # 检查用户取消
        if self._wait_box_active and ida_kernwin.user_cancelled():
            logger.info("Export cancelled by user at %d/%d",
                        self.idx, len(self.remaining_funcs))
            self._finish(cancelled=True)
            return -1

        # 所有函数已处理完
        if self.idx >= len(self.remaining_funcs):
            self._finish(cancelled=False)
            return -1

        func_ea = self.remaining_funcs[self.idx]
        self.idx += 1

        # 记录当前函数的计时信息
        self._current_func_ea = func_ea
        self._current_func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
        self._current_func_start_time = time.time()


        # 先更新等待框（让用户看到即将处理哪个函数，便于判断卡死位置）
        self._update_wait_box()

        self._process_one(func_ea)

        # 记录完成时间
        func_elapsed = time.time() - self._current_func_start_time
        self._last_func_name = self._current_func_name
        self._last_func_time = func_elapsed
        self._current_func_name = None
        self._current_func_ea = None

        # 更新等待框显示完成结果
        self._update_wait_box()

        # 每 50 个函数保存一次进度
        if self.idx % 50 == 0:
            self._flush_all_pending(wait=False)
            save_progress(self.export_dir, self.processed_addrs,
                          self.fallback_funcs, self.failed_funcs, self.skipped_funcs)
            logger.info("Progress: %d/%d functions", self.idx, len(self.remaining_funcs))

        # 每 500 个函数清理一次内存
        if self.idx % 500 == 0:
            clear_undo_buffer()
            try:
                if ida_hexrays:
                    ida_hexrays.clear_cached_cfuncs()
            except Exception:
                pass
            gc.collect()

        return self.TIMER_INTERVAL_MS

    def run_blocking(self, show_dialog=False):
        """阻塞式运行，用于 `idat -A -S...` 批处理模式。"""
        global _active_export_job
        _active_export_job = self
        self._start_time = time.time()
        self._job_start_time = self._start_time

        try:
            if not self._lazy_init():
                logger.info("All functions already exported!")
                enable_undo()
                _active_export_job = None
                return

            self._initialized = True

            while self.idx < len(self.remaining_funcs):
                self._collect_done_futures()

                func_ea = self.remaining_funcs[self.idx]
                self.idx += 1

                self._current_func_ea = func_ea
                self._current_func_name = ida_funcs.get_func_name(func_ea) or hex(func_ea)
                self._current_func_start_time = time.time()

                self._process_one(func_ea)

                func_elapsed = time.time() - self._current_func_start_time
                self._last_func_name = self._current_func_name
                self._last_func_time = func_elapsed
                self._current_func_name = None
                self._current_func_ea = None

                if self.idx % 50 == 0:
                    self._flush_all_pending(wait=False)
                    save_progress(self.export_dir, self.processed_addrs,
                                  self.fallback_funcs, self.failed_funcs, self.skipped_funcs)
                    logger.info("Progress: %d/%d functions", self.idx, len(self.remaining_funcs))

                if self.idx % 500 == 0:
                    clear_undo_buffer()
                    try:
                        if ida_hexrays:
                            ida_hexrays.clear_cached_cfuncs()
                    except Exception:
                        pass
                    gc.collect()

            self._finish(cancelled=False, show_dialog=show_dialog)
        except Exception:
            try:
                if self.io_executor is not None:
                    self._flush_all_pending(wait=True)
                    self.io_executor.shutdown(wait=True)
            except Exception:
                pass
            clear_processing(self.export_dir)
            save_progress(self.export_dir, self.processed_addrs,
                          self.fallback_funcs, self.failed_funcs, self.skipped_funcs)
            enable_undo()
            _active_export_job = None
            raise

    # ------------------------------------------------------------------
    # 单函数处理（在主线程中，IDA API 完全安全）
    # ------------------------------------------------------------------

    def _process_one(self, func_ea):
        func_name = ida_funcs.get_func_name(func_ea)
        func = ida_funcs.get_func(func_ea)

        if func is None:
            self.skipped_funcs.append((func_ea, func_name, "not a valid function"))
            self.processed_addrs.add(func_ea)
            self._last_func_status = "skipped"
            return

        if func.flags & ida_funcs.FUNC_LIB:
            self.skipped_funcs.append((func_ea, func_name, "library function"))
            self.processed_addrs.add(func_ea)
            self._last_func_status = "skipped"
            return

        # 检查是否已存在（跳过模式）
        if self.skip_existing and not self.force_reexport:
            existing, _ = find_existing_function_output(self.export_dir, func_ea)
            if existing:
                self.exported_funcs += 1
                self.processed_addrs.add(func_ea)
                self._last_func_status = "ok"
                return

        fallback_reason = None
        output_body = None
        export_type = None

        func_size = func.end_ea - func.start_ea
        if func_ea in self.crash_blacklist:
            fallback_reason = "in crash/hang blacklist"
        elif func_size > MAX_FUNC_SIZE_FOR_DECOMPILE:
            fallback_reason = "function too large ({} bytes, limit {} bytes)".format(
                func_size, MAX_FUNC_SIZE_FOR_DECOMPILE)
        else:
            # 使用带上限的计数，避免在超大函数上遍历所有指令
            insn_count = 0
            for _ in idautils.FuncItems(func_ea):
                insn_count += 1
                if insn_count > MAX_FUNC_INSN_COUNT:
                    break
            if insn_count > MAX_FUNC_INSN_COUNT:
                fallback_reason = "too many instructions (>{}, limit {})".format(
                    MAX_FUNC_INSN_COUNT, MAX_FUNC_INSN_COUNT)

        if fallback_reason is None:
            mark_processing(self.export_dir, func_ea)
            decompile_start = time.time()
            try:
                dec_obj = _decompile_safe(func_ea, self._decompile_flags)

                if dec_obj is None:
                    fallback_reason = "decompile returned None"
                else:
                    dec_str = str(dec_obj)
                    dec_obj = None
                    if dec_str and dec_str.strip():
                        output_body = dec_str
                        export_type = "decompile"
                    else:
                        fallback_reason = "empty decompilation result"
            except ida_hexrays.DecompilationFailure as e:
                fallback_reason = "decompilation failure: {}".format(str(e))
            except Exception as e:
                fallback_reason = "unexpected error: {}".format(str(e))
            finally:
                dec_obj = None
            clear_processing(self.export_dir)

            # 反编译超时检测：超时的函数自动加入黑名单，下次跳过
            decompile_elapsed = time.time() - decompile_start
            if decompile_elapsed > DECOMPILE_TIME_LIMIT:
                _add_to_blacklist(self.export_dir, func_ea)
                logger.warning("Decompile timeout (%.1fs) for %s @ %s, added to blacklist",
                               decompile_elapsed, func_name, hex(func_ea))

        if output_body is None:
            output_body, disasm_error = generate_function_disassembly(func_ea)
            if output_body is None:
                combined = fallback_reason or "unknown"
                if disasm_error:
                    combined += "; disasm fallback failed: " + disasm_error
                self.failed_funcs.append((func_ea, func_name, combined))
                self.processed_addrs.add(func_ea)
                self._last_func_status = "failed"
                self._last_error_msg = combined
                return
            export_type = "disassembly-fallback"

        callers = get_callers(func_ea)
        callees = get_callees(func_ea)

        # 提交文件写入到 I/O 线程池（纯文件 I/O，不调用 IDA API）
        job_args = (func_ea, func_name, output_body, callers, callees, export_type, fallback_reason)
        export_dir = self.export_dir

        def _write(args):
            ea, name, body, calrs, callrs, etype, freason = args
            lines = build_function_output_lines(ea, name, etype, calrs, callrs, body,
                                                fallback_reason=freason)
            path = get_function_output_path(export_dir, ea, etype)
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                return True, get_function_output_relative_path(ea, etype), calrs, callrs, etype, freason, None
            except IOError as e:
                return False, get_function_output_relative_path(ea, etype), calrs, callrs, etype, freason, str(e)

        future = self.io_executor.submit(_write, job_args)
        self.pending_futures.append((future, func_ea, func_name, callers, callees, export_type, fallback_reason))

        # 更新上一个函数的状态
        if export_type == "disassembly-fallback":
            self._last_func_status = "fallback"
            self._last_error_msg = fallback_reason
        else:
            self._last_func_status = "ok"
            self._last_error_msg = None

    # ------------------------------------------------------------------
    # I/O 结果收集
    # ------------------------------------------------------------------

    def _collect_done_futures(self):
        """收集已完成的写入 future（非阻塞）。"""
        still_pending = []
        for item in self.pending_futures:
            future, func_ea, func_name, callers, callees, export_type, fallback_reason = item
            if not future.done():
                still_pending.append(item)
                continue
            self._record_future_result(future, func_ea, func_name, callers, callees, export_type, fallback_reason)
        self.pending_futures = still_pending

    def _flush_all_pending(self, wait=True):
        """等待所有挂起 future 完成并收集结果。"""
        for item in self.pending_futures:
            future, func_ea, func_name, callers, callees, export_type, fallback_reason = item
            try:
                if wait:
                    future.result(timeout=60)
            except Exception:
                pass
            if future.done():
                self._record_future_result(future, func_ea, func_name, callers, callees, export_type, fallback_reason)
        self.pending_futures = [item for item in self.pending_futures if not item[0].done()]

    def _record_future_result(self, future, func_ea, func_name, callers, callees, export_type, fallback_reason):
        try:
            success, out_fn, r_callers, r_callees, r_etype, r_freason, error = future.result(timeout=0)
        except Exception as e:
            self.failed_funcs.append((func_ea, func_name, "IO error: {}".format(str(e))))
            self.processed_addrs.add(func_ea)
            return

        if success:
            func_info = {
                'address': func_ea, 'name': func_name, 'filename': out_fn,
                'export_type': r_etype, 'callers': r_callers, 'callees': r_callees,
            }
            if r_freason:
                func_info['fallback_reason'] = r_freason
            self.function_index.append(func_info)
            self.addr_to_info[func_ea] = func_info
            if r_etype == "disassembly-fallback":
                self.fallback_funcs.append((func_ea, func_name,
                                            r_freason or "decompilation failed", out_fn))
            self.exported_funcs += 1
            self.processed_addrs.add(func_ea)
        else:
            self.failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
            self.processed_addrs.add(func_ea)

    # ------------------------------------------------------------------
    # 完成和日志
    # ------------------------------------------------------------------

    def _finish(self, cancelled, show_dialog=True):
        """等待 I/O 完成，写日志，显示完成对话框。在主线程中调用，完全安全。"""
        global _active_export_job

        # 等待所有 I/O 完成
        if self.io_executor is not None:
            self._flush_all_pending(wait=True)
            self.io_executor.shutdown(wait=True)

        clear_processing(self.export_dir)
        save_progress(self.export_dir, self.processed_addrs,
                      self.fallback_funcs, self.failed_funcs, self.skipped_funcs)

        if cancelled:
            logger.info("Export was cancelled by user")

        logger.info("Decompilation Summary:")
        logger.info("  Total functions   : %d", self.total_funcs)
        logger.info("  Exported          : %d", self.exported_funcs)
        logger.info("  Fallback (disasm) : %d", len(self.fallback_funcs))
        logger.info("  Skipped           : %d", len(self.skipped_funcs))
        logger.info("  Failed            : %d", len(self.failed_funcs))

        self._write_logs()
        enable_undo()

        # 隐藏等待框（可能有多层嵌套，多次 hide 确保全部清除）
        if self._wait_box_active:
            for _ in range(3):
                try:
                    ida_kernwin.hide_wait_box()
                except Exception:
                    break
            self._wait_box_active = False

        # 清理全局引用
        _active_export_job = None

        if show_dialog:
            # 显示完成对话框（在主线程直接调用，完全安全）
            if cancelled:
                title = "Export Cancelled"
            else:
                title = "Export Completed"

            elapsed = time.time() - self._job_start_time
            elapsed_str = "{:d}m {:02d}s".format(int(elapsed) // 60, int(elapsed) % 60)

            summary = ("{}\n\n"
                       "Exported : {}  |  Fallback : {}  |  Failed : {}\n"
                       "Skipped  : {}  |  Time: {}\n\n"
                       "Output: {}").format(
                title,
                self.exported_funcs, len(self.fallback_funcs),
                len(self.failed_funcs), len(self.skipped_funcs),
                elapsed_str, self.export_dir)
            ida_kernwin.info(summary)

    def _write_logs(self):
        ed = self.export_dir
        if self.fallback_funcs:
            with open(os.path.join(ed, "disassembly_fallback.txt"), 'w', encoding='utf-8') as f:
                f.write("# Fallback to disassembly for {} functions\n".format(len(self.fallback_funcs)))
                f.write("# Format: address | function_name | reason | output_file\n")
                f.write("#" + "=" * 80 + "\n\n")
                for addr, name, reason, out_fn in self.fallback_funcs:
                    f.write("{} | {} | {} | {}\n".format(hex(addr), name, reason, out_fn))
            logger.info("  Fallback list: disassembly_fallback.txt")

        if self.failed_funcs:
            with open(os.path.join(ed, "decompile_failed.txt"), 'w', encoding='utf-8') as f:
                f.write("# Failed to decompile {} functions\n".format(len(self.failed_funcs)))
                f.write("# Format: address | function_name | reason\n")
                f.write("#" + "=" * 80 + "\n\n")
                for addr, name, reason in self.failed_funcs:
                    f.write("{} | {} | {}\n".format(hex(addr), name, reason))
            logger.info("  Failed list: decompile_failed.txt")

        if self.skipped_funcs:
            with open(os.path.join(ed, "decompile_skipped.txt"), 'w', encoding='utf-8') as f:
                f.write("# Skipped {} functions\n".format(len(self.skipped_funcs)))
                f.write("# Format: address | function_name | reason\n")
                f.write("#" + "=" * 80 + "\n\n")
                for addr, name, reason in self.skipped_funcs:
                    f.write("{} | {} | {}\n".format(hex(addr), name, reason))
            logger.info("  Skipped list: decompile_skipped.txt")

        if self.function_index:
            index_path = os.path.join(ed, "function_index.txt")
            with open(index_path, 'w', encoding='utf-8') as f:
                f.write("# Function Index\n")
                f.write("# Total exported: {}\n".format(len(self.function_index)))
                f.write("#" + "=" * 80 + "\n\n")
                for fi in self.function_index:
                    f.write("=" * 80 + "\n")
                    f.write("Function: {}\n".format(fi['name']))
                    f.write("Address: {}\n".format(hex(fi['address'])))
                    f.write("File: {}\n".format(fi['filename']))
                    f.write("Type: {}\n".format(fi['export_type']))
                    if 'fallback_reason' in fi:
                        f.write("Fallback reason: {}\n".format(fi['fallback_reason']))
                    f.write("\n")
                    if fi['callers']:
                        f.write("Called by ({}):\n".format(len(fi['callers'])))
                        for ca in fi['callers']:
                            if ca in self.addr_to_info:
                                ci = self.addr_to_info[ca]
                                f.write("  - {} ({}) -> {}\n".format(hex(ca), ci['name'], ci['filename']))
                            else:
                                f.write("  - {}\n".format(hex(ca)))
                    else:
                        f.write("Called by: none\n")
                    f.write("\n")
                    if fi['callees']:
                        f.write("Calls ({}):\n".format(len(fi['callees'])))
                        for ce in fi['callees']:
                            if ce in self.addr_to_info:
                                ci = self.addr_to_info[ce]
                                f.write("  - {} ({}) -> {}\n".format(hex(ce), ci['name'], ci['filename']))
                            else:
                                f.write("  - {}\n".format(hex(ce)))
                    else:
                        f.write("Calls: none\n")
                    f.write("\n")
            logger.info("  Function index: function_index.txt")


def export_decompiled_functions(export_dir, skip_existing=True, force_reexport=False):
    """使用 register_timer 驱动的主线程增量导出（不阻塞 IDA UI）。"""
    global _active_export_job

    ensure_dir(os.path.join(export_dir, "decompile"))
    ensure_dir(os.path.join(export_dir, "disassembly"))

    if force_reexport:
        processed_addrs, prev_fallback, prev_failed, prev_skipped = set(), [], [], []
        logger.info("Force re-export mode")
    else:
        processed_addrs, prev_fallback, prev_failed, prev_skipped = load_progress(export_dir)

    crash_blacklist = load_crash_blacklist(export_dir)
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]
    total_remaining = len(remaining_funcs)

    logger.info("Found %d functions total, %d remaining", total_funcs, total_remaining)

    if total_remaining == 0:
        logger.info("All functions already exported!")
        return

    # 不在此处调用 replace_wait_box — pipeline 的等待框可能已由 _tick_decompile 释放
    # _FuncExportJob.tick() 会在第一个 tick 中通过 show_wait_box 创建自己的等待框

    job = _FuncExportJob(
        export_dir=export_dir,
        remaining_funcs=remaining_funcs,
        total_funcs=total_funcs,
        processed_addrs=processed_addrs,
        crash_blacklist=crash_blacklist,
        skip_existing=skip_existing,
        force_reexport=force_reexport,
        prev_fallback=prev_fallback,
        prev_failed=prev_failed,
        prev_skipped=prev_skipped,
    )

    _active_export_job = job
    # register_timer: 在 IDA 主线程事件循环中周期性调用 job.tick
    # job.tick 返回 -1 时定时器自动停止
    job._timer = ida_kernwin.register_timer(_FuncExportJob.TIMER_INTERVAL_MS, job.tick)

    if job._timer is None:
        logger.error("Failed to register export timer")
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass
        _active_export_job = None


def export_decompiled_functions_sync(export_dir, skip_existing=True, force_reexport=False):
    """阻塞式导出函数，用于批处理模式。"""
    ensure_dir(os.path.join(export_dir, "decompile"))
    ensure_dir(os.path.join(export_dir, "disassembly"))

    job = _FuncExportJob(
        export_dir=export_dir,
        skip_existing=skip_existing,
        force_reexport=force_reexport,
    )
    job.run_blocking(show_dialog=False)


def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")

    string_count = 0
    BATCH_SIZE = 500  # 每500个字符串清理一次

    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, s in enumerate(idautils.Strings()):
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"

                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1

                # 定期清理撤销缓冲区
                if (idx + 1) % BATCH_SIZE == 0:
                    clear_undo_buffer()

            except Exception as e:
                continue

    logger.info("Strings Summary:")
    logger.info("  Total strings exported: %d", string_count)


def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")

    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, imp_cb)

    logger.info("Imports Summary:")
    logger.info("  Total imports exported: %d", import_count)


def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")

    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)

            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1

    logger.info("Exports Summary:")
    logger.info("  Total exports exported: %d", export_count)


def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)

    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16

    total_bytes = 0
    file_count = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue

        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)

        logger.info("Processing segment: %s (%s - %s)", seg_name, hex(seg_start), hex(seg_end))

        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)

            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)

            # 跳过已存在的文件
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                total_bytes += (chunk_end - current_addr)
                continue

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")

                addr = current_addr
                while addr < chunk_end:
                    line_size = min(BYTES_PER_LINE, chunk_end - addr)
                    raw = ida_bytes.get_bytes(addr, line_size)
                    if not raw:
                        addr += BYTES_PER_LINE
                        continue

                    line_bytes = bytearray(raw)
                    if len(line_bytes) < BYTES_PER_LINE:
                        line_bytes.extend(b'\x00' * (BYTES_PER_LINE - len(line_bytes)))

                    # 构建十六进制部分（批量，避免逐字符拼接）
                    hex_parts = []
                    for i in range(BYTES_PER_LINE):
                        hex_parts.append("{:02X}".format(line_bytes[i]))
                        if i == 7:
                            hex_parts.append("")
                    hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[9:])
                    if line_size < BYTES_PER_LINE:
                        hex_str = hex_str[:line_size * 3] + "   " * (BYTES_PER_LINE - line_size)

                    # 构建 ASCII 部分
                    ascii_part = ''.join(
                        chr(b) if 0x20 <= b <= 0x7E else '.'
                        for b in line_bytes[:line_size]
                    )

                    f.write("{:016X} | {} | {}\n".format(addr, hex_str.ljust(49), ascii_part))

                    addr += BYTES_PER_LINE
                    total_bytes += line_size

            file_count += 1
            current_addr = chunk_end

            # 每处理完一个chunk清理一次撤销缓冲区
            clear_undo_buffer()

    logger.info("Memory Export Summary:")
    logger.info("  Total bytes exported: %d (%.2f MB)", total_bytes, total_bytes / (1024 * 1024))
    logger.info("  Files created: %d", file_count)


def _ptr_export_get_ptr_size():
    """获取当前数据库的指针大小"""
    return 8 if ida_ida.inf_is_64bit() else 4


def _ptr_export_read_pointer(ea, ptr_size):
    """读取指针值"""
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)


def _ptr_export_get_segment_name(ea):
    """获取地址所在段名"""
    seg = ida_segment.getseg(ea)
    if not seg:
        return "unknown"
    name = ida_segment.get_segm_name(seg)
    return name if name else "unknown"


def _ptr_export_is_valid_target(target_ea):
    """判断目标地址是否落在有效段内"""
    if target_ea in (0, ida_idaapi.BADADDR):
        return False
    return ida_segment.getseg(target_ea) is not None


def _ptr_export_safe_text(value):
    """将文本压成单行，便于写入导出文件"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            value = repr(value)
    else:
        value = str(value)

    value = value.replace("\r", " ").replace("\n", " ").replace("|", "/").strip()
    if len(value) > 80:
        value = value[:77] + "..."
    return value


def _ptr_export_get_target_name(target_ea):
    """获取目标符号名"""
    name = ida_name.get_name(target_ea)
    if not name:
        func = ida_funcs.get_func(target_ea)
        if func:
            name = ida_funcs.get_func_name(func.start_ea)
    if not name:
        name = "unknown"
    return _ptr_export_safe_text(name)


def _ptr_export_try_get_string_preview(target_ea):
    """尝试提取字符串预览"""
    try:
        flags = ida_bytes.get_full_flags(target_ea)
        if not ida_bytes.is_strlit(flags):
            return ""
    except Exception:
        return ""

    try:
        strtype = ida_nalt.get_str_type(target_ea)
    except Exception:
        strtype = ida_nalt.STRTYPE_C

    try:
        raw = ida_bytes.get_strlit_contents(target_ea, -1, strtype)
    except Exception:
        raw = None

    preview = _ptr_export_safe_text(raw)
    if preview:
        return '"{}"'.format(preview)
    return "string_literal"


def _ptr_export_is_import_target(target_ea, target_name):
    """启发式判断是否为导入项/IAT"""
    seg_name = _ptr_export_get_segment_name(target_ea).lower()
    name_l = (target_name or "").lower()

    if name_l.startswith("__imp_") or name_l.startswith("imp_"):
        return True

    import_like_segments = {
        "extern", ".idata", "idata", ".idata$2", ".idata$4", ".idata$5", ".idata$6",
        ".got", "got", ".got.plt", "got.plt", "__la_symbol_ptr", "__nl_symbol_ptr"
    }
    return seg_name in import_like_segments


def _ptr_export_classify_target(target_ea):
    """返回 (target_name, target_type, target_detail)"""
    target_name = _ptr_export_get_target_name(target_ea)

    try:
        flags = ida_bytes.get_full_flags(target_ea)
    except Exception:
        flags = 0

    if _ptr_export_is_import_target(target_ea, target_name):
        return target_name, "import_pointer", "import_entry"

    try:
        if ida_bytes.is_strlit(flags):
            return target_name, "string_pointer", _ptr_export_try_get_string_preview(target_ea)
    except Exception:
        pass

    try:
        func = ida_funcs.get_func(target_ea)
    except Exception:
        func = None

    if func:
        if func.start_ea == target_ea:
            return target_name, "function_pointer", "function_start"
        func_name = _ptr_export_get_target_name(func.start_ea)
        return target_name, "code_pointer", "inside_{}".format(func_name)

    try:
        if ida_bytes.is_code(flags):
            return target_name, "code_pointer", "instruction"
    except Exception:
        pass

    try:
        if ida_bytes.is_struct(flags):
            return target_name, "struct_pointer", "struct_data"
    except Exception:
        pass

    try:
        if ida_bytes.is_data(flags):
            return target_name, "data_pointer", "data_item_size={}".format(ida_bytes.get_item_size(target_ea))
    except Exception:
        pass

    return target_name, "unknown_pointer", ""


def _ptr_export_add_record(records, seen, source_ea, target_ea):
    """去重后加入一条记录"""
    key = (source_ea, target_ea)
    if key in seen:
        return
    seen.add(key)

    target_name, target_type, target_detail = _ptr_export_classify_target(target_ea)
    records.append({
        "source_addr": source_ea,
        "source_seg": _ptr_export_get_segment_name(source_ea),
        "points_to": target_ea,
        "target_name": target_name,
        "target_type": target_type,
        "target_detail": target_detail,
    })


def _ptr_export_collect_data_xrefs(records, seen):
    """收集所有代码头/数据头上的 data xref"""
    total = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if not seg:
            continue

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags)):
                continue

            try:
                target = ida_xref.get_first_dref_from(head)
            except Exception:
                target = ida_idaapi.BADADDR

            while target != ida_idaapi.BADADDR:
                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, head, target)
                    total += 1
                try:
                    target = ida_xref.get_next_dref_from(head, target)
                except Exception:
                    break

    return total


def _ptr_export_collect_raw_pointers(records, seen, ptr_size):
    """扫描常见数据段中的裸指针，补齐未建立 xref 的项"""
    total = 0

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        seg_name = ida_segment.get_segm_name(seg)
        seg_start = seg.start_ea
        seg_end = seg.end_ea

        if not seg_name or not (
                seg_name.startswith(".data") or seg_name.startswith(".rdata") or seg_name.startswith("data")):
            continue

        logger.info("Scanning segment: %s (%X - %X)", seg_name, seg_start, seg_end)

        for head in idautils.Heads(seg_start, seg_end):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not ida_bytes.is_data(flags):
                continue

            try:
                item_size = ida_bytes.get_item_size(head)
            except Exception:
                item_size = 0

            if item_size < ptr_size:
                continue

            slot_count = item_size // ptr_size
            if slot_count <= 0:
                continue

            for i in range(slot_count):
                slot_ea = head + i * ptr_size
                try:
                    target = _ptr_export_read_pointer(slot_ea, ptr_size)
                except Exception:
                    continue

                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, slot_ea, target)
                    total += 1

    return total


def export_pointers(export_dir):
    """导出指针引用，保留原有导出目录模式"""
    output_path = os.path.join(export_dir, "pointers.txt")
    ptr_size = _ptr_export_get_ptr_size()
    records = []
    seen = set()

    logger.info("Starting pointer scan. Pointer size: %d bytes", ptr_size)

    dref_hits = _ptr_export_collect_data_xrefs(records, seen)
    raw_hits = _ptr_export_collect_raw_pointers(records, seen, ptr_size)

    records.sort(key=lambda item: (
        item["source_addr"],
        item["points_to"],
        item["source_seg"],
        item["target_name"],
        item["target_type"],
        item["target_detail"],
    ))

    if records:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# Total Pointers Found: {}\n".format(len(records)))
                f.write(
                    "# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail\n")
                f.write("# Pointer size: {}\n".format(ptr_size))
                f.write("# Data xref hits: {}\n".format(dref_hits))
                f.write("# Raw pointer hits: {}\n".format(raw_hits))
                f.write("-" * 120 + "\n")
                for p in records:
                    f.write("{:X} | {} | {:X} | {} | {} | {}\n".format(
                        p["source_addr"],
                        p["source_seg"],
                        p["points_to"],
                        p["target_name"],
                        p["target_type"],
                        p["target_detail"]
                    ))
            logger.info("Pointers exported to: %s", output_path)
            logger.info("Pointers Summary:")
            logger.info("  Data xref hits: %d", dref_hits)
            logger.info("  Raw pointer hits: %d", raw_hits)
            logger.info("  Unique pointer references exported: %d", len(records))
        except Exception as e:
            logger.error("Failed to write pointers: %s", str(e))
    else:
        logger.info("No pointers found or no data segments scanned.")


# ============================================================================
# Timer-Driven Export Pipeline (non-blocking, macOS safe)
# ============================================================================

_active_pipeline = None


class _ExportPipeline(object):
    """全阶段定时器驱动的导出管线。

    所有导出阶段（分析等待、初始化、字符串、导入、导出、指针、内存、反编译）
    都在 IDA 主线程的 register_timer 回调中增量执行。两次 tick 之间 IDA 事件循环
    正常运行，UI 始终保持响应，用户随时可以取消。

    macOS 上 auto_wait() 会阻塞主线程导致 Cocoa NSRunLoop 死锁，
    改为定时器轮询 auto_is_ok() 完全规避此问题。
    """

    TIMER_INTERVAL_MS = 5
    TICK_BUDGET_S = 0.15       # 每 tick 最大执行时间（秒），平衡吞吐与 macOS UI 响应
    STRINGS_BATCH = 500        # 每个 tick 处理的字符串数
    MEMORY_CHUNK = 512 * 1024  # 每个 tick 处理的内存块大小 (512KB)
    PTR_HEADS_PER_TICK = 1500  # 每 tick 最多扫描的 head 数量
    ANALYSIS_POLL_INTERVAL_MS = 100  # auto-analysis 轮询间隔（ms）

    def __init__(self, export_dir, force_reexport, skip_auto_analysis):
        self.export_dir = export_dir
        self.force_reexport = force_reexport
        self.skip_auto_analysis = skip_auto_analysis
        self.has_hexrays = None  # 在 _tick_init 中确定

        self._timer = None
        self._wait_box_active = False
        self._start_time = time.time()
        self._tick_start = 0.0  # 当前 tick 开始时间，用于时间预算控制
        self._phase = 0
        self._phase_initialized = False

        # 动态构建阶段列表
        self._phase_names = []
        if not skip_auto_analysis:
            self._phase_names.append("Analysis")
        self._phase_names.append("Init")
        self._phase_names.extend(["Strings", "Imports", "Exports", "Pointers", "Memory"])
        # Decompile 阶段在 _tick_init 确定有 Hex-Rays 后动态追加
        self._total_phases = len(self._phase_names)

        # ---- Strings state ----
        self._str_iter = None
        self._str_f = None
        self._str_count = 0

        # ---- Pointers state ----
        self._ptr_sub_phase = 0   # 0=dxref scanning, 1=raw init, 2=raw scanning, 3=write
        self._ptr_records = []
        self._ptr_seen = set()
        self._ptr_size = 0
        self._ptr_all_segs = []
        self._ptr_seg_idx = 0
        self._ptr_dref_hits = 0
        self._ptr_raw_hits = 0
        self._ptr_raw_segs = []
        self._ptr_raw_seg_idx = 0
        self._ptr_heads_iter = None     # dxref 扫描的 heads 迭代器
        self._ptr_raw_heads_iter = None # raw pointer 扫描的 heads 迭代器

        # ---- Memory state ----
        self._mem_segs = []
        self._mem_seg_idx = 0
        self._mem_addr = None
        self._mem_total_bytes = 0
        self._mem_file_count = 0

        # ---- Decompile state (job delegated to pipeline timer, no nested register_timer) ----
        self._job = None  # _FuncExportJob 实例，通过 pipeline timer 直接驱动

    def start(self):
        global _active_pipeline
        _active_pipeline = self

        ensure_dir(os.path.join(self.export_dir, "decompile"))
        ensure_dir(os.path.join(self.export_dir, "disassembly"))
        ensure_dir(os.path.join(self.export_dir, "memory"))

        self._timer = ida_kernwin.register_timer(self.TIMER_INTERVAL_MS, self._tick)
        if self._timer is None:
            logger.error("Failed to register export pipeline timer")
            _active_pipeline = None
            return False
        return True

    # ------------------------------------------------------------------
    # 主 tick 回调
    # ------------------------------------------------------------------

    def _tick(self):
        """由 IDA 定时器调用。处理当前阶段的一个工作单元。"""
        self._tick_start = time.time()

        # 检查用户取消
        if self._wait_box_active and ida_kernwin.user_cancelled():
            self._finish(cancelled=True)
            return -1

        # 所有阶段完成
        if self._phase >= self._total_phases:
            self._finish(cancelled=False)
            return -1

        self._update_wait_box()

        # 动态构建 handlers 列表
        handlers = []
        if not self.skip_auto_analysis:
            handlers.append(self._tick_analysis)
        handlers.append(self._tick_init)
        handlers.extend([
            self._tick_strings,
            self._tick_imports,
            self._tick_exports,
            self._tick_pointers,
            self._tick_memory,
        ])
        if self.has_hexrays:
            handlers.append(self._tick_decompile)

        try:
            done = handlers[self._phase]()
        except Exception as e:
            logger.error("Pipeline phase %s error: %s", self._phase_names[self._phase], e, exc_info=True)
            done = True

        if done:
            logger.info("Pipeline phase completed: %s", self._phase_names[self._phase])
            clear_undo_buffer()
            self._phase += 1
            self._phase_initialized = False

        # Analysis 阶段用较长的轮询间隔，减少 CPU 占用
        if self._phase == 0 and not self.skip_auto_analysis and not done:
            return self.ANALYSIS_POLL_INTERVAL_MS
        return self.TIMER_INTERVAL_MS

    # ------------------------------------------------------------------
    # 时间预算控制
    # ------------------------------------------------------------------

    def _should_yield(self):
        """检查当前 tick 是否已超出时间预算，需要让出主线程。"""
        return time.time() - self._tick_start > self.TICK_BUDGET_S

    # ------------------------------------------------------------------
    # Phase: Analysis (定时器轮询，替代阻塞的 auto_wait)
    # ------------------------------------------------------------------

    def _tick_analysis(self):
        """轮询 auto-analysis 状态，不阻塞主线程。

        替代 ida_auto.auto_wait()，后者在 macOS 上会阻塞 Cocoa NSRunLoop
        导致 spinning beach ball 和 "Not Responding"。
        """
        if ida_auto.auto_is_ok():
            logger.info("Auto-analysis completed")
            return True
        # 继续轮询，_tick() 会返回 ANALYSIS_POLL_INTERVAL_MS
        return False

    # ------------------------------------------------------------------
    # Phase: Init (初始化 Hex-Rays 反编译器)
    # ------------------------------------------------------------------

    def _tick_init(self):
        """初始化 Hex-Rays 反编译器并动态追加 Decompile 阶段。"""
        if ida_hexrays is None:
            self.has_hexrays = False
            logger.warning("ida_hexrays module not available, skipping decompilation")
            return True
        if ida_hexrays.init_hexrays_plugin():
            self.has_hexrays = True
            self._phase_names.append("Decompile")
            self._total_phases = len(self._phase_names)
            logger.info("Hex-Rays decompiler initialized")
        else:
            self.has_hexrays = False
            logger.warning("Hex-Rays decompiler not available, skipping decompilation")
        return True

    # ------------------------------------------------------------------
    # 等待框管理
    # ------------------------------------------------------------------

    def _update_wait_box(self, extra=""):
        if self._phase >= self._total_phases:
            return
        elapsed = time.time() - self._start_time
        elapsed_str = "{:02d}:{:02d}".format(int(elapsed) // 60, int(elapsed) % 60)
        phase_name = self._phase_names[self._phase] if self._phase < self._total_phases else "Done"
        msg = "[Stage {}/{}] {} | Elapsed: {} | Cancel to abort".format(
            self._phase + 1, self._total_phases, phase_name, elapsed_str)
        if extra:
            msg += "\n" + extra
        try:
            if not self._wait_box_active:
                ida_kernwin.show_wait_box(msg)
                self._wait_box_active = True
            else:
                ida_kernwin.replace_wait_box(msg)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Stage: Strings (增量，每 tick 处理 STRINGS_BATCH 个)
    # ------------------------------------------------------------------

    def _tick_strings(self):
        if not self._phase_initialized:
            path = os.path.join(self.export_dir, "strings.txt")
            self._str_f = open(path, 'w', encoding='utf-8')
            self._str_f.write("# Strings exported from IDA\n")
            self._str_f.write("# Format: address | length | type | string\n")
            self._str_f.write("#" + "=" * 80 + "\n\n")
            self._str_iter = iter(idautils.Strings())
            self._str_count = 0
            self._phase_initialized = True

        batch = 0
        while batch < self.STRINGS_BATCH:
            if self._should_yield():
                break
            try:
                s = next(self._str_iter)
            except StopIteration:
                self._str_f.close()
                self._str_f = None
                logger.info("Exported %d strings", self._str_count)
                return True
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                self._str_f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea), s.length, str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')))
                self._str_count += 1
            except Exception:
                pass
            batch += 1
        return False

    # ------------------------------------------------------------------
    # Stage: Imports (通常很快，一个 tick 完成)
    # ------------------------------------------------------------------

    def _tick_imports(self):
        export_imports(self.export_dir)
        return True

    # ------------------------------------------------------------------
    # Stage: Exports (通常很快，一个 tick 完成)
    # ------------------------------------------------------------------

    def _tick_exports(self):
        export_exports(self.export_dir)
        return True

    # ------------------------------------------------------------------
    # Stage: Pointers (增量，每 tick 处理一个段)
    # ------------------------------------------------------------------

    def _tick_pointers(self):
        if not self._phase_initialized:
            self._ptr_records = []
            self._ptr_seen = set()
            self._ptr_size = _ptr_export_get_ptr_size()
            self._ptr_all_segs = []
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg:
                    self._ptr_all_segs.append(seg)
            self._ptr_seg_idx = 0
            self._ptr_sub_phase = 0
            self._ptr_dref_hits = 0
            self._ptr_raw_hits = 0
            self._ptr_heads_iter = None
            self._ptr_raw_heads_iter = None
            self._phase_initialized = True

        if self._ptr_sub_phase == 0:
            # Data xref: 每 tick 处理 PTR_HEADS_PER_TICK 个 head（带时间预算）
            if self._ptr_seg_idx >= len(self._ptr_all_segs):
                self._ptr_sub_phase = 1
                self._ptr_heads_iter = None
                return False

            if self._ptr_heads_iter is None:
                seg = self._ptr_all_segs[self._ptr_seg_idx]
                seg_name = ida_segment.get_segm_name(seg) if seg else "?"
                self._ptr_heads_iter = iter(idautils.Heads(seg.start_ea, seg.end_ea))

            heads_processed = 0
            while heads_processed < self.PTR_HEADS_PER_TICK:
                if self._should_yield():
                    return False
                try:
                    head = next(self._ptr_heads_iter)
                except StopIteration:
                    self._ptr_seg_idx += 1
                    self._ptr_heads_iter = None
                    return False
                try:
                    flags = ida_bytes.get_full_flags(head)
                except Exception:
                    continue
                if not ida_bytes.is_head(flags):
                    continue
                if not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags)):
                    continue
                try:
                    target = ida_xref.get_first_dref_from(head)
                except Exception:
                    target = ida_idaapi.BADADDR
                while target != ida_idaapi.BADADDR:
                    if _ptr_export_is_valid_target(target):
                        _ptr_export_add_record(self._ptr_records, self._ptr_seen, head, target)
                        self._ptr_dref_hits += 1
                    try:
                        target = ida_xref.get_next_dref_from(head, target)
                    except Exception:
                        break
                heads_processed += 1
            return False

        elif self._ptr_sub_phase == 1:
            # 初始化 raw pointer 扫描
            self._ptr_raw_segs = []
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                seg_name = ida_segment.get_segm_name(seg) if seg else ""
                if seg_name and (seg_name.startswith(".data") or seg_name.startswith(".rdata")
                                or seg_name.startswith("data")):
                    self._ptr_raw_segs.append(seg_ea)
            self._ptr_raw_seg_idx = 0
            self._ptr_sub_phase = 2
            return False

        elif self._ptr_sub_phase == 2:
            # Raw pointer: 每 tick 处理 PTR_HEADS_PER_TICK 个 head（带时间预算）
            if self._ptr_raw_seg_idx >= len(self._ptr_raw_segs):
                self._ptr_sub_phase = 3
                self._ptr_raw_heads_iter = None
                return False

            if self._ptr_raw_heads_iter is None:
                seg_ea = self._ptr_raw_segs[self._ptr_raw_seg_idx]
                seg = ida_segment.getseg(seg_ea)
                seg_name = ida_segment.get_segm_name(seg) if seg else "?"
                seg = ida_segment.getseg(seg_ea)
                seg_start = seg.start_ea if seg else seg_ea
                seg_end = seg.end_ea if seg else seg_ea
                self._ptr_raw_heads_iter = iter(idautils.Heads(seg_start, seg_end))

            ptr_size = self._ptr_size
            heads_processed = 0
            while heads_processed < self.PTR_HEADS_PER_TICK:
                if self._should_yield():
                    return False
                try:
                    head = next(self._ptr_raw_heads_iter)
                except StopIteration:
                    self._ptr_raw_seg_idx += 1
                    self._ptr_raw_heads_iter = None
                    return False
                try:
                    flags = ida_bytes.get_full_flags(head)
                except Exception:
                    continue
                if not ida_bytes.is_head(flags) or not ida_bytes.is_data(flags):
                    continue
                try:
                    item_size = ida_bytes.get_item_size(head)
                except Exception:
                    item_size = 0
                if item_size < ptr_size:
                    continue
                for i in range(item_size // ptr_size):
                    slot_ea = head + i * ptr_size
                    try:
                        target = _ptr_export_read_pointer(slot_ea, ptr_size)
                    except Exception:
                        continue
                    if _ptr_export_is_valid_target(target):
                        _ptr_export_add_record(self._ptr_records, self._ptr_seen, slot_ea, target)
                        self._ptr_raw_hits += 1
                heads_processed += 1
            return False

        elif self._ptr_sub_phase == 3:
            # 排序并写入
            self._ptr_records.sort(key=lambda item: (
                item["source_addr"], item["points_to"],
                item["source_seg"], item["target_name"],
                item["target_type"], item["target_detail"],
            ))
            output_path = os.path.join(self.export_dir, "pointers.txt")
            if self._ptr_records:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write("# Total Pointers Found: {}\n".format(len(self._ptr_records)))
                    f.write("# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail\n")
                    f.write("# Pointer size: {}\n".format(self._ptr_size))
                    f.write("# Data xref hits: {}\n".format(self._ptr_dref_hits))
                    f.write("# Raw pointer hits: {}\n".format(self._ptr_raw_hits))
                    f.write("-" * 120 + "\n")
                    for p in self._ptr_records:
                        f.write("{:X} | {} | {:X} | {} | {} | {}\n".format(
                            p["source_addr"], p["source_seg"], p["points_to"],
                            p["target_name"], p["target_type"], p["target_detail"]))
                logger.info("Exported %d pointers (dxref=%d, raw=%d)",
                            len(self._ptr_records), self._ptr_dref_hits, self._ptr_raw_hits)
            else:
                logger.info("No pointers found")
            # 释放内存
            self._ptr_records = []
            self._ptr_seen = set()
            return True

        return False

    # ------------------------------------------------------------------
    # Stage: Memory (增量，每 tick 处理一个 1MB 块)
    # ------------------------------------------------------------------

    def _tick_memory(self):
        if not self._phase_initialized:
            self._mem_segs = []
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                if seg:
                    self._mem_segs.append(seg)
            self._mem_seg_idx = 0
            self._mem_addr = None
            self._mem_total_bytes = 0
            self._mem_file_count = 0
            self._phase_initialized = True

        BYTES_PER_LINE = 16

        if self._mem_seg_idx >= len(self._mem_segs):
            logger.info("Memory export: %d bytes (%d files)", self._mem_total_bytes, self._mem_file_count)
            return True

        seg = self._mem_segs[self._mem_seg_idx]
        if self._mem_addr is None:
            self._mem_addr = seg.start_ea

        seg_name = ida_segment.get_segm_name(seg)
        chunk_end = min(self._mem_addr + self.MEMORY_CHUNK, seg.end_ea)
        chunk_size = chunk_end - self._mem_addr

        filename = "{:08X}--{:08X}.txt".format(self._mem_addr, chunk_end)
        filepath = os.path.join(self.export_dir, "memory", filename)

        if os.path.exists(filepath):
            self._mem_file_count += 1
        else:
            # 一次性读取整个块（单次 IDA API 调用，避免数千次 get_byte/get_bytes）
            raw = ida_bytes.get_bytes(self._mem_addr, chunk_size)
            if raw:
                lines = []
                lines.append("# Memory dump: {} - {}".format(hex(self._mem_addr), hex(chunk_end)))
                lines.append("# Segment: {}".format(seg_name))
                lines.append("#" + "=" * 76)
                lines.append("")
                lines.append("# Address        | Hex Bytes                                       | ASCII")
                lines.append("#" + "-" * 76)

                data = bytearray(raw)
                for offset in range(0, len(data), BYTES_PER_LINE):
                    line_bytes = data[offset:offset + BYTES_PER_LINE]
                    line_size = len(line_bytes)

                    # 构建十六进制
                    hex_left = " ".join("{:02X}".format(b) for b in line_bytes[:8])
                    hex_right = " ".join("{:02X}".format(b) for b in line_bytes[8:])
                    hex_str = (hex_left + "  " + hex_right).ljust(49)

                    # 构建 ASCII
                    ascii_part = ''.join(
                        chr(b) if 0x20 <= b <= 0x7E else '.'
                        for b in line_bytes
                    )

                    lines.append("{:016X} | {} | {}".format(
                        self._mem_addr + offset, hex_str, ascii_part))
                    self._mem_total_bytes += line_size

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines) + '\n')
            self._mem_file_count += 1

        self._mem_addr = chunk_end
        if self._mem_addr >= seg.end_ea:
            self._mem_seg_idx += 1
            self._mem_addr = None

        return False

    # ------------------------------------------------------------------
    # Stage: Decompile (通过 pipeline timer 直接驱动，不嵌套 register_timer)
    # ------------------------------------------------------------------

    def _tick_decompile(self):
        """反编译阶段 — 通过 pipeline timer 直接驱动 _FuncExportJob，不嵌套 register_timer。

        macOS 上从 timer callback 内调用 register_timer() 会导致 Cocoa NSRunLoop 死锁。
        解决方案：不注册新的定时器，而是通过 pipeline 已有的 timer 直接调用 job.tick()。
        第一次调用时创建 job（轻量 __init__，无 IDA API、无 ThreadPoolExecutor），
        后续调用直接委托给 job.tick()，直到 job 完成。
        """
        global _active_export_job

        if not self._phase_initialized:
            # 第一次调用：创建 job，不注册新定时器
            self._job = _FuncExportJob(
                export_dir=self.export_dir,
                skip_existing=True,
                force_reexport=self.force_reexport,
            )
            self._job._start_time = self._start_time
            _active_export_job = self._job
            self._phase_initialized = True
            self._wait_box_active = False  # job 会管理自己的等待框
            return False  # 阶段未完成，pipeline timer 继续调用

        # 后续调用：委托给 job.tick()
        try:
            result = self._job.tick()
        except Exception as e:
            self._job = None
            _active_export_job = None
            return True  # 阶段完成（异常终止）

        if result == -1:
            # job 完成（正常结束或取消），job._finish() 已在 tick() 内调用
            self._job = None
            _active_export_job = None
            return True  # 阶段完成

        return False  # 继续 tick

    # ------------------------------------------------------------------
    # 完成
    # ------------------------------------------------------------------

    def _finish(self, cancelled):
        global _active_pipeline

        # 清理打开的文件句柄
        if self._str_f is not None and not self._str_f.closed:
            self._str_f.close()
            self._str_f = None

        if self._wait_box_active:
            for _ in range(3):
                try:
                    ida_kernwin.hide_wait_box()
                except Exception:
                    break
            self._wait_box_active = False

        _active_pipeline = None

        if cancelled:
            enable_undo()
            logger.info("Export cancelled by user at phase %d/%d",
                        self._phase + 1, self._total_phases)
            ida_kernwin.info("Export cancelled by user.")
        elif self.has_hexrays is not True:
            # 无 Hex-Rays 或初始化前退出时，pipeline 是最终完成者
            enable_undo()
            elapsed = time.time() - self._start_time
            elapsed_str = "{:d}m {:02d}s".format(int(elapsed) // 60, int(elapsed) % 60)
            logger.info("Export completed (no Hex-Rays)")
            ida_kernwin.info("Export completed (no decompiler)!\n\nTime: {}\nOutput: {}".format(
                elapsed_str, self.export_dir))


def do_export(export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None, force_reexport=False):
    """执行导出操作

    所有耗时操作（auto-analysis 等待、Hex-Rays 初始化、数据导出）都在定时器驱动的
    pipeline 中异步执行，run() 立即返回，不阻塞 IDA UI。

    Args:
        export_dir: 导出目录路径，如果为None则使用默认或询问用户
        ask_user: 是否询问用户选择目录
        skip_auto_analysis: 是否跳过等待自动分析（如果已经分析完成）
        worker_count: 并行工作线程数，默认为CPU核心数-1
        force_reexport: 强制重新导出所有函数（忽略之前的进度，用于patch后重新导出）
    """
    global WORKER_COUNT


    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)

    logger.info("=" * 60)
    logger.info("IDA Export for AI Analysis")
    logger.info("=" * 60)
    logger.info("Using %d worker threads for parallel I/O", WORKER_COUNT)

    # 初始清理
    clear_undo_buffer()

    # 尝试禁用撤销功能以减少内存使用
    disable_undo()

    if export_dir is None:
        default_export_dir = get_default_export_dir()

        if ask_user:
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                        "Export to default directory?\n\n{}\n\nYes: Use default directory\nNo: Choose custom directory\nCancel: Abort export".format(
                                            default_export_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                logger.info("Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(default_export_dir, 0, "Enter export directory path:")
                if selected_dir:
                    export_dir = selected_dir
                    logger.info("Using custom directory: %s", export_dir)
                else:
                    logger.info("Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)

    logger.info("Export directory: %s", export_dir)

    # 隐藏 IDA 自带的 "Running Python script" 等待框
    # pipeline 会在第一个 timer tick 中创建自己的等待框
    try:
        ida_kernwin.hide_wait_box()
    except Exception:
        pass

    # 启动定时器驱动的导出管线
    # run() 立即返回，所有导出工作在后续 timer tick 中增量执行
    # auto-analysis 等待和 Hex-Rays 初始化都在 pipeline 内异步完成
    pipeline = _ExportPipeline(
        export_dir=export_dir,
        force_reexport=force_reexport,
        skip_auto_analysis=skip_auto_analysis,
    )
    if not pipeline.start():
        enable_undo()
        ida_kernwin.warning("Failed to start export pipeline!")
        return


def do_export_sync(export_dir=None, skip_auto_analysis=False, worker_count=None, force_reexport=False):
    """同步阻塞导出，适用于 `idat -A -S...` 批处理模式。"""
    global WORKER_COUNT

    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)

    logger.info("=" * 60)
    logger.info("IDA Export for AI Analysis (blocking batch mode)")
    logger.info("=" * 60)
    logger.info("Using %d worker threads for parallel I/O", WORKER_COUNT)

    clear_undo_buffer()
    disable_undo()

    try:
        if export_dir is None:
            export_dir = get_default_export_dir()

        ensure_dir(export_dir)
        logger.info("Export directory: %s", export_dir)

        if not skip_auto_analysis:
            logger.info("Waiting for auto-analysis to complete...")
            ida_auto.auto_wait()
            logger.info("Auto-analysis completed")

        if ida_hexrays is None:
            logger.warning("ida_hexrays module not available, decompilation will fall back to disassembly")
        else:
            try:
                if ida_hexrays.init_hexrays_plugin():
                    logger.info("Hex-Rays decompiler initialized")
                else:
                    logger.warning("Hex-Rays decompiler not available, decompilation will fall back to disassembly")
            except Exception as e:
                logger.warning("Failed to initialize Hex-Rays: %s", str(e))

        export_strings(export_dir)
        export_imports(export_dir)
        export_exports(export_dir)
        export_pointers(export_dir)
        export_memory(export_dir)
        export_decompiled_functions_sync(export_dir, skip_existing=True, force_reexport=force_reexport)

        logger.info("Blocking export completed: %s", export_dir)
    finally:
        enable_undo()


# ============================================================================
# Plugin Class (plugmod_t pattern, recommended by IDA 9.x)
# ============================================================================

class ExportForAIPlugmod(ida_idaapi.plugmod_t):
    """IDA plugmod for exporting data for AI analysis.

    使用 plugmod_t 模式（IDA 9.x 推荐），配合 PLUGIN_MULTI flag。
    plugmod_t 的生命周期由 IDA 管理：
    - __init__ / init: 插件加载时调用
    - run: 用户通过菜单或快捷键触发
    - term: 插件卸载时调用
    """

    def __init__(self):
        super().__init__()

    def run(self, arg):
        """插件运行 - 所有操作通过定时器异步执行，run() 快速返回"""
        try:

            # 检查是否已有导出在运行
            if _active_pipeline is not None or _active_export_job is not None:
                ida_kernwin.warning("An export is already in progress!\n"
                                    "Please wait for it to complete or cancel it first.")
                return

            # 显示默认导出目录，让用户选择模式
            default_dir = get_default_export_dir()

            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                        "Export for AI Analysis\n\n"
                                        "Directory: {}\n\n"
                                        "Yes: Export (skip already exported)\n"
                                        "No: Force re-export all (use after patching)\n"
                                        "Cancel: Abort".format(default_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                logger.info("Export cancelled by user")
                return

            force_reexport = (choice == ida_kernwin.ASKBTN_NO)

            do_export(export_dir=default_dir, ask_user=False, force_reexport=force_reexport)
        except Exception as e:
            logger.error("Export failed: %s", e, exc_info=True)
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        """插件卸载"""
        logger.info("Export for AI plugin unloaded")


class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA Plugin entry point (PLUGIN_MULTI -> plugmod_t)"""

    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Export IDA data for AI analysis"
    help = "Export decompiled functions with disassembly fallback, strings, memory, imports and exports"
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        """插件初始化 - 返回 plugmod_t 实例"""
        logger.info("Export for AI plugin loaded (Ctrl-Shift-E)")
        return ExportForAIPlugmod()


def PLUGIN_ENTRY():
    """IDA插件入口点"""
    return ExportForAIPlugin()


# ============================================================================
# Standalone Script Support
# ============================================================================

if __name__ == "__main__":
    # 支持作为独立脚本运行（用于批处理模式）
    # ARGV 是 IDC 概念，批处理模式下通过 idc 模块获取
    import idc as _idc
    argc = int(_idc.eval_idc("ARGV.count"))
    if argc < 2:
        export_dir = None
        skip_analysis = False
    elif argc < 3:
        export_dir = _idc.eval_idc("ARGV[1]")
        skip_analysis = False
    else:
        export_dir = _idc.eval_idc("ARGV[1]")
        skip_analysis = (_idc.eval_idc("ARGV[2]") == "1")

    # 批处理模式改用同步导出，确保所有文件写完后再退出
    do_export_sync(export_dir, skip_auto_analysis=skip_analysis)

    # 只在批处理模式下退出
    if argc >= 2:
        ida_pro.qexit(0)
