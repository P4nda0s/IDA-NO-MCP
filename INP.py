# ida_export_for_ai.py
# IDA Plugin to export decompiled functions, strings, memory, imports and exports for AI analysis
# Compatible with IDA 9.0+

import os
import sys
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_auto
import ida_kernwin
import ida_idaapi
import ida_ida
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import multiprocessing as mp

# Conditionally import modules that may not exist in IDA 9.0
try:
    import ida_undo
    HAS_IDA_UNDO = True
except ImportError:
    HAS_IDA_UNDO = False

try:
    import ida_idp
    HAS_IDA_IDP = True
except ImportError:
    HAS_IDA_IDP = False

WORKER_COUNT = max(1, mp.cpu_count() - 1)
TASK_BATCH_SIZE = 50

def get_worker_count():
    """获取用户配置的并行工作线程数"""
    return WORKER_COUNT

def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        try:
            import ida_loader
            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except:
            pass
    return os.path.dirname(idb_path) if idb_path else os.getcwd()

def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)

def clear_undo_buffer():
    """清理 IDA 撤销缓冲区，防止内存溢出"""
    try:
        if HAS_IDA_UNDO:
            ida_undo.clear_undo_buffer()
        gc.collect()
    except:
        pass

def disable_undo():
    """禁用撤销功能"""
    try:
        if HAS_IDA_IDP and hasattr(ida_idp, 'disable_undo'):
            ida_idp.disable_undo(True)
    except:
        pass

def enable_undo():
    """启用撤销功能"""
    try:
        if HAS_IDA_IDP and hasattr(ida_idp, 'disable_undo'):
            ida_idp.disable_undo(False)
    except:
        pass

def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
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
        if idc.is_code(idc.get_full_flags(head)):
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

def save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs):
    """保存当前进度到文件"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))

def load_progress(export_dir):
    """从文件加载进度"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    failed = []
    skipped = []
    
    if not os.path.exists(progress_file):
        return processed, failed, skipped
    
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
                    elif status == 'failed' and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == 'skipped' and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print("[+] Loaded progress: {} functions already processed".format(len(processed)))
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))
    
    return processed, failed, skipped

def export_decompiled_functions(export_dir, skip_existing=True):
    """导出所有函数的反编译代码（内存优化版 - 流式处理）
    
    Args:
        export_dir: 导出目录
        skip_existing: 是否跳过已存在的文件
    """
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)

    total_funcs = 0
    exported_funcs = 0
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}

    # 使用单线程I/O避免内存累积
    io_executor = ThreadPoolExecutor(max_workers=1)

    # 加载之前的进度
    processed_addrs, prev_failed, prev_skipped = load_progress(export_dir)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    # 收集所有函数地址
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    
    # 过滤掉已处理的函数
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]
    
    print("[*] Found {} functions total, {} remaining to process".format(total_funcs, len(remaining_funcs)))
    print("[*] Memory-optimized mode: processing one function at a time")
    
    if len(remaining_funcs) == 0:
        print("[+] All functions already exported!")
        io_executor.shutdown(wait=False)
        return

    # 流式处理 - 不预加载所有调用关系
    BATCH_SIZE = 10  # 减小批量大小
    MEMORY_CLEAN_INTERVAL = 5  # 更频繁地清理内存
    pending_writes = []
    
    def write_function_file(args):
        """线程安全的文件写入"""
        func_ea, func_name, dec_str, callers, callees = args
        
        output_lines = []
        output_lines.append("/*")
        output_lines.append(" * func-name: {}".format(func_name))
        output_lines.append(" * func-address: {}".format(hex(func_ea)))
        output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
        output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
        output_lines.append(" */")
        output_lines.append("")
        output_lines.append(dec_str)

        output_filename = "{:X}.c".format(func_ea)
        output_path = os.path.join(decompile_dir, output_filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, None
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, str(e)
    
    def aggressive_memory_cleanup():
        """激进的内存清理"""
        # 清理IDA Hex-Rays内部缓存
        try:
            if hasattr(ida_hexrays, 'clear_cached_cfuncs'):
                ida_hexrays.clear_cached_cfuncs()
        except:
            pass
        # 强制垃圾回收
        gc.collect()
        gc.collect()  # 两次收集确保清理
    
    for idx, func_ea in enumerate(remaining_funcs):
        # 实时获取函数信息（不缓存）
        func_name = idc.get_func_name(func_ea)
        
        # 跳过外部函数和导入函数
        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue

        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        dec_str = None
        dec_obj = None
        
        try:
            # 尝试反编译
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                processed_addrs.add(func_ea)
                continue

            dec_str = str(dec_obj)
            # 立即释放反编译对象
            dec_obj = None
            
            if not dec_str or len(dec_str.strip()) == 0:
                failed_funcs.append((func_ea, func_name, "empty decompilation result"))
                processed_addrs.add(func_ea)
                continue

            # 只在需要时获取调用关系
            callers = get_callers(func_ea)
            callees = get_callees(func_ea)

            output_filename = "{:X}.c".format(func_ea)
            output_path = os.path.join(decompile_dir, output_filename)
            
            # 如果文件已存在且skip_existing为True，则跳过
            if skip_existing and os.path.exists(output_path):
                exported_funcs += 1
                processed_addrs.add(func_ea)
                # 立即释放dec_str
                dec_str = None
                if (exported_funcs + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                    print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
                continue

            # 提交写入任务
            write_args = (func_ea, func_name, dec_str, callers, callees)
            future = io_executor.submit(write_function_file, write_args)
            pending_writes.append((future, func_ea, func_name, output_filename, callers, callees))
            
            # 立即释放dec_str，因为已经传递给写入任务
            dec_str = None
            
        except ida_hexrays.DecompilationFailure as e:
            failed_funcs.append((func_ea, func_name, "decompilation failure: {}".format(str(e))))
            processed_addrs.add(func_ea)
            continue
        except Exception as e:
            failed_funcs.append((func_ea, func_name, "unexpected error: {}".format(str(e))))
            print("[!] Error decompiling {} at {}: {}".format(func_name, hex(func_ea), str(e)))
            processed_addrs.add(func_ea)
            continue
        finally:
            # 确保反编译对象被释放
            dec_obj = None
            dec_str = None
        
        # 定期清理撤销缓冲区
        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()
        
        # 批量等待写入完成并收集结果
        if len(pending_writes) >= BATCH_SIZE:
            for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
                try:
                    result = future.result()
                    func_ea, func_name, success, output_filename, callers, callees, error = result
                    
                    if success:
                        func_info = {
                            'address': func_ea,
                            'name': func_name,
                            'filename': output_filename,
                            'callers': callers,
                            'callees': callees
                        }
                        function_index.append(func_info)
                        addr_to_info[func_ea] = func_info
                        exported_funcs += 1
                        processed_addrs.add(func_ea)
                    else:
                        failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                        processed_addrs.add(func_ea)
                    
                except Exception as e:
                    print("[!] Write error: {}".format(str(e)))
            
            # 保存进度并清理
            save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)
            if exported_funcs % 100 == 0:
                print("[+] Exported {} / {} functions...".format(exported_funcs + len(prev_failed) + len(prev_skipped), total_funcs))
            
            # 清理索引，避免内存无限增长
            if len(function_index) > 1000:
                # 保存到临时文件后清空
                function_index = []
                addr_to_info = {}
            
            pending_writes = []
            aggressive_memory_cleanup()
    
    # 处理剩余的写入任务
    if pending_writes:
        for future, func_ea, func_name, output_filename, callers, callees in pending_writes:
            try:
                result = future.result()
                func_ea, func_name, success, output_filename, callers, callees, error = result
                
                if success:
                    func_info = {
                        'address': func_ea,
                        'name': func_name,
                        'filename': output_filename,
                        'callers': callers,
                        'callees': callees
                    }
                    function_index.append(func_info)
                    addr_to_info[func_ea] = func_info
                    exported_funcs += 1
                    processed_addrs.add(func_ea)
                else:
                    failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                    processed_addrs.add(func_ea)
                
            except Exception as e:
                print("[!] Write error: {}".format(str(e)))
    
    # 关闭线程池
    io_executor.shutdown(wait=True)
    
    # 最终保存进度
    save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)
    
    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Skipped: {} (library/invalid functions)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    # 保存失败列表
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    # 保存跳过列表
    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, 'w', encoding='utf-8') as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    # 生成函数索引文件
    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")

            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info['name']))
                f.write("Address: {}\n".format(hex(func_info['address'])))
                f.write("File: {}\n".format(func_info['filename']))
                f.write("\n")

                if func_info['callers']:
                    f.write("Called by ({} callers):\n".format(len(func_info['callers'])))
                    for caller_addr in func_info['callers']:
                        if caller_addr in addr_to_info:
                            caller_info = addr_to_info[caller_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(caller_addr),
                                caller_info['name'],
                                caller_info['filename']
                            ))
                        else:
                            caller_name = idc.get_func_name(caller_addr)
                            f.write("  - {} ({})\n".format(hex(caller_addr), caller_name))
                else:
                    f.write("Called by: none\n")

                f.write("\n")

                if func_info['callees']:
                    f.write("Calls ({} callees):\n".format(len(func_info['callees'])))
                    for callee_addr in func_info['callees']:
                        if callee_addr in addr_to_info:
                            callee_info = addr_to_info[callee_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(callee_addr),
                                callee_info['name'],
                                callee_info['filename']
                            ))
                        else:
                            callee_name = idc.get_func_name(callee_addr)
                            f.write("  - {} ({})\n".format(hex(callee_addr), callee_name))
                else:
                    f.write("Calls: none\n")

                f.write("\n")

        print("    Function index saved to: function_index.txt")

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
    
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))

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
    
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))

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
    
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))

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
        
        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))
        
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
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            
            file_count += 1
            current_addr = chunk_end
            
            # 每处理完一个chunk清理一次撤销缓冲区
            clear_undo_buffer()
    
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024*1024)))
    print("    Files created: {}".format(file_count))

def do_export(export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None):
    """执行导出操作

    Args:
        export_dir: 导出目录路径，如果为None则使用默认或询问用户
        ask_user: 是否询问用户选择目录
        skip_auto_analysis: 是否跳过等待自动分析（如果已经分析完成）
        worker_count: 并行工作线程数，默认为CPU核心数-1
    """
    global WORKER_COUNT
    
    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)
    
    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    print("[*] Using {} worker threads for parallel I/O".format(WORKER_COUNT))
    
    # 初始清理
    clear_undo_buffer()
    
    # 尝试禁用撤销功能以减少内存使用
    disable_undo()

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")

    if not skip_auto_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        print("[*] Tip: This may take a while for large files. Press Ctrl+Break to cancel.")
        
        # 在auto_wait之前清理一次
        clear_undo_buffer()
        
        ida_auto.auto_wait()
        
        # auto_wait之后立即清理
        clear_undo_buffer()
    else:
        print("[*] Skipping auto-analysis wait (assuming already complete)")

    if export_dir is None:
        idb_dir = get_idb_directory()
        default_export_dir = os.path.join(idb_dir, "export-for-ai")

        if ask_user:
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                "Export to default directory?\n\n{}\n\nYes: Use default directory\nNo: Choose custom directory\nCancel: Abort export".format(default_export_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(default_export_dir, 0, "Enter export directory path:")
                if selected_dir:
                    export_dir = selected_dir
                    print("[*] Using custom directory: {}".format(export_dir))
                else:
                    print("[*] Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)

    print("[+] Export directory: {}".format(export_dir))
    print("")

    print("[*] Exporting strings...")
    export_strings(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting imports...")
    export_imports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting exports...")
    export_exports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting memory...")
    export_memory(export_dir)
    clear_undo_buffer()
    print("")

    if has_hexrays:
        print("[*] Exporting decompiled functions...")
        print("[*] Tip: If IDA crashes, you can restart and the export will resume from where it left off")
        export_decompiled_functions(export_dir, skip_existing=True)

    # 恢复撤销功能
    enable_undo()
    
    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

    ida_kernwin.info("Export completed!\n\nOutput directory:\n{}".format(export_dir))


# ============================================================================
# Plugin Class
# ============================================================================

class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA Plugin for exporting data for AI analysis"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Export IDA data for AI analysis"
    help = "Export decompiled functions, strings, memory, imports and exports"
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        """插件初始化"""
        print("[+] Export for AI plugin loaded")
        print("    Hotkey: {}".format(self.wanted_hotkey))
        print("    Menu: Edit -> Plugins -> Export for AI")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """插件运行"""
        try:
            # 询问是否跳过自动分析（如果用户已经分析完成）
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                "Has the auto-analysis already completed?\n\n"
                "Yes: Skip waiting for auto-analysis (faster)\n"
                "No: Wait for auto-analysis to complete\n"
                "Cancel: Abort export")
            
            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                return
            
            skip_analysis = (choice == ida_kernwin.ASKBTN_YES)
            do_export(skip_auto_analysis=skip_analysis)
        except Exception as e:
            print("[!] Export failed: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        """插件卸载"""
        print("[-] Export for AI plugin unloaded")


def PLUGIN_ENTRY():
    """IDA插件入口点"""
    return ExportForAIPlugin()


# ============================================================================
# Standalone Script Support
# ============================================================================

if __name__ == "__main__":
    # 支持作为独立脚本运行（用于批处理模式）
    # IDA 9.0 兼容的参数获取方式
    export_dir = None
    skip_analysis = False
    
    try:
        # 优先使用 idc.ARGV（IDA 9.0+ 推荐方式）
        if hasattr(idc, 'ARGV') and idc.ARGV is not None and len(idc.ARGV) > 1:
            export_dir = idc.ARGV[1]
            if len(idc.ARGV) > 2:
                skip_analysis = (idc.ARGV[2] == "1")
        else:
            # 回退到 eval_idc 方式（旧版 IDA 兼容）
            argc = int(idc.eval_idc("ARGV.count"))
            if argc >= 2:
                export_dir = idc.eval_idc("ARGV[1]")
            if argc >= 3:
                skip_analysis = (idc.eval_idc("ARGV[2]") == "1")
    except:
        # 如果参数获取失败，使用默认值
        pass

    # 批处理模式不询问用户
    do_export(export_dir, ask_user=False, skip_auto_analysis=skip_analysis)

    # 脚本执行完成后自动退出IDA
    print("[*] Script execution completed, exiting IDA...")
    idc.qexit(0)
