import os
import subprocess
import time
import angr
import sys
import statistics # For mean, median
import math
# pip install lief pyelftools (if you want to calculate section entropy for ELF/PE)
# import lief
# from scipy.stats import entropy as scipy_entropy

def get_filesize(path):
    """Gets the file size in bytes."""
    return os.path.getsize(path)

def check_file_exists(path):
    """Checks if a file exists."""
    if not os.path.isfile(path):
        print(f"Error: File does not exist or is not a file: {path}")
        sys.exit(1)

def measure_runtime(executable_path):
    """Measures the execution time of an executable file."""
    print(f"Executing {os.path.basename(executable_path)}...")
    start_perf_time = time.perf_counter()
    process = None
    try:
        process = subprocess.Popen([executable_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=120) # Increase timeout if needed
        if process.returncode != 0:
            print(f"Warning: {os.path.basename(executable_path)} finished with error code {process.returncode}.")
    except subprocess.TimeoutExpired:
        print(f"Warning: {os.path.basename(executable_path)} ran too long (> 120 seconds) and was terminated.")
        if process:
            process.kill()
            process.communicate() # Clean up zombie resources
        return float('inf')
    except FileNotFoundError:
        print(f"Error: Executable file not found: {executable_path}")
        return float('nan')
    except PermissionError:
        print(f"Error: No permission to execute file: {executable_path}")
        return float('nan')
    except Exception as e:
        print(f"Unknown error while executing {executable_path}: {e}")
        return float('nan')

    end_perf_time = time.perf_counter()
    runtime = end_perf_time - start_perf_time
    return runtime

def analyze_binary_with_angr(binary_path):
    """
    Analyzes the executable file using angr to get detailed information,
    including obfuscation-centric metrics.
    """
    print(f"Analyzing {os.path.basename(binary_path)} with angr (this may take a while)...")
    analysis_results = {
        "nodes": 0, "edges": 0, "functions": 0,
        "basic_blocks": 0, "total_instructions": 0,
        "avg_fan_in": 0.0, "max_fan_in": 0,
        "avg_fan_out": 0.0, "max_fan_out": 0,
        "potential_dispatchers": 0,
        "avg_bb_instruction_count": 0.0,
        "indirect_jumps_calls": 0
    }
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        
        # For deeper obfuscation analysis, a more complete CFG might be better, but slower.
        # cfg = proj.analyses.CFGEmulated(resolve_indirect_jumps=True, context_sensitivity_level=1)
        # Or CFGFast if speed is a priority
        print(f"  Starting CFG generation for {os.path.basename(binary_path)}...")
        start_cfg_time = time.time()
        cfg = proj.analyses.CFGFast() # Keeping CFGFast for the example, can be changed to CFG() or CFGEmulated
        end_cfg_time = time.time()
        print(f"  CFG generation finished in {end_cfg_time - start_cfg_time:.2f} seconds.")

        analysis_results["nodes"] = len(cfg.graph.nodes())
        analysis_results["edges"] = len(cfg.graph.edges())
        analysis_results["functions"] = len(proj.kb.functions)
        
        if not cfg.model or not hasattr(cfg.model, 'nodes') or not cfg.graph:
             print(f"Warning: CFG model or graph is not complete for {binary_path}")
             return analysis_results # Return current results if CFG is incomplete

        all_blocks = list(cfg.model.nodes()) # Actual basic blocks in the model
        analysis_results["basic_blocks"] = len(all_blocks)

        if analysis_results["basic_blocks"] == 0:
            print(f"Warning: No basic blocks found in {binary_path} from CFG model.")
            # Still try to count instructions from functions if available
            if proj.kb and proj.kb.functions:
                for func in proj.kb.functions.values():
                    if not func.is_simprocedure and not func.is_plt:
                        for block in func.blocks:
                            try:
                                analysis_results["total_instructions"] += block.instructions
                            except: pass
            return analysis_results

        fan_ins = []
        fan_outs = []
        bb_instruction_counts = []
        
        DISPATCHER_FAN_OUT_THRESHOLD = 10 # Threshold to consider a block a dispatcher (adjustable)

        for node in cfg.graph.nodes(): # Iterate through nodes in the CFG graph
            # A node might not be an actual basic block in the binary (e.g., FakeRet)
            # So, get info from the actual block object if possible
            actual_block = cfg.model.get_any_node(node.addr, is_syscall=node.is_syscall)
            if actual_block: # Only process nodes corresponding to actual blocks
                try:
                    fan_ins.append(cfg.graph.in_degree(node))
                    current_fan_out = cfg.graph.out_degree(node)
                    fan_outs.append(current_fan_out)

                    if current_fan_out > DISPATCHER_FAN_OUT_THRESHOLD:
                        analysis_results["potential_dispatchers"] += 1
                    
                    # Count instructions and jumpkind from the block object
                    angr_block = proj.factory.block(actual_block.addr, size=actual_block.size)
                    bb_instruction_counts.append(angr_block.instructions)
                    analysis_results["total_instructions"] += angr_block.instructions
                    
                    if angr_block.vex.jumpkind == 'Ijk_Indirect':
                        analysis_results["indirect_jumps_calls"] += 1
                    # One could also check other jumpkinds like Ijk_Call, Ijk_Ret for separate stats

                except angr.AngrError as e:
                    # print(f"  Error processing block {hex(node.addr)}: {e}")
                    pass # Skip block if there's an error (e.g., can't disassemble)
                except AttributeError: # E.g., node doesn't have size, addr
                    pass

        if fan_ins:
            analysis_results["avg_fan_in"] = statistics.mean(fan_ins)
            analysis_results["max_fan_in"] = max(fan_ins)
        if fan_outs:
            analysis_results["avg_fan_out"] = statistics.mean(fan_outs)
            analysis_results["max_fan_out"] = max(fan_outs)
        if bb_instruction_counts:
            analysis_results["avg_bb_instruction_count"] = statistics.mean(bb_instruction_counts)
        
        # If total_instructions is still 0 (due to the iteration method above potentially missing some)
        # try counting via functions again as a fallback
        if analysis_results["total_instructions"] == 0 and proj.kb and proj.kb.functions:
            # print("  Retrying instruction count via functions...")
            for func in proj.kb.functions.values():
                if not func.is_simprocedure and not func.is_plt:
                    for block_obj in func.blocks:
                        try:
                            analysis_results["total_instructions"] += block_obj.instructions
                        except: pass

    except angr.AngrAnalysisError as e:
        print(f"Angr analysis error for {os.path.basename(binary_path)}: {e}")
    except Exception as e:
        print(f"Unknown error during Angr analysis of {os.path.basename(binary_path)}: {type(e).__name__} - {e}")
    
    return analysis_results

def calculate_cyclomatic_complexity(edges, nodes, components=1):
    """Calculates Cyclomatic Complexity."""
    if nodes == 0: return 0
    return edges - nodes + (2 * components)

def percent_change(before, after):
    """Calculates the percentage change, rounded to 3 decimal places."""
    if before == after: return 0.0
    if before == 0: return float('inf') if float(after) > 0 else 0.0
    try:
        change = ((float(after) - float(before)) / float(before)) * 100
        return round(change, 3)
    except ZeroDivisionError: return float('inf')
    except ValueError: return float('nan') # If 'before' or 'after' is not a number

def print_comparison(metric, before, after, unit="", higher_is_more_obfuscated=True):
    """Prints the comparison results.
    higher_is_more_obfuscated: True if a higher value means stronger obfuscation.
    """
    change = percent_change(before, after)
    sign = "+" if change >= 0 else ""

    def format_value(val):
        if val == float('inf'): return "inf"
        if val == float('nan'): return "NaN"
        if isinstance(val, float): return f"{val:.3f}" # Consistent 3 decimal places for floats
        return val

    before_str = format_value(before)
    after_str = format_value(after)

    print(f"{metric}:")
    print(f"  Before: {before_str} {unit}")
    print(f"  After : {after_str} {unit}")

    obfuscation_effect = ""
    if not isinstance(change, float) or math.isnan(change) or math.isinf(change):
        if change == float('inf'):
            obfuscation_effect = "(Significant increase - Effective obfuscation)" if higher_is_more_obfuscated else "(Significant decrease)"
        else: # NaN or other cases
            obfuscation_effect = "(Undetermined)"
    elif higher_is_more_obfuscated:
        if change > 50: obfuscation_effect = "(Significant increase - Effective obfuscation)"
        elif change > 10: obfuscation_effect = "(Increase - Obfuscated)"
        elif change < -10: obfuscation_effect = "(Decrease - Less obfuscated?)"
        else: obfuscation_effect = ""
    else: # lower_is_more_obfuscated (e.g., avg basic block size might decrease with CFF)
        if change < -50: obfuscation_effect = "(Significant decrease - Effective obfuscation)"
        elif change < -10: obfuscation_effect = "(Decrease - Obfuscated)"
        elif change > 10: obfuscation_effect = "(Increase - Less obfuscated?)"
        else: obfuscation_effect = ""

    if change == float('inf'):
        print(f"  Change: +inf% {obfuscation_effect}\n")
    elif isinstance(change, float) and math.isnan(change):
        print(f"  Change: NaN% {obfuscation_effect}\n")
    else:
        print(f"  Change: {sign}{change:.3f}% {obfuscation_effect}\n")

# Example entropy calculation function (simple, could be improved with lief)
# def calculate_section_entropy(binary_path, section_name=".text"):
#     try:
#         parsed_binary = lief.parse(binary_path) # Requires lief
#         if parsed_binary:
#             section = parsed_binary.get_section(section_name)
#             if section:
#                 data = bytes(section.content)
#                 if not data: return 0.0
#                 value_counts = [data.count(i) for i in range(256)]
#                 probabilities = [count / len(data) for count in value_counts if count > 0]
#                 # Entropy in bits, normalized to 0-1 by dividing by 8 (log2(256))
#                 return scipy_entropy(probabilities, base=2) / 8.0 # Requires scipy
#     except Exception as e:
#         # print(f"Error calculating entropy for {section_name} of {binary_path}: {e}")
#         pass
#     return 0.0

def main(file_before, file_after):
    print("=== Starting File Benchmark ===\n")
    check_file_exists(file_before)
    check_file_exists(file_after)

    # Analysis
    print("--- Analyzing file BEFORE obfuscation ---")
    res_before = analyze_binary_with_angr(file_before)
    print("\n--- Analyzing file AFTER obfuscation ---")
    res_after = analyze_binary_with_angr(file_after)
    print("\n--- Comparison Results ---")

    # 1. File Size
    size_before = get_filesize(file_before)
    size_after = get_filesize(file_after)
    print_comparison("File Size", size_before, size_after, "bytes", higher_is_more_obfuscated=True)

    # 2. Execution Time
    runtime_before = measure_runtime(file_before)
    runtime_after = measure_runtime(file_after)
    # Longer runtime usually means obfuscation overhead
    print_comparison("Execution Time", runtime_before, runtime_after, "seconds", higher_is_more_obfuscated=True)

    # 3. Metrics from Angr
    print_comparison("CFG Nodes", res_before["nodes"], res_after["nodes"], higher_is_more_obfuscated=True)
    print_comparison("CFG Edges", res_before["edges"], res_after["edges"], higher_is_more_obfuscated=True)
    
    complexity_before = calculate_cyclomatic_complexity(res_before["edges"], res_before["nodes"])
    complexity_after = calculate_cyclomatic_complexity(res_after["edges"], res_after["nodes"])
    print_comparison("Cyclomatic Complexity (Total)", complexity_before, complexity_after, higher_is_more_obfuscated=True)

    # Number of functions might decrease if CFF merges them, or Angr's function identification is affected
    print_comparison("Number of Functions (Angr)", res_before["functions"], res_after["functions"], higher_is_more_obfuscated=False) 
    print_comparison("Number of Basic Blocks", res_before["basic_blocks"], res_after["basic_blocks"], higher_is_more_obfuscated=True)
    print_comparison("Estimated Total Assembly Instructions", res_before["total_instructions"], res_after["total_instructions"], higher_is_more_obfuscated=True)
    
    # "Obfuscation-centric" metrics
    print_comparison("Avg CFG Fan-in", res_before["avg_fan_in"], res_after["avg_fan_in"], unit="edges/node", higher_is_more_obfuscated=True) # CFF might increase locally
    print_comparison("Max CFG Fan-in", res_before["max_fan_in"], res_after["max_fan_in"], unit="edges", higher_is_more_obfuscated=True)
    print_comparison("Avg CFG Fan-out", res_before["avg_fan_out"], res_after["avg_fan_out"], unit="edges/node", higher_is_more_obfuscated=True) # CFF increases this significantly
    print_comparison("Max CFG Fan-out", res_before["max_fan_out"], res_after["max_fan_out"], unit="edges", higher_is_more_obfuscated=True) # Dispatcher indicator
    print_comparison("Potential Dispatcher Blocks (Fan-out > 10)", res_before["potential_dispatchers"], res_after["potential_dispatchers"], higher_is_more_obfuscated=True)
    
    # Avg BB size might decrease if CFF splits blocks, or increase with junk code.
    # Careful interpretation of higher_is_more_obfuscated for this metric is needed.
    print_comparison("Avg Instructions/Basic Block", res_before["avg_bb_instruction_count"], res_after["avg_bb_instruction_count"], unit="instrs/BB", higher_is_more_obfuscated=False) 
    
    print_comparison("Number of Indirect Jumps/Calls", res_before["indirect_jumps_calls"], res_after["indirect_jumps_calls"], higher_is_more_obfuscated=True)

    # Example entropy calculation (uncomment if lief and scipy are installed)
    # entropy_before = calculate_section_entropy(file_before)
    # entropy_after = calculate_section_entropy(file_after)
    # print_comparison(".text Section Entropy (0-1)", entropy_before, entropy_after, higher_is_more_obfuscated=True)

    print("=== Benchmark Complete ===")

if __name__ == "__main__":
    file_before_default = "path/to/your/original_binary.exe" # Example
    file_after_default = "path/to/your/obfuscated_binary.exe" # Example
    try:
        # Try to read paths from a simple config file (e.g., last_paths.txt)
        with open("last_paths.txt", "r") as f:
            file_before_default = f.readline().strip()
            file_after_default = f.readline().strip()
    except FileNotFoundError:
        pass # It's okay if the file doesn't exist, use hardcoded defaults

    file_before_input = input(f"Enter path to original binary (default: {file_before_default}): ").strip()
    file_after_input = input(f"Enter path to obfuscated binary (default: {file_after_default}): ").strip()

    file_before = file_before_input if file_before_input else file_before_default
    file_after = file_after_input if file_after_input else file_after_default

    # Save the used paths for the next run
    try:
        with open("last_paths.txt", "w") as f:
            f.write(file_before + "\n")
            f.write(file_after + "\n")
    except IOError:
        print("Warning: Could not save file paths for the next run.")

    if not os.path.isfile(file_before):
        print(f"Error: Original file is invalid: '{file_before}'")
        sys.exit(1)
    if not os.path.isfile(file_after):
        print(f"Error: Obfuscated file is invalid: '{file_after}'")
        sys.exit(1)

    main(file_before, file_after)