#!/usr/bin/python3
# This script transforms the data taken from taenia through track_paths.py into colors for idapython.
# In Ida, the functions executed are colored in the function list, blocks and lines executed are colored in the main view.

import idautils
import json



# Model =======================================================================

# Status
STATUS_NEW = 0x1
STATUS_HANG = 0x2
STATUS_CRASH = 0x4

class InternalFunc:
    def __init__(self, ida_func):
        self.ida_func = ida_func
        self.iterations = 0
        self.status = 0

    def maybe_inc_status(self, status):
        if status > self.status:
            self.status = status

    def maybe_inc_iterations(self, iterations):
        if iterations > self.iterations:
            self.iterations = iterations



# Parsing =====================================================================

def check_arch(arch):
    '''Check that the real arch is similar to the one for the input_file.'''
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16

    try:
        is_be = info.is_be()
    except:
        is_be = info.mf

    if is_be:
        endian = "big"
    else:
        endian = "little"
    print("[+] Processor: {0}, {1}bit, {2} endian".format(info.procName, bits, endian))

    if (bits == 64 and arch != "x64") or (bits == 32 and arch != "x86"):
        print("[-] Wrong architecture: ida processor is {0}bit, trace is {1}.".format(bits, arch))
        return False
    return True


def parse_path_info(input_file):
    '''Parse the path addresses exported from track_paths.py.'''
    with open(input_file, 'r') as f:
        data = json.loads(f.read())
        if not check_arch(data["arch"]):
            data = None
    print("[+] Parsing done.")
    return data




# Colors ======================================================================

def reset_function_colors(func):
    '''Reset the colors of a function: in the function list and the function blocks.'''
    func.color = 0xffffff
    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        color_block(block, 0xffffff, func.start_ea)


def reset_colors():
    '''Reset all colors in ida.'''
    heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
    for h in heads:
        SetColor(h, CIC_ITEM, 0xFFFFFF)

    for addr in idautils.Functions():
        func = idaapi.get_func(addr)
        reset_function_colors(func)

    idaapi.refresh_lists()
    idaapi.refresh_idaview_anyway()
    print("[+] Colors reset.")


def get_new_color(iteration, status, inc=0):
    '''Get a color adapted to the number of times the block has been used and the kind of path.'''
    reds = [0x7575ff, 0x6565ef]
    oranges = [0x00aaff, 0x0099ee]
    greens = [0x8fffc5, 0x7fefb5]
    blues = [0xffffff, 0xf09060, 0xc87850, 0xa06040, 0x784830, 0x503020]

    if status & STATUS_CRASH == STATUS_CRASH :
        return reds[inc]

    elif status & STATUS_HANG == STATUS_HANG:
        return oranges[inc]

    elif status & STATUS_NEW == STATUS_NEW:
        return greens[inc]

    # From white to dark blue.
    if iteration == 0:
        return blues[0 + inc]
    if iteration <= 1:
        return blues[1 + inc]
    if iteration <= 10:
        return blues[2 + inc]
    if iteration <= 100:
        return blues[3 + inc]
    if iteration > 100:
        return blues[3 + inc]
    return 0xffffff


def color_block(block, color, func_addr):
    '''Color a block in the flowchart.'''
    node_info = idaapi.node_info_t()
    node_info.bg_color = color
    idaapi.set_node_info2(func_addr, block.id, node_info, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
    # Color lines
    for address in range(block.start_ea, block.end_ea):
        SetColor(address, CIC_ITEM, color)



# Execution ===================================================================

def colorize(blocks):
    '''Apply the colors.'''
    reset_colors()

    functions =[]
    prev_func_start_ea = -1
    func = None
    # Color blocks and parse functions
    for block in blocks:
        address = block["Address"]
        iterations = block["Iterations"]
        status = block["Status"]
        #print("\t{0}: {1} - {2}".format(hex(address), str(iterations), str(status)))
        color = get_new_color(iterations, status)

        # Managing ida functions
        ida_func = idaapi.get_func(address)
        if ida_func is None:
            print("[-] Function {0} not found, maybe your trace was not generated with the right arch.".format(hex(address)))
        else:
            if ida_func.start_ea != prev_func_start_ea:
                prev_func_start_ea = ida_func.start_ea
                found_it = False
                for f in functions:
                    if f.ida_func.start_ea == ida_func.start_ea:
                        found_it = True
                        func = f
                        break
                if not found_it:
                    func = InternalFunc(ida_func)
                    functions.append(func)

            func.maybe_inc_status(status)
            func.maybe_inc_iterations(iterations)

            # Adding colors in flowchart
            flow_chart = idaapi.FlowChart(ida_func)
            for ida_block in flow_chart:
                if ida_block.start_ea <= address and ida_block.end_ea > address:
                    # Found the right block.
                    color_block(ida_block, color, ida_func.start_ea)
                    found_it = True
                    break

    # Color functions
    for func in functions:
        func_color = get_new_color(func.iterations, func.status)
        func.ida_func.color = func_color

    # Color lines
    for block in blocks:
        address = block["Address"]
        iterations = block["Iterations"]
        status = block["Status"]
        color = get_new_color(iterations, status, 1)

        SetColor(address, CIC_ITEM, color)


    idaapi.refresh_lists()
    idaapi.refresh_idaview_anyway()
    print("[+] Coloring done.")



# Useful functions ============================================================

def list_threads(data):
    if data is None:
        print("[-] No data.")
        return
    for thread in data["Threads"]:
        print(thread["Thid"])


def color_thread(data, thid):
    if data is None:
        print("[-] No data.")
        return
    for thread in data["Threads"]:
        if thread["Thid"] == thid:
            colorize(thread["Blocks"])
            break
    else:
        print("[-] Thread id {0} not found.".format(thid))


def color_path(data, status, path_id):
    '''Status must be: path, crash or hang.'''
    if data is None:
        print("[-] No data.")
        return
    if "{0} {1}".format(status, path_id) not in data.keys():
        print("Path not found.")
        return
    colorize(data["{0} {1}".format(status, path_id)]["Blocks"])


def color_meta_path(data):
    if data is None:
        print("[-] No data.")
        return
    colorize(data["Meta path"]["Blocks"])



# Illustration ================================================================
INPUT_FILE = "<path to export_for_ida>"
data = parse_path_info(INPUT_FILE)
color_meta_path(data)

