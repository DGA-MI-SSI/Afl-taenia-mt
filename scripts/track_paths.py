#!/usr/bin/python3
#
# Disclaimer: this is highly experimental. I use it for debug purposes.
# It works for me on smart_sample, it might work in other cases.
#
# Parse the log file in order to rebuild the paths traversed in the target.
# Need a full run of afl-taenia built in DEBUG_PATH mode (-p option for build.sh).
# Produce path/svg/path.svg that hold all the paths encountered during execution.
# Produce a path-<i>.svg in path/svg/ for each path i.
# Dot file are saved in path/dot.


import capstone
import copy
import json
import os
import shutil
import string
import sys
import time

from elftools.elf.elffile import ELFFile
from optparse import OptionParser


print("Track_paths")

OFFSET     = 0
d_cur_address = dict()  # Link between afl cur_loc and real address. Made at trace generation.



# Model =======================================================================

# Status
STATUS_NEW = 0x1
STATUS_HANG = 0x2
STATUS_CRASH = 0x4


class Block:
    '''A block, it may be a new block, or being linked to a crash or a hang.'''

    all_block_addresses = []    # Keep them in order to detect same blocks in different threads.
    def __init__(self, address, thid, status=0):
        self.address = address
        self.thid = thid
        self.status = status
        self.iterations = 1

    def set_status(self, status):
        self.status |= status

    def is_new(self):
        return (self.status & STATUS_NEW) == STATUS_NEW

    def has_hanged(self):
        return (self.status & STATUS_HANG) == STATUS_HANG

    def has_crashed(self):
        return (self.status & STATUS_CRASH) == STATUS_CRASH

    def get_color(self, new=False):
        color = "white"
        if self.has_crashed():
            color = "red"
        elif self.has_hanged():
            color = "orange"
        elif self.is_new():
            if new:
                color = "green"
        return color


class FunctionBlock:
    '''A function, it contains blocks of code.'''
    def __init__(self, name, start_ea, end_ea):
        self.name = name
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.blocks = []

    def add_block(self, block):
        self.blocks.append(block)

    def add_or_update_block(self, block, update_iteration=True):
        for b in self.blocks:
            if b.address == block.address:
                if update_iteration:
                    b.iterations += block.iterations
                b.set_status(block.status)
                return
        else:
            self.add_block(block)

    def add_or_update_blocks(self, blocks):
        '''Used to update recursively the meta_path.'''
        for block in blocks:
            for b in self.blocks:
                if b.address == block.address:
                    b.iterations += block.iterations
                    b.set_status(block.status)
                    break
            else:
                self.add_block(copy.deepcopy(block))
                if block.address not in Block.all_block_addresses:
                    block.set_status(STATUS_NEW)
                    Block.all_block_addresses.append(block.address)

    def set_new(self):
        for block in self.blocks:
            if block.address not in Block.all_block_addresses:
                block.set_status(STATUS_NEW)
                Block.all_block_addresses.append(block.address)


class ThreadBlock:
    '''A thread meta-block, it contains functions meta-blocks.'''
    def __init__(self, thid):
        self.thid = thid
        self.functions = [FunctionBlock("", 0, 0)] # Default function

    def add_function(self, function):
        self.functions.append(function)

    def has_function(self, function):
        for f in self.functions:
            if f.name == function.name:
                return True
        return False

    def get_function(self, block):
        for f in self.functions:
            if f.start_ea <= block.address and block.address < f.end_ea:
                return f
        else:
            for f in common_functions:
                if f.start_ea <= block.address and block.address < f.end_ea:
                    function = FunctionBlock(f.name, f.start_ea, f.end_ea)
                    self.functions.append(function)
                    return function
        return self.functions[0] # Default function

    def add_function_if_new(self, function):
        if not self.has_function(function):
            self.add_function(function)

    def add_or_update_functions(self, functions):
        '''Used to update recursively the meta_path.'''
        for function in functions:
            for f in self.functions:
                if f.name == function.name:
                    f.add_or_update_blocks(function.blocks)
                    break
            else:
                self.add_function(copy.deepcopy(function))
                function.set_new()

    def set_new(self):
        for function in self.functions:
            function.set_new()


class Transition:
    ''' A transition is the number of time a jump is taken from a start block to an end block.'''

    def __init__(self, start, end, status=0):
        self.start = start
        self.end = end
        self.iterations = 1
        self.status = status

    def set_status(self, status):
        self.status |= status

    def is_new(self):
        return (self.status & STATUS_NEW) == STATUS_NEW

    def has_hanged(self):
        return (self.status & STATUS_HANG) == STATUS_HANG

    def has_crashed(self):
        return (self.status & STATUS_CRASH) == STATUS_CRASH

    def get_color(self, new=False):
        color = "black"
        if self.has_crashed():
            color = "red"
        elif self.has_hanged():
            color = "orange"
        elif self.is_new():
            if new:
                color = "green"
        return color


class Path:
    '''A path is a list of transitions.'''

    path_index = 1
    crash_index = 1
    hang_index = 1
    def __init__(self, value=None):
        self.value = value
        self.status = None
        self.index = 0
        self.threads = []
        self.transitions = []

    def set_status(self, status):
        if self.status is not None:
            # Already done, skip.
            return
        self.status = status


    def add_to_queue_if_unique(self, queue):
        for p in queue:
            if p.value == self.value:
                return
        else:
            # We want and index dependent on the status
            if self.status == "path":
                self.index = Path.path_index
                Path.path_index += 1
            elif self.status == "crash":
                self.index = Path.crash_index
                Path.crash_index += 1
            elif self.status == "hang":
                self.index = Path.hang_index
                Path.hang_index += 1
            queue.append(self)


    def add_thread(self, thread):
        self.threads.append(thread)

    def add_or_update_threads(self, threads):
        '''Used to update recursively the meta_path.'''
        for thread in threads:
            for t in self.threads:
                if t.thid == thread.thid:
                    t.add_or_update_functions(thread.functions)
                    break
            else:
                self.add_thread(copy.deepcopy(thread))
                thread.set_new()

    def get_or_make_thread(self, thid):
        for t in self.threads:
            if t.thid == thid:
                return t
        else:
            t = ThreadBlock(thid)
            self.add_thread(t)
            return t

    def add_transition(self, transition):
        self.transitions.append(transition)

    def inc_transition(self, transition):
        for t in self.transitions:
            if t.start == transition.start and t.end == transition.end:
                t.iterations += transition.iterations
                t.status |= transition.status
                return

    def add_or_inc_transition(self, transition, mark_new=False):
        '''Used to update the metapath's transitions.'''
        for t in self.transitions:
            if t.start is None or transition.start is None:
                if t.start == transition.start and t.end.address == transition.end.address:
                    if t.end.thid == transition.end.thid:
                        t.iterations += transition.iterations
                        t.status |= transition.status
                        return
                    else:
                        self.add_transition(transition)
                        return
            elif t.start.address == transition.start.address and t.end.address == transition.end.address:
                if t.start.thid == transition.start.thid and t.end.thid == transition.end.thid:
                    t.iterations += transition.iterations
                    t.status |= transition.status
                    return
                else:
                    self.add_transition(transition)
                    return
        else:
            if mark_new:
                transition.set_status(STATUS_NEW)
            self.add_transition(transition)

    def add_or_inc_transitions_and_mark_new(self, transitions):
        for transition in transitions:
            self.add_or_inc_transition(transition, True)



# Parsing elf =================================================================

NO_FUNCTION = 0
FUNCTION_ADDRESS = 1
FUNCTION_SYMBOL = 2

common_functions = []  # Info for all functions.
def parse_elf(binary_file, arch):
    '''Parse an elf file to extract all functions. It first parses the .symtab in order to get the binary's symbols (if it's not stripped). Then it parses the .plt to get imported symbols.'''

    print("\t[+] Parsing elf file.")
    with open(binary_file, 'rb') as f:
        elf = ELFFile(f)

        real_arch = elf.get_machine_arch()
        print("\t[+] Arch is {0}".format(real_arch))
        if real_arch != arch:
            print("\t[-] This is not the architecture specified.")
            exit(0)

        symtab = elf.get_section_by_name(".symtab")
        plt = elf.get_section_by_name(".plt")
        if symtab is None:
            print("\t[-] No symtab, can't get symbols.")
        else:
            print("\t[+] Searching symbols in .symtab.")
            for symbol in symtab.iter_symbols():
                if symbol.entry["st_size"] > 0:
                    common_functions.append(FunctionBlock(symbol.name,
                                 symbol.entry["st_value"],
                                 symbol.entry["st_value"] + symbol.entry["st_size"]))
                    print("\t\tFunction found: {0} ({1},{2})".format(symbol.name, hex(symbol.entry["st_value"]), hex(symbol.entry["st_value"] + symbol.entry["st_size"])))

        plt = elf.get_section_by_name('.plt')
        if plt is None:
            print("\t[-] No plt, can't get imported symbols.")
        else:
            print("\t[+] Searching symbols in .plt.")
            # Linking rela_plt real addresses to symbols.
            rela_plt = None
            if arch == "x64":
                rela_plt = elf.get_section_by_name(".rela.plt")
                relocs = dict()
                for reloc in rela_plt.iter_relocations():
                    symtable = elf.get_section(rela_plt['sh_link'])
                    sym = symtable.get_symbol(reloc['r_info_sym'])
                    relocs[reloc['r_offset']] = sym.name

                # Linking plt addresses to symbols.
                # Warning, this section is highly experimental.

                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                function_name = ".plt"
                function_start_address = plt.header["sh_addr"]
                function_end_address = plt.header["sh_addr"]
                for ins in md.disasm(plt.data(), plt.header["sh_addr"]):
                    # capstone gives:
                    # jmp	qword ptr [rip + 0x20236a]
                    if ins.mnemonic == "jmp":
                        #print("{0}:\t{1}\t{2}".format(hex(ins.address), ins.mnemonic, ins.op_str))
                        if "rip + " in ins.op_str:
                            offset = ins.op_str.split("rip + ")[1][:-1]
                            if offset is not None:
                                offset = int(offset, 16) + ins.address + 6
                                if offset in relocs.keys():
                                    function_name = relocs[offset]
                                    function_start_address = ins.address
                        else:
                            function_end_address = ins.address
                            print("\t\tFunction imported: {0} ({1}:{2})".format(function_name, hex(function_start_address), hex(function_end_address)))
                            common_functions.append(FunctionBlock(function_name,
                                    function_start_address,
                                    function_end_address))

            elif arch == "x86":
                rela_plt = elf.get_section_by_name(".rel.plt")
                relocs = []
                for reloc in rela_plt.iter_relocations():
                    symtable = elf.get_section(rela_plt['sh_link'])
                    sym = symtable.get_symbol(reloc['r_info_sym'])
                    relocs.append(sym.name)

                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                function_name = ".plt"
                function_start_address = plt.header["sh_addr"]
                function_end_address = plt.header["sh_addr"]
                index = 0
                for ins in md.disasm(plt.data(), plt.header["sh_addr"]):
                    # capstone gives:
                    if ins.mnemonic == "jmp":
                        if "ebx + " in ins.op_str:
                            # Here we assume that the relocs are in the same order in rel and in plt.
                            function_name = relocs[index]
                            function_start_address = ins.address
                        else:
                            function_end_address = ins.address
                            print("\tFunction imported: {0} ({1}:{2})".format(function_name, hex(function_start_address), hex(function_end_address)))
                            common_functions.append(FunctionBlock(function_name,
                                    function_start_address,
                                    function_end_address))
                            index += 1
        print("\t[+] Elf file parsed, symbols retrieved.")
        #for f in common_functions:
        #    print("Function {0}: {1}-{2}".format(f.name, f.start_ea, f.end_ea))
        return True


def check_function_use(metapath):
    '''Check that the function we parsed are used in the model. If it is not the case, we may have a problem.'''
    block_in_functions = 0
    for thread in metapath.threads:
        for function in thread.functions[1:]: # Skip the default one.
            block_in_functions += len(function.blocks)
    if block_in_functions == 0:
        print("\t[!] None of the function we parsed were used, maybe you did not use the right arch.")


# Parsing =====================================================================

def b2s(bstr):
    '''Transform a b'Qwerty' into Qwerty.'''
    return str(bstr)[2:-1].replace(' ', '')


def brief_parse(data, dumb):
    '''Clean useless logs. Must be fast.'''
    total_data = []
    input_data = []
    preload = True
    for line in data:
        # thid|command|payload
        fields = line.split(b"|")
        if len(fields) < 2:
            if len(line) > 0:
                # Input that span over several lines.
                input_data.append(line)
            continue
        command = fields[1]
        if command == b"Inp":
            if dumb and not preload:
                # In dumb mode, we track paths neither new, nor crash, nor timeout.
                total_data.append(input_data)
            preload = False

            # New input, we clean
            input_data = []
            input_data.append(line)
        elif command == b"New": # New path
            input_data.append(line)
            total_data.append(input_data)
        elif command == b"Crash":
            input_data.append(line)
            total_data.append(input_data)
        elif command == b"Timeout":
            input_data.append(line)
            total_data.append(input_data)
        elif command == b"Gen":
            # Gen|<address>, <cur_loc>
            payload = fields[2]
            data = payload.split(b", ")
            d_cur_address[data[1]] = data[0]
        else:
            input_data.append(line)

    if dumb:
        # Last dumb path.
        total_data.append(input_data)

    # We keep logs that were not finished for ulterior parsing.
    return total_data, d_cur_address, input_data


def parse(meta_path, queue, data, d_cur_address, display_threads):
    '''Transform the logs in the model information.'''

    for inp in data:
        prev_block = None
        cur_path = Path()
        for line in inp:
            if b"|" not in line:
                # Input that span over several lines.
                cur_path.value += b2s(line)
                continue

            fields = line.split(b"|")
            thid = 0
            try:
                thid = int(fields[0], 10)
            except:
                # Inputs from afl may also fuzz this script/
                print("\t[-] Error: invalid format: {0}".format(line))
                continue
            command = fields[1]

            if not display_threads:
                # If we don't want to see threads, we set the thid to 0 so all blocks will be in the same thread.
                thid = 0

            cur_thread = cur_path.get_or_make_thread(thid)

            # Path management
            if command == b"Inp":
                # Inp|<value>
                cur_path.value = b2s(fields[2])

            elif command == b"Exe":
                # Exe|<cur_loc>, <idx>
                payload = fields[2]
                data = payload.split(b", ")
                cur_address = b2s(d_cur_address[data[0]])
                cur_block = Block(int(cur_address, 16) - OFFSET, int(thid))

                cur_function = cur_thread.get_function(cur_block)
                cur_function.add_or_update_block(cur_block)

                cur_transition = Transition(prev_block, cur_block)
                cur_path.add_or_inc_transition(cur_transition)

                prev_block = cur_block

            elif command == b"New":
                # May occur after a "Crash" or "Timeout"
                cur_path.set_status("path")
                break

            elif command == b"Crash":
                # The last transition provoked a crash.
                cur_transition.set_status(STATUS_CRASH)
                cur_block.set_status(STATUS_CRASH)
                cur_path.add_or_inc_transition(cur_transition)
                cur_path.set_status("crash")
                break

            elif command == b"Timeout":
                cur_transition.set_status(STATUS_HANG)
                cur_block.set_status(STATUS_HANG)
                cur_path.add_or_inc_transition(cur_transition)
                cur_function.add_or_update_block(cur_block, False)   # Sometimes, timeout forgets to add blocks.
                cur_path.set_status("hang")
                break

            else:
                print("\t[-] Error: wrong command: {0}.".format(command))
                continue

        cur_path.add_to_queue_if_unique(queue)
        meta_path.add_or_inc_transitions_and_mark_new(cur_path.transitions)
        meta_path.add_or_update_threads(cur_path.threads)
    return meta_path, queue


def parse_logs(meta_path, queue, filename, display_threads, dumb, kept_logs=[]):
    '''Parse the given logfile into the defined model.'''
    remaining_logs = []

    with open(filename, 'rb') as f:
        data, d_cur_address, remaining_logs = brief_parse(kept_logs + f.read().split(b"\n"), dumb)
        parse(meta_path, queue, data, d_cur_address, display_threads)

    print("\t[+] Parsing done.")
    return remaining_logs



# Graph generation ============================================================


def clean_string(string):
    cleaned_value = ""
    forbidden_chars = ["\"", "\n", "."]
    # Cleaning the value from all weird non-printable chars.
    if string is None:
        return "<None>"
    for c in string:
        if c in forbidden_chars:
            cleaned_value += "_"
        else:
            cleaned_value += c
    return cleaned_value


def generate_graph(path, display_threads, meta_path=False):
    '''Transform a path into a dot file, then generate it in svg.'''
    filename = ""
    new = True
    if meta_path:
        filename = "meta_path"
        new = False     # Don't mark new paths/blocks.
    else:
        filename = "{0}-{1}".format(path.status, path.index)

    with open("paths/dot/{0}.dot".format(filename), 'w') as f:

        cleaned_value = clean_string(path.value)

        data = "digraph D {\n"
        data += "\tnode [shape=\"record\"];\n"
        data += "\tcompound = true;\n"  # For inter-cluster links.
        data += "\t\"{0}\" [fillcolor=\"lightblue\", style=\"filled\"];\n".format(cleaned_value)

        for thread in path.threads:
            if display_threads:
                data += "\tsubgraph cluster_th_{0}".format(thread.thid) + " {\n"
                data += "\t\tlabel = \"Thread {0}\";\n".format(thread.thid)
            for function_index in range(len(thread.functions)):
                function = thread.functions[function_index]
                if function_index != 0: # Not default function
                    data += "\t\tsubgraph cluster_th_{0}_fun_{1}".format(thread.thid, clean_string(function.name)) + " {\n"
                    data += "\t\t\tlabel = \"Function {0}\";\n".format(function.name)
                for block in function.blocks:
                    data += "\t\t\tth_{0}_blk_{1} [label=\"{1}\", fillcolor=\"{2}\", style=\"filled\"];\n".format(
                            thread.thid,
                            hex(block.address),
                            block.get_color(new))
                if function_index != 0:
                    data += "\t\t}\n"
            if display_threads:
                data += "\t}\n"

        transition_index = 1
        for transition in path.transitions:
            label = transition_index
            if meta_path:
                label = transition.iterations
            if transition.start is None:
                data += "\t\"{0}\" -> th_{1}_blk_{2} [label=\"{3}\" color=\"{4}\"];\n".format(
                            cleaned_value,
                            transition.end.thid,
                            hex(transition.end.address),
                            label,
                            transition.get_color(new))
                    
            else:
                data += "\tth_{0}_blk_{1} -> th_{2}_blk_{3} [label=\"{4}\" color=\"{5}\"];\n".format(
                            transition.start.thid,
                            hex(transition.start.address),
                            transition.end.thid,
                            hex(transition.end.address),
                            label,
                            transition.get_color(new))
            transition_index += 1

        data += "\n}"
        f.write(data)
    os.system("dot -Tsvg paths/dot/{0}.dot > paths/svg/{0}.svg".format(filename))


def clean_dirs():
    '''Remove the required dirs.'''
    try:
        shutil.rmtree("paths")
    except: # If paths does not exist
        return


def make_dirs():
    '''Make the required dirs.'''
    os.mkdir("paths")
    os.mkdir("paths/dot")
    os.mkdir("paths/svg")


def generate_graphs(meta_path, queue, display_threads):
    '''Transform all paths in graphs, starting with the meta_path.'''
    print("\t[+] Generating graphs (If you see 'Error: trouble in init_rank' below, you should upgrade graphviz).")
    generate_graph(meta_path, display_threads, True)

    # Generate one graph per queued input.
    for path in queue:
        generate_graph(path, display_threads)

    print("\t[+] Graphs generated.")


# Export for idapython ========================================================

def export_path(path, binary_offset, no_new=False):
    data = dict()
    transitions = []
    for transition in path.transitions:
        btrans = dict()
        status = transition.status

        if no_new:
            # We don't want the new paths
            status &= ~STATUS_NEW

        start_address = 0
        if transition.start is not None:
            start_address = transition.start.address

        btrans["Start"] = start_address - binary_offset
        btrans["End"] = transition.end.address - binary_offset
        btrans["Iterations"] = transition.iterations
        btrans["Status"] = status
        transitions.append(btrans)
    data["Transitions"] = transitions

    blocks = []
    for thread in path.threads:
        bthr = dict()
        bthr["Thid"] = thread.thid
        bthr["Blocks"] = []

        for function in thread.functions:
            for block in function.blocks:
                bdict = dict()
                status = block.status

                if no_new:
                    # We don't want the new paths
                    status &= ~STATUS_NEW

                bdict["Address"] = block.address - binary_offset
                bdict["Iterations"] = block.iterations
                bdict["Status"] = status
                blocks.append(bdict)
    data["Blocks"] = blocks

    return data


def export_to_idapython(meta_path, queue, arch, binary_offset):
    if (meta_path.transitions) == 0:
        print("\t[-] Error: no transitions.")
        sys.exit(0)

    with open("paths/export_for_ida", 'w') as f:
        data = dict()

        data["arch"] = arch

        # Export paths
        data["Meta path"] = export_path(meta_path, binary_offset, True)

        for path in queue:
            data["{0} {1}".format(path.status, path.index)] = export_path(path, binary_offset)

        # Export threads
        threads = []
        for thread in meta_path.threads:
            bthr = dict()
            bthr["Thid"] = thread.thid
            bthr["Blocks"] = []

            for function in thread.functions:
                for block in function.blocks:
                    bdict = dict()
                    status = block.status
                    status &= ~STATUS_NEW
                    
                    bdict["Address"] = block.address - binary_offset
                    bdict["Iterations"] = block.iterations
                    bdict["Status"] = status

                    bthr["Blocks"].append(bdict)
            threads.append(bthr)
        data["Threads"] = threads

        f.write(json.dumps(data))

    print("\t[+] Export done, you will find the exported file in 'paths/export_for_ida'.")



# Parsing options =============================================================

parser = OptionParser()
parser.add_option("-a", "--arch", dest="arch", default="x64", help="Architecture of the target, either x86 or x64.")
parser.add_option("-b", "--base-offset", dest="base_offset", default=None, help="Base memory offset of the process (difference between objdump and process address layout), in base 16.")
parser.add_option("-c", "--continuous", dest="continuous", default=False, action="store_true", help="Continuously parse the file (every 10s) and clean it.")
parser.add_option("-d", "--dumb", dest="dumb", default=False, action="store_true", help="Enable dumb mode. In dumb mode, all pahts taken are tracked, even those that are not saved by afl.")
parser.add_option("-f", "--file", dest="binary_file", default="", help="The binary file targeted. Used to display the functions as clusters.")
parser.add_option("-g", "--graph", dest="make_graph", default=False, action="store_true", help="Generate svg graphs that shows the pathes that were taken.")
parser.add_option("-i", "--ida", dest="export_to_ida", default=False, action="store_true", help="Export the paths to ida, in order to color the basic blocks taken.")
parser.add_option("-l", "--log-file", dest="log_file", default="/dev/shm/afl_debug_path", help="Log file that will be parsed.")
parser.add_option("-o", "--offset", dest="binary_offset", default="0", help="Offset between IDA and objdump.")
parser.add_option("-t", "--no-thread", dest="display_threads", action="store_false", default=True, help="Display the threads as clusters.")
(options, args) = parser.parse_args()

if options.arch == "x64":
    OFFSET = 0x4000000000   # Offset from qemu for x64
else:
    OFFSET = 0xffffa000     # Offset from qemu for x86

if options.base_offset != None:
    OFFSET = int(options.base_offset, 16)
print("\t[*] Base offset is {0}.".format(hex(OFFSET)))

if options.binary_file != "":
    parse_elf(options.binary_file, options.arch)

if options.continuous:
    # Repeat the action continuously
    queue = []              # Our vision of the queue, a list of Tescases.
    meta_path = Path("Start")   # Hold all paths found so far.
    i = 1
    kept_logs = []

    while True:
        print("[+] Parsing file, iteration {0}.".format(i))
        try:
            os.rename(options.log_file, options.log_file + ".tmp")
        except:
            print("\t[!] File {0} not found, skipping.".format(options.log_file))
            time.sleep(10)
            continue
        remaining_logs = parse_logs(meta_path, queue, options.log_file + ".tmp", options.display_threads, options.dumb, kept_logs)
        kept_logs = remaining_logs
        check_function_use(meta_path)

        if options.make_graph:
            clean_dirs()
            make_dirs()
            generate_graphs(meta_path, queue, options.display_threads)
        if options.export_to_ida:
            export_to_idapython(meta_path, queue, options.arch, int(options.binary_offset, 16))

        print("\t[+] Queue size: {0}.".format(len(queue)))

        os.remove(options.log_file + ".tmp")
        i += 1
        time.sleep(10)

else:
    # One-shot
    queue = []              # Our vision of the queue, a list of Tescases.
    meta_path = Path("Start")   # Hold all paths found so far.
    remaining_logs = parse_logs(meta_path, queue, options.log_file, options.display_threads, options.dumb)
    check_function_use(meta_path)

    if options.make_graph:
        clean_dirs()
        make_dirs()
        generate_graphs(meta_path, queue, options.display_threads)
    if options.export_to_ida:
        export_to_idapython(meta_path, queue, options.arch, int(options.binary_offset, 16))

