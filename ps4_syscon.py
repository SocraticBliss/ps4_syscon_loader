#!/usr/bin/env python
'''
PS4 Syscon Loader by SocraticBliss (R)
Dedicated to zecoxao <3
ps4_syscon_loader.py: IDA loader for reading Sony PlayStation(R) 4 Syscon Firmware files
'''

from idaapi import *
from idc import *

import idaapi as ida
import idc

# Load Processor Details...
def processor(processor):
    
    # Processor
    idc.set_processor_type(processor, SETPROC_LOADER)
    
    # Assembler
    idc.set_target_assembler(0x0)
    
    # Compiler
    idc.set_inf_attr(INF_COMPILER, COMP_GNU)
    
    # Loader Flags
    idc.set_inf_attr(INF_LFLAGS, LFLG_PC_FLAT | LFLG_COMPRESS)
    
    # Assume GCC3 names
    idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3)
    
    # Analysis Flags
    idc.set_inf_attr(INF_AF, 0xBFFFBFFF)

# Pablo's Function Search...
def function_search(mode, search, address = 0):
    
    while address < BADADDR:
        address = ida.find_binary(address, BADADDR, search, 0x10, SEARCH_DOWN)
        if address < BADADDR:
            address += mode
            ida.del_items(address, 0)
            ida.add_func(address, BADADDR)
            address += 1

# Load Segment Details...
def segment(f, start, end, name, type = 'DATA', perm = SEGPERM_MAXVAL):
    
    f.file2base(start, start, end, FILEREG_PATCHABLE)
    ida.add_segm(0x0, start, end, name, type, 0x0)
    
    # Processor Specific Segment Details
    idc.set_segm_addressing(start, 0x1)
    idc.set_segm_alignment(start, saAbs)
    idc.set_segm_combination(start, scPriv)
    idc.set_segm_attr(start, SEGATTR_PERM, perm)


# PROGRAM START

# Open File Dialog...
def accept_file(f, n):
    
    try:
        if not isinstance(n, (int, long)) or n == 0:
            return 'PS4 - Syscon Full Firmware' if f.read(4) == '\x80\x01\xFF\xFF' else 0
    
    except:
        pass

# Load Input Binary...
def load_file(f, neflags, format):
    
    print('# PS4 Syscon Loader')
    
    # PS4 Syscon Processor
    processor('rl78')
    
    # Boot Cluster 0
    print('# Creating Vector Table Area 0')
    segment(f, 0x0, 0x80, 'VTA0')
    
    for vec in xrange(0x40):
        ida.create_data(vec * 2, FF_WORD | FF_0OFF, 0x2, BADNODE)
    
    print('# Creating CALLT Table Area 0')
    segment(f, 0x80, 0xC0, 'CALLTTA0')
    
    print('# Creating Option Byte Area 0')
    segment(f, 0xC0, 0xC4, 'OBA0')
    
    print('# Creating On-chip Debug Security 0')
    segment(f, 0xC4, 0xCE, 'ODS0')
    
    print('# Creating Program Area 0')
    segment(f, 0xCE, 0x1000, 'PA0', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # Boot Cluster 1
    print('# Creating Vector Table Area 1')
    segment(f, 0x1000, 0x1080, 'VTA1')
    
    for vec in xrange(0x40):
        ida.create_data(0x1000 + (vec * 2), FF_WORD | FF_0OFF, 0x2, BADNODE)
    
    print('# Creating CALLT Table Area 1')
    segment(f, 0x1080, 0x10C0, 'CALLTTA1')
    
    print('# Creating Option Byte Area 1')
    segment(f, 0x10C0, 0x10C4, 'OBA1')
    
    print('# Creating On-chip Debug Security 1')
    segment(f, 0x10C4, 0x10CE, 'ODS1')
    
    # ROM
    print('# Creating Program Area 1')
    segment(f, 0x10CE, 0x80000, 'PA1', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # 0x80000 - 0xF0000 : Reserved
    
    print('# Creating Special Function Register 2')
    segment(f, 0xF0000, 0xF0800, 'SFR2')
    
    print('# Creating Reserved')
    segment(f, 0xF0800, 0xF1000, 'RES')
    
    # DATA
    print('# Creating Data')
    segment(f, 0xF1000, 0xF3000, 'DATA')
    
    print('# Creating Mirror')
    segment(f, 0xF3000, 0xF7F00, 'MIRROR')
    
    # RAM
    print('# Creating RAM')
    segment(f, 0xF7F00, 0xFFEE0, 'RAM')
    
    print('# Creating General-purpose Register')
    segment(f, 0xFFEE0, 0xFFF00, 'GR')
    
    print('# Creating Special Function Register')
    segment(f, 0xFFF00, 0x100000, 'SFR')
    
    print('# Search Function Start')
    function_search(1, 'D7 61 DD')
    function_search(1, 'FF C3 31 17')
    function_search(1, 'FB C3 31 17')
    function_search(1, 'FF 61 DD 8E FA')
    function_search(1, 'FF 61 DD C7')
    function_search(0, '61 DD C7')
    function_search(1, 'D7 C7 C3 C1')
    function_search(1, 'D7 C7 16')
    function_search(1, 'D7 30 02 00 C1')
    function_search(1, 'D7 C7 C1')
    function_search(1, 'D7 C7 88')
    function_search(1, 'D7 C7 20')
    function_search(1, 'D7 C7 41')
    function_search(1, 'D7 C7 36')
    function_search(1, '00 C7 C3 C1 FB')
    function_search(1, 'FF C7 57')
    function_search(2, '00 00 C7 C5 C1')
    function_search(1, '00 C5 C1')
    
    print('# Done!')
    return 1

# PROGRAM END