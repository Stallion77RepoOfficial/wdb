#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced x86/x64 Disassembler for WDB
Provides real assembly instruction decoding, not just pseudo-disassembly
"""

import struct
from typing import List, Dict, Tuple, Optional

class X86Instruction:
    def __init__(self, address: int, bytes_data: bytes, mnemonic: str, operands: str = "", 
                 comment: str = "", flow_type: str = "sequential"):
        self.address = address
        self.bytes = bytes_data
        self.length = len(bytes_data)
        self.mnemonic = mnemonic
        self.operands = operands
        self.comment = comment
        self.flow_type = flow_type  # sequential, call, jump, return, interrupt
        
    def __str__(self):
        hex_bytes = " ".join(f"{b:02X}" for b in self.bytes)
        return f"{self.address:08X}: {hex_bytes:<20} {self.mnemonic} {self.operands} {self.comment}"
    
    def to_dict(self):
        return {
            "address": f"0x{self.address:08X}",
            "bytes": "".join(f"{b:02X}" for b in self.bytes),
            "length": self.length,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "comment": self.comment,
            "flow_type": self.flow_type
        }

class X86Disassembler:
    def __init__(self, is_64bit: bool = False):
        self.is_64bit = is_64bit
        self.registers_32 = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        self.registers_16 = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"]
        self.registers_8 = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"]
        
        if is_64bit:
            self.registers_64 = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                               "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]
    
    def decode_modrm(self, modrm: int, data: bytes, offset: int) -> Tuple[str, int]:
        """Decode ModR/M byte and return operand string and consumed bytes"""
        mod = (modrm >> 6) & 3
        reg = (modrm >> 3) & 7
        rm = modrm & 7
        
        consumed = 0
        
        if mod == 3:  # Register-to-register
            return self.registers_32[rm], consumed
        elif mod == 0:  # Memory, no displacement
            if rm == 5:  # Special case: [disp32]
                if offset + 4 <= len(data):
                    disp = struct.unpack("<I", data[offset:offset+4])[0]
                    return f"[0x{disp:08X}]", 4
            elif rm == 4:  # SIB byte follows
                return "[SIB]", 0  # Simplified
            else:
                return f"[{self.registers_32[rm]}]", consumed
        elif mod == 1:  # Memory + byte displacement
            if offset + 1 <= len(data):
                disp = struct.unpack("<b", data[offset:offset+1])[0]
                if rm == 4:
                    return f"[SIB{disp:+d}]", 1
                return f"[{self.registers_32[rm]}{disp:+d}]", 1
        elif mod == 2:  # Memory + dword displacement
            if offset + 4 <= len(data):
                disp = struct.unpack("<i", data[offset:offset+4])[0]
                if rm == 4:
                    return f"[SIB{disp:+d}]", 4
                return f"[{self.registers_32[rm]}{disp:+d}]", 4
        
        return "[?]", 0
    
    def disassemble_instruction(self, data: bytes, address: int) -> Optional[X86Instruction]:
        """Disassemble a single instruction from bytes"""
        if not data:
            return None
            
        original_data = data
        offset = 0
        
        # Handle prefixes
        prefixes = []
        while offset < len(data) and data[offset] in [0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65]:
            prefixes.append(data[offset])
            offset += 1
        
        if offset >= len(data):
            return None
            
        opcode = data[offset]
        offset += 1
        
        # Single byte instructions
        single_byte_ops = {
            0x90: ("NOP", "", "sequential"),
            0xC3: ("RET", "", "return"),
            0xCC: ("INT3", "", "interrupt"),
            0xCB: ("RETF", "", "return"),
            0xF4: ("HLT", "", "interrupt"),
            0xFA: ("CLI", "", "sequential"),
            0xFB: ("STI", "", "sequential"),
            0x9C: ("PUSHFD", "", "sequential"),
            0x9D: ("POPFD", "", "sequential"),
            0x60: ("PUSHAD", "", "sequential"),
            0x61: ("POPAD", "", "sequential"),
            0xAA: ("STOSB", "", "sequential"),
            0xAB: ("STOSD", "", "sequential"),
            0xA4: ("MOVSB", "", "sequential"),
            0xA5: ("MOVSD", "", "sequential"),
        }
        
        if opcode in single_byte_ops:
            mnemonic, operands, flow_type = single_byte_ops[opcode]
            return X86Instruction(address, original_data[:offset], mnemonic, operands, "", flow_type)
        
        # PUSH/POP register (0x50-0x5F)
        if 0x50 <= opcode <= 0x57:
            reg = self.registers_32[opcode - 0x50]
            return X86Instruction(address, original_data[:offset], "PUSH", reg, "", "sequential")
        
        if 0x58 <= opcode <= 0x5F:
            reg = self.registers_32[opcode - 0x58]
            return X86Instruction(address, original_data[:offset], "POP", reg, "", "sequential")
        
        # MOV register, immediate (0xB0-0xBF)
        if 0xB8 <= opcode <= 0xBF:
            reg = self.registers_32[opcode - 0xB8]
            if offset + 4 <= len(data):
                imm = struct.unpack("<I", data[offset:offset+4])[0]
                offset += 4
                return X86Instruction(address, original_data[:offset], "MOV", 
                                    f"{reg}, 0x{imm:08X}", "", "sequential")
        
        # Conditional jumps (0x70-0x7F) - short form
        if 0x70 <= opcode <= 0x7F:
            jump_conditions = {
                0x70: "JO", 0x71: "JNO", 0x72: "JB", 0x73: "JAE",
                0x74: "JE", 0x75: "JNE", 0x76: "JBE", 0x77: "JA",
                0x78: "JS", 0x79: "JNS", 0x7A: "JP", 0x7B: "JNP",
                0x7C: "JL", 0x7D: "JGE", 0x7E: "JLE", 0x7F: "JG"
            }
            if offset < len(data):
                disp = struct.unpack("<b", data[offset:offset+1])[0]
                offset += 1
                target = address + offset + disp
                return X86Instruction(address, original_data[:offset], jump_conditions[opcode],
                                    f"0x{target:08X}", f"({disp:+d})", "jump")
        
        # Near jumps and calls
        if opcode == 0xE8:  # CALL rel32
            if offset + 4 <= len(data):
                disp = struct.unpack("<i", data[offset:offset+4])[0]
                offset += 4
                target = address + offset + disp
                return X86Instruction(address, original_data[:offset], "CALL",
                                    f"0x{target:08X}", f"({disp:+d})", "call")
        
        if opcode == 0xE9:  # JMP rel32
            if offset + 4 <= len(data):
                disp = struct.unpack("<i", data[offset:offset+4])[0]
                offset += 4
                target = address + offset + disp
                return X86Instruction(address, original_data[:offset], "JMP",
                                    f"0x{target:08X}", f"({disp:+d})", "jump")
        
        if opcode == 0xEB:  # JMP rel8
            if offset < len(data):
                disp = struct.unpack("<b", data[offset:offset+1])[0]
                offset += 1
                target = address + offset + disp
                return X86Instruction(address, original_data[:offset], "JMP",
                                    f"0x{target:08X}", f"({disp:+d})", "jump")
        
        # MOV instructions with ModR/M
        if opcode == 0x89:  # MOV r/m32, r32
            if offset < len(data):
                modrm = data[offset]
                offset += 1
                reg = (modrm >> 3) & 7
                operand, consumed = self.decode_modrm(modrm, data, offset)
                offset += consumed
                return X86Instruction(address, original_data[:offset], "MOV",
                                    f"{operand}, {self.registers_32[reg]}", "", "sequential")
        
        if opcode == 0x8B:  # MOV r32, r/m32
            if offset < len(data):
                modrm = data[offset]
                offset += 1
                reg = (modrm >> 3) & 7
                operand, consumed = self.decode_modrm(modrm, data, offset)
                offset += consumed
                return X86Instruction(address, original_data[:offset], "MOV",
                                    f"{self.registers_32[reg]}, {operand}", "", "sequential")
        
        # ADD/SUB/CMP with ModR/M
        alu_ops = {
            0x01: "ADD", 0x03: "ADD", 0x29: "SUB", 0x2B: "SUB",
            0x39: "CMP", 0x3B: "CMP", 0x85: "TEST", 0x09: "OR", 0x0B: "OR"
        }
        
        if opcode in alu_ops:
            if offset < len(data):
                modrm = data[offset]
                offset += 1
                reg = (modrm >> 3) & 7
                operand, consumed = self.decode_modrm(modrm, data, offset)
                offset += consumed
                
                if opcode in [0x01, 0x29, 0x39, 0x85, 0x09]:  # r/m32, r32
                    return X86Instruction(address, original_data[:offset], alu_ops[opcode],
                                        f"{operand}, {self.registers_32[reg]}", "", "sequential")
                else:  # r32, r/m32
                    return X86Instruction(address, original_data[:offset], alu_ops[opcode],
                                        f"{self.registers_32[reg]}, {operand}", "", "sequential")
        
        # Two-byte opcodes (0x0F prefix)
        if opcode == 0x0F and offset < len(data):
            opcode2 = data[offset]
            offset += 1
            
            # Conditional jumps - long form (0x0F 0x80-0x8F)
            if 0x80 <= opcode2 <= 0x8F:
                jump_conditions = {
                    0x80: "JO", 0x81: "JNO", 0x82: "JB", 0x83: "JAE",
                    0x84: "JE", 0x85: "JNE", 0x86: "JBE", 0x87: "JA",
                    0x88: "JS", 0x89: "JNS", 0x8A: "JP", 0x8B: "JNP",
                    0x8C: "JL", 0x8D: "JGE", 0x8E: "JLE", 0x8F: "JG"
                }
                if offset + 4 <= len(data):
                    disp = struct.unpack("<i", data[offset:offset+4])[0]
                    offset += 4
                    target = address + offset + disp
                    return X86Instruction(address, original_data[:offset], jump_conditions[opcode2],
                                        f"0x{target:08X}", f"({disp:+d})", "jump")
        
        # Default case - unknown instruction
        return X86Instruction(address, original_data[:1], "DB", f"0x{opcode:02X}", "unknown", "sequential")
    
    def disassemble_block(self, data: bytes, base_address: int, max_instructions: int = 50) -> List[X86Instruction]:
        """Disassemble a block of code"""
        instructions = []
        offset = 0
        
        while offset < len(data) and len(instructions) < max_instructions:
            remaining_data = data[offset:]
            if not remaining_data:
                break
                
            instruction = self.disassemble_instruction(remaining_data, base_address + offset)
            if instruction is None:
                # Skip bad byte
                offset += 1
                continue
                
            instructions.append(instruction)
            offset += instruction.length
            
            # Stop at return/interrupt instructions for better analysis
            if instruction.flow_type in ["return", "interrupt"]:
                break
        
        return instructions
    
    def analyze_control_flow(self, instructions: List[X86Instruction]) -> Dict:
        """Analyze control flow patterns"""
        analysis = {
            "total_instructions": len(instructions),
            "calls": [],
            "jumps": [],
            "returns": [],
            "loops": [],
            "branches": 0
        }
        
        for inst in instructions:
            if inst.flow_type == "call":
                analysis["calls"].append({
                    "address": inst.address,
                    "target": inst.operands,
                    "instruction": str(inst)
                })
            elif inst.flow_type == "jump":
                analysis["jumps"].append({
                    "address": inst.address,
                    "target": inst.operands,
                    "instruction": str(inst),
                    "conditional": inst.mnemonic != "JMP"
                })
                if inst.mnemonic != "JMP":
                    analysis["branches"] += 1
            elif inst.flow_type == "return":
                analysis["returns"].append({
                    "address": inst.address,
                    "instruction": str(inst)
                })
        
        # Simple loop detection
        jump_targets = set()
        for jump in analysis["jumps"]:
            try:
                target_addr = int(jump["target"], 16)
                jump_targets.add(target_addr)
            except:
                pass
        
        for inst in instructions:
            if inst.address in jump_targets:
                # This instruction is a jump target
                for jump in analysis["jumps"]:
                    try:
                        if int(jump["target"], 16) == inst.address and int(jump["address"], 16) > inst.address:
                            analysis["loops"].append({
                                "start": inst.address,
                                "end": int(jump["address"], 16),
                                "type": "backward_jump"
                            })
                    except:
                        pass
        
        return analysis
