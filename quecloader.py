#Quectel module loader
#@author Azox (Sudki Karim)
#@category Quectel
#@keybinding 
#@menupath 
#@toolbar

file = askFile("Please specify a file to import", "Import")
lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("ARM"))
comp = lang.getDefaultCompilerSpec()
program = importFileAsBinary(file, lang, comp)
monitor = ghidra.util.task.TaskMonitor.DUMMY

flat = ghidra.program.flatapi.FlatProgramAPI(program)
txn = program.startTransaction("Import program")
mem = program.getMemory()
start = mem.getMinAddress()
magic = mem.getInt(start)

if magic != 0x4d4f4455:
    print("[E] Not a Quectel Firwmare")
else:
    print("[I] Quectel magic OK")


ER_RO_start = mem.getInt(start.add(0x40))
ER_RO_len = mem.getInt(start.add(0x38))
ER_RW_start = ER_RO_start + ER_RO_len
ER_RW_len = mem.getInt(start.add(0x44))
ER_ZI_start = ER_RW_start + ER_RW_len
ER_ZI_len = mem.getInt(start.add(0x3c))

mem.removeBlock(mem.getBlocks()[0], ghidra.util.task.TaskMonitor.DUMMY)

#ER_RO
print("ER_RO")
print(hex(ER_RO_start))
print(hex(ER_RO_len))
fb = mem.getAllFileBytes()
bl_ER_RO = mem.createInitializedBlock("ER_RO", start.add(ER_RO_start), fb[0], 0, ER_RO_len, False)
bl_ER_RO.setRead(True)
bl_ER_RO.setExecute(True)


#ER_RW
print("ER_RW")
print(hex(ER_RW_start))
print(hex(ER_RW_len))
print("total size")
bl_ER_RW = mem.createInitializedBlock("ER_RW", start.add(ER_RW_start), fb[0], ER_RO_len, ER_RW_len, False)
bl_ER_RW.setRead(True)
bl_ER_RW.setWrite(True)


#ER_ZI
print("ER_ZI")
print(ER_ZI_start)
print(ER_ZI_len)

bl_ER_ZI = mem.createUninitializedBlock("ER_ZI", start.add(ER_ZI_start), ER_ZI_len, False)
bl_ER_ZI.setRead(True)
bl_ER_ZI.setWrite(True)

start = mem.getMinAddress()

#Preamble
flat.createDwords(start.add(0x0), 32)
flat.createLabel(start.add(0x0),  "txm_module_preamble_id", True)
flat.createLabel(start.add(0x4),  "txm_module_preamble_version_major", True)
flat.createLabel(start.add(0x8),  "txm_module_preamble_version_minor", True)
flat.createLabel(start.add(0xc),  "txm_module_preamble_preamble_size", True)
flat.createLabel(start.add(0x10), "txm_module_preamble_application_module_id", True)
flat.createLabel(start.add(0x14), "txm_module_preamble_property_flags", True)

shell_entry = flat.toAddr(mem.getInt(start.add(0x18)))
flat.createLabel(start.add(0x18), "txm_module_preamble_shell_entry_function",True)
flat.addEntryPoint(shell_entry)
flat.createFunction(shell_entry, "txm_module_preamble_shell_entry_function")
flat.disassemble(shell_entry)

start_function = flat.toAddr(mem.getInt(start.add(0x1c)))
flat.createLabel(start.add(0x1c), "txm_module_preamble_start_function", True)
flat.addEntryPoint(start_function)
flat.createFunction(start_function, "txm_module_preamble_start_function")
flat.disassemble(start_function)

flat.createLabel(start.add(0x20), "txm_module_preamble_stop_function", True)
flat.createLabel(start.add(0x24), "txm_module_preamble_start_stop_priority", True)
flat.createLabel(start.add(0x28), "txm_module_preamble_start_stop_stack_size", True)
flat.createLabel(start.add(0x2c), "txm_module_preamble_callback_function", True)

callback_function = flat.toAddr(mem.getInt(start.add(0x2c)))
flat.addEntryPoint(callback_function)
flat.createFunction(callback_function, "txm_module_preamble_callback_function")
flat.disassemble(callback_function)

flat.createLabel(start.add(0x30), "txm_module_preamble_callback_priority", True)
flat.createLabel(start.add(0x34), "txm_module_preamble_callback_stack_size", True)
flat.createLabel(start.add(0x38), "txm_module_preamble_code_size", True)
flat.createLabel(start.add(0x3c), "ER_ZI_LEN", True)
flat.createLabel(start.add(0x40), "ER_RO_BASE", True)
flat.createLabel(start.add(0x44), "ER_RW_LEN", True)

program.endTransaction(txn, True)
openProgram(program)
