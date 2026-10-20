# IDA Pro -S script. Runs inside IDA's Python environment; exports address/call/xref evidence.
import ida_auto, ida_funcs, ida_name, ida_hexrays, ida_lines, ida_xref, ida_bytes, idaapi, idc, idautils, ida_gdl, json, os
out = idc.ARGV[1] if len(idc.ARGV) > 1 else os.path.join(os.getcwd(), 'ida-evidence.json')
ida_auto.auto_wait()
rows=[]
for f in ida_funcs.get_func_qty() and [ida_funcs.getn_func(i) for i in range(ida_funcs.get_func_qty())] or []:
    if not f: continue
    start=int(f.start_ea); end=int(f.end_ea); name=ida_name.get_name(start) or hex(start)
    ins=[]; refs=[]; calls=[]; ea=start; limit=0; blocks=[]
    while ea < end and limit < 2000:
        mnem=idc.print_insn_mnem(ea); dis=idc.generate_disasm_line(ea, 0) or ''
        ins.append({'address':hex(ea),'mnemonic':mnem,'text':ida_lines.tag_remove(dis)})
        for x in idautils.CodeRefsFrom(ea, 0):
            refs.append(hex(x))
            if ida_funcs.get_func(x): calls.append({'address':hex(x),'name':ida_name.get_name(x) or hex(x)})
        nxt=idc.next_head(ea,end)
        if nxt <= ea: break
        ea=nxt; limit+=1
    decomp='';
    try:
        c=ida_hexrays.decompile(start)
        if c: decomp=str(c)
    except Exception: pass
    try:
        for bb in ida_gdl.FlowChart(ida_funcs.get_func(start)):
            succ=[hex(int(s.start_ea)) for s in bb.succs()]
            blocks.append({'start':hex(int(bb.start_ea)),'end':hex(int(bb.end_ea)),'successors':succ})
    except Exception: pass
    incoming=[]
    for xr in idautils.XrefsTo(start, 0): incoming.append({'from':hex(int(xr.frm)), 'type':'code' if xr.iscode else 'data'})
    rows.append({'name':name,'entry':hex(start),'end':hex(end),'size':end-start,'decompiled':decomp,'instructions':ins,'xrefs':incoming,'calls':calls,'basicBlocks':blocks})
with open(out,'w',encoding='utf-8') as fp: json.dump({'provider':'IDA','input':idc.get_input_file_path(),'functions':rows},fp,indent=2)
idaapi.qexit(0)
