// Ghidra post-script: export decompilation, instructions, cross-references and basic blocks as evidence.
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class ExportFunctions extends ghidra.app.script.GhidraScript {
  private String esc(String s) { if (s == null) return ""; return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"); }
  @Override public void run() throws Exception {
    String[] args=getScriptArgs(); if(args.length<1){println("Output JSON path missing");return;}
    DecompInterface d=new DecompInterface(); d.openProgram(currentProgram);
    try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
      out.print("{\"provider\":\"Ghidra\",\"program\":\""+esc(currentProgram.getName())+"\",\"language\":\""+esc(currentProgram.getLanguageID().toString())+"\",\"functions\":[");
      FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true); boolean first=true;
      while(it.hasNext()&&!monitor.isCancelled()) {
        Function f=it.next(); if(!first)out.print(",");first=false;
        DecompileResults r=d.decompileFunction(f,30,new ConsoleTaskMonitor());
        String code=(r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null)?r.getDecompiledFunction().getC():"";
        out.print("{\"name\":\""+esc(f.getName())+"\",\"entry\":\""+f.getEntryPoint()+"\",\"end\":\""+f.getBody().getMaxAddress()+"\",\"signature\":\""+esc(f.getSignature().toString())+"\",\"decompiled\":\""+esc(code)+"\",\"instructions\":[");
        boolean fi=true; Listing listing=currentProgram.getListing(); InstructionIterator ins=listing.getInstructions(f.getBody(),true); int n=0;
        while(ins.hasNext()&&n++<2500){Instruction i=ins.next();if(!fi)out.print(",");fi=false;out.print("{\"address\":\""+i.getAddress()+"\",\"text\":\""+esc(i.toString())+"\",\"length\":"+i.getLength()+"}");}
        out.print("],\"xrefs\":["); boolean fx=true; ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()); int nr=0;
        while(refs.hasNext()&&nr++<1000){Reference ref=refs.next();if(!fx)out.print(",");fx=false;out.print("{\"from\":\""+ref.getFromAddress()+"\",\"type\":\""+esc(ref.getReferenceType().toString())+"\"}");}
        out.print("],\"calls\":["); boolean fc=true; InstructionIterator ins2=listing.getInstructions(f.getBody(),true); int nc=0;
        while(ins2.hasNext()&&nc++<2500){Instruction i=ins2.next();for(Reference ref: i.getReferencesFrom()){if(ref.getReferenceType().isCall()){if(!fc)out.print(",");fc=false;Function target=currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());out.print("{\"address\":\""+ref.getToAddress()+"\",\"name\":\""+esc(target==null?currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress())==null?"unknown":currentProgram.getSymbolTable().getPrimarySymbol(ref.getToAddress()).getName():target.getName())+"\"}");}}}
        out.print("],\"basicBlocks\":["); boolean fb=true; SimpleBlockModel model=new SimpleBlockModel(currentProgram); CodeBlockIterator blocks=model.getCodeBlocksContaining(f.getBody(),monitor); int nb=0;
        while(blocks.hasNext()&&nb++<1000){CodeBlock b=blocks.next();if(!fb)out.print(",");fb=false;out.print("{\"start\":\""+b.getFirstStartAddress()+"\",\"end\":\""+b.getMaxAddress()+"\",\"successors\":[");boolean fs=true;CodeBlockReferenceIterator succ=b.getDestinations(monitor);while(succ.hasNext()){CodeBlockReference sr=succ.next();if(!fs)out.print(",");fs=false;out.print("\""+sr.getDestinationAddress()+"\"");}out.print("]}");}
        out.print("]}");
      }
      out.println("]}");
    } finally {d.dispose();}
  }
}
