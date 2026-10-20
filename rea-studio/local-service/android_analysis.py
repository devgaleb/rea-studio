"""Deterministic Android source cross-reference extraction from JADX output.

All references retain source paths and line numbers; regex-based parsing is intentionally
labelled as source-level triage, not a complete Java/Kotlin parser.
"""
from pathlib import Path
import re

PERMISSION_RISK = {
    'android.permission.READ_SMS': 'sensitive: SMS read',
    'android.permission.RECEIVE_SMS': 'sensitive: SMS receive',
    'android.permission.SEND_SMS': 'sensitive: SMS send',
    'android.permission.READ_CONTACTS': 'sensitive: contacts read',
    'android.permission.WRITE_CONTACTS': 'sensitive: contacts write',
    'android.permission.RECORD_AUDIO': 'sensitive: microphone',
    'android.permission.CAMERA': 'sensitive: camera',
    'android.permission.ACCESS_FINE_LOCATION': 'sensitive: precise location',
    'android.permission.ACCESS_COARSE_LOCATION': 'sensitive: approximate location',
    'android.permission.READ_CALL_LOG': 'sensitive: call log',
    'android.permission.REQUEST_INSTALL_PACKAGES': 'high-impact: package installation',
    'android.permission.SYSTEM_ALERT_WINDOW': 'high-impact: overlay window',
    'android.permission.BIND_ACCESSIBILITY_SERVICE': 'high-impact: accessibility service',
}
COMPONENT_TAGS = ('activity','activity-alias','service','receiver','provider')
METHOD_RE = re.compile(r'(?m)^\s*(?:(?:public|protected|private|static|final|native|synchronized|abstract|default|\s)+)(?:[\w.$<>?,\[\]@]+\s+)+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^;{}]*)\)\s*(?:throws\s+[^\{]+)?\{')
CALL_RE = re.compile(r'(?<![\w.$])(?P<owner>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*(?P<method>[A-Za-z_$][\w$]*)\s*\(')
BARE_CALL_RE = re.compile(r'(?<![\w$])(?P<method>[A-Za-z_$][\w$]*)\s*\(')
STRING_RE = re.compile(r'"((?:\\.|[^"\\]){4,})"')


def analyze_jadx_tree(root):
    root = Path(root)
    result = {'manifestPath': None, 'permissions': [], 'permissionFindings': [], 'components': [],
              'methods': [], 'crossReferences': [], 'apiIndicators': [], 'limitations': [
                  'Java source cross-references are lexical candidates from JADX output, not a full compiler call graph.',
                  'Reflection, dynamic loading, obfuscation, native calls and unresolved dispatch can hide relationships.']}
    manifest = next((p for p in root.rglob('AndroidManifest.xml') if p.is_file()), None)
    if manifest:
        result['manifestPath'] = str(manifest.relative_to(root))
        txt = manifest.read_text('utf-8', errors='replace')
        result['permissions'] = sorted(set(re.findall(r'<uses-permission(?:-sdk-\d+)?\b[^>]*android:name="([^"]+)', txt)))
        result['components'] = [{'type':tag,'name':name,'evidencePath':result['manifestPath']}
          for tag,name in re.findall(r'<(activity|activity-alias|service|receiver|provider)\b[^>]*android:name="([^"]+)',txt)]
        for perm in result['permissions']:
            if perm in PERMISSION_RISK:
                result['permissionFindings'].append({'permission':perm,'label':PERMISSION_RISK[perm],'evidencePath':result['manifestPath']})
    java_files = sorted(root.rglob('*.java'))
    method_index = {}
    call_edges = []
    indicators = []
    for p in java_files:
        try: txt = p.read_text('utf-8', errors='replace')
        except OSError: continue
        rel = str(p.relative_to(root))
        package = re.search(r'(?m)^\s*package\s+([\w.]+)\s*;',txt)
        imports = re.findall(r'(?m)^\s*import\s+(?:static\s+)?([\w.*]+)\s*;',txt)
        cls = re.search(r'\bclass\s+([A-Za-z_$][\w$]*)',txt)
        owner = (package.group(1)+'.' if package else '')+(cls.group(1) if cls else p.stem)
        for m in METHOD_RE.finditer(txt):
            line = txt.count('\n',0,m.start())+1
            rec = {'owner':owner,'name':m.group('name'),'signature':m.group('name')+'('+m.group('args').strip()+')','path':rel,'line':line}
            result['methods'].append(rec); method_index.setdefault(m.group('name'),[]).append(rec)
        # Approximate enclosing method by most recent declaration before each call.
        declarations = list(METHOD_RE.finditer(txt))
        qualified = list(CALL_RE.finditer(txt))
        calls = [(m, m.group('owner')) for m in qualified]
        for bare in BARE_CALL_RE.finditer(txt):
            if any(q.start() <= bare.start() < q.end() for q in qualified): continue
            # Ignore declarations themselves, control syntax and constructor expressions.
            if any(m.start('name') <= bare.start('method') < m.start('name') + len(m.group('name')) for m in declarations): continue
            if bare.group('method') in {'if','for','while','switch','catch','return','new','synchronized','super','this'}: continue
            calls.append((bare, owner))
        for call, target_owner in calls:
            target = call.group('method')
            line = txt.count('\n',0,call.start())+1
            parent = next((m for m in reversed(declarations) if m.start()<call.start()),None)
            caller = parent.group('name') if parent else '<initializer>'
            candidates = method_index.get(target, [])
            call_edges.append({'callerOwner':owner,'caller':caller,'targetOwner':target_owner,'target':target,
              'resolvedCandidates':[{'owner':x['owner'],'path':x['path'],'line':x['line']} for x in candidates[:8]],'path':rel,'line':line,
              'resolution':'name-match-candidate' if candidates else 'unresolved-external-or-dynamic'})
        for s in STRING_RE.findall(txt):
            if re.search(r'https?://|content://|android\.permission\.|/system/|/data/data/|DexClassLoader|Runtime\.getRuntime|ProcessBuilder|Cipher|SecretKey|AccessibilityService|SmsManager',s,re.I):
                indicators.append({'value':s[:300],'path':rel,'line':txt.count('\n',0,txt.find('"'+s+'"'))+1})
    # Re-resolve after full scan, so methods declared later in file order are included.
    for edge in call_edges:
        cands=method_index.get(edge['target'],[])
        edge['resolvedCandidates']=[{'owner':x['owner'],'path':x['path'],'line':x['line']} for x in cands[:8]]
        edge['resolution']='name-match-candidate' if cands else 'unresolved-external-or-dynamic'
    result['crossReferences']=call_edges[:50000]
    result['methods']=result['methods'][:50000]
    result['apiIndicators']=indicators[:5000]
    result['summary']={'javaFiles':len(java_files),'methods':len(result['methods']),'callSites':len(result['crossReferences']),
      'candidateResolvedCallSites':sum(bool(x['resolvedCandidates']) for x in result['crossReferences']),
      'manifestComponents':len(result['components']),'declaredPermissions':len(result['permissions'])}
    return result
