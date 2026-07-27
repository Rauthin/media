#!/usr/bin/env python3
"""Read every reachable Git blob and audit the current architecture non-destructively.

The coverage certificate is based on every unique blob reachable from all local
branches, remote branches and tags. Every text blob is read line-by-line; binary
blobs are hashed. Potential secret values are never printed.
"""
from __future__ import annotations

import argparse, ast, collections, datetime as dt, hashlib, json, math, os, re, shutil, subprocess, urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:
    yaml = None
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None
try:
    from PIL import Image, ExifTags
except Exception:
    Image = ExifTags = None

VERSION = "2026-07-27.2"
TEXT_EXT = {".py",".pyi",".js",".mjs",".cjs",".ts",".tsx",".jsx",".gs",".html",".htm",".css",".scss",".less",".json",".jsonc",".yaml",".yml",".xml",".md",".txt",".csv",".tsv",".ini",".cfg",".conf",".toml",".env",".sh",".bash",".zsh",".ps1",".sql",".graphql",".gql",".svg",".properties",".gradle",".java",".kt",".rb",".php",".go",".rs",".c",".h",".cpp",".hpp",".cs",".lock",".gitignore",".gitattributes",".editorconfig",".npmrc",".nvmrc",".dockerignore"}
TEXT_NAMES = {"Dockerfile","Makefile","Procfile","Gemfile","Rakefile","LICENSE","README","CODEOWNERS","CNAME","_headers","_redirects","robots.txt","sitemap.xml","appsscript.json",".clasp.json"}
SKIP = {".git","node_modules",".venv","venv","dist","build",".cache"}
SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{24,}")),
    ("credential_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['\"](?!\$\{|\{\{|process\.env|PropertiesService|secrets\.)[^'\"]{8,}['\"]")),
]
RISK_PATTERNS = [
    ("eval_or_exec", re.compile(r"\b(?:eval|exec)\s*\("), "high"),
    ("shell_true", re.compile(r"shell\s*=\s*True"), "high"),
    ("curl_pipe_shell", re.compile(r"curl\b[^\n|]*\|\s*(?:ba)?sh\b"), "high"),
    ("chmod_777", re.compile(r"chmod\s+(?:-R\s+)?777\b"), "high"),
    ("force_push", re.compile(r"git\s+push\b[^\n]*(?:--force|-f)\b"), "high"),
    ("clasp_force_push", re.compile(r"clasp\s+push\s+--force"), "high"),
    ("http_url", re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"), "medium"),
    ("destructive_sheet_clear", re.compile(r"\.clear(?:Contents|Format|Notes|DataValidations)?\s*\("), "medium"),
    ("delete_trigger", re.compile(r"(?:deleteTrigger|ScriptApp\.getProjectTriggers)"), "medium"),
    ("broad_exception", re.compile(r"\bexcept\s+(?:Exception|BaseException)\b|\bcatch\s*\([^)]*\)\s*\{\s*\}"), "medium"),
    ("todo", re.compile(r"(?i)\b(?:TODO|FIXME|HACK|XXX)\b"), "info"),
]
FUNC_RE = [
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)\b"),
]
SCRIPT_ID_RE = [re.compile(r"(?i)\bscriptId\b\s*[:=]\s*['\"]([A-Za-z0-9_-]{30,})['\"]"), re.compile(r"\bLIVE_SCRIPT_ID\b\s*:\s*([A-Za-z0-9_-]{30,})")]
URL_RE = re.compile(r"https?://[^\s'\"<>)}\]]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

@dataclass
class Finding:
    severity: str
    category: str
    path: str
    line: int | None
    message: str
    ref: str | None = None
    fingerprint: str | None = None
    def done(self):
        raw = f"{self.severity}|{self.category}|{self.path}|{self.line}|{self.message}|{self.ref}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:20]
        return self

def run(cmd, cwd=None, text=True, check=True, input_data=None):
    return subprocess.run(cmd, cwd=cwd, text=text, check=check, capture_output=True, input=input_data)

def git(repo: Path, *args: str) -> str:
    return run(["git", *args], cwd=repo).stdout

def entropy(value: str) -> float:
    if not value: return 0.0
    counts = collections.Counter(value)
    return -sum((n/len(value))*math.log2(n/len(value)) for n in counts.values())

def redact(line: str) -> str:
    text = line.strip()[:220]
    for _, pattern in SECRET_PATTERNS: text = pattern.sub("<REDACTED>", text)
    return text

def is_text(path: str, data: bytes) -> bool:
    if b"\x00" in data[:8192]: return False
    if Path(path).suffix.lower() in TEXT_EXT or Path(path).name in TEXT_NAMES: return True
    try:
        sample = data[:8192].decode("utf-8")
        return sum(ord(c)<9 or 13<ord(c)<32 for c in sample)/max(1,len(sample)) < .02
    except UnicodeDecodeError: return False

def refs(repo: Path) -> list[str]:
    values = git(repo,"for-each-ref","--format=%(refname)","refs/heads","refs/remotes","refs/tags").splitlines()
    return sorted(x for x in values if x and not x.endswith("/HEAD"))

def tree_blobs(repo: Path, all_refs: list[str]):
    by_sha = collections.defaultdict(list)
    for ref in all_refs:
        raw = run(["git","ls-tree","-r","-z",ref],cwd=repo,text=False).stdout
        for item in raw.split(b"\0"):
            if not item: continue
            meta, path = item.split(b"\t",1)
            mode, kind, sha = meta.decode().split()
            if kind == "blob": by_sha[sha].append({"ref":ref,"path":path.decode(errors="replace"),"mode":mode})
    return by_sha

def functions(text: str, path: str):
    out=[]
    for no,line in enumerate(text.splitlines(),1):
        for pattern in FUNC_RE:
            match=pattern.search(line)
            if match:
                out.append({"name":match.group(1),"path":path,"line":no})
                break
    return out

def scan_line_history(repo: Path, findings: list[Finding]):
    all_refs=refs(repo); by_sha=tree_blobs(repo,all_refs)
    records=[]; digest=hashlib.sha256(); urls=set(); emails=set(); script_ids=set(); text_lines=0; text_blobs=0; binary_blobs=0
    for sha in sorted(by_sha):
        data=run(["git","cat-file","blob",sha],cwd=repo,text=False).stdout
        occ=by_sha[sha]; path=sorted(x["path"] for x in occ)[0]; record={"sha":sha,"bytes":len(data),"occurrences":occ,"canonical_path":path}
        if is_text(path,data):
            text_blobs+=1; text=data.decode("utf-8",errors="replace"); line_hash=hashlib.sha256(); count=0
            ref=sorted(x["ref"] for x in occ)[0]
            for no,line in enumerate(text.splitlines(),1):
                count+=1; line_hash.update(hashlib.sha256(line.encode(errors="replace")).digest())
                for category,pattern in SECRET_PATTERNS:
                    if pattern.search(line): findings.append(Finding("critical",category,path,no,"Potential secret material: "+redact(line),ref).done())
                for category,pattern,severity in RISK_PATTERNS:
                    if pattern.search(line): findings.append(Finding(severity,category,path,no,redact(line),ref).done())
                for token in re.findall(r"['\"]([A-Za-z0-9_./+=-]{40,})['\"]",line):
                    if entropy(token)>=4.2 and not re.fullmatch(r"[0-9a-f]{40,64}",token,re.I): findings.append(Finding("high","high_entropy_literal",path,no,f"High-entropy literal length={len(token)}",ref).done())
                urls.update(URL_RE.findall(line)); emails.update(EMAIL_RE.findall(line))
                for pattern in SCRIPT_ID_RE: script_ids.update(pattern.findall(line))
            record.update({"binary":False,"lines":count,"line_digest":line_hash.hexdigest(),"functions":functions(text,path)})
            text_lines+=count; digest.update(bytes.fromhex(record["line_digest"]))
        else:
            binary_blobs+=1; record["binary"]=True; digest.update(hashlib.sha256(data).digest())
        records.append(record)
    return {"refs":all_refs,"ref_count":len(all_refs),"commit_count":int(git(repo,"rev-list","--all","--count").strip() or 0),"unique_blob_count":len(records),"text_blob_count":text_blobs,"binary_blob_count":binary_blobs,"text_line_count":text_lines,"coverage_digest":digest.hexdigest(),"urls":sorted(urls),"emails":sorted(emails),"script_ids":sorted(script_ids),"blob_records":records}

def local(root: Path, html: Path, value: str):
    value=value.strip()
    if not value or value.startswith(("http://","https://","//","data:","mailto:","tel:","javascript:","#")): return None
    clean=urllib.parse.unquote(value.split("?",1)[0].split("#",1)[0])
    return root/clean.lstrip("/") if clean.startswith("/") else html.parent/clean

def site_root(path: Path, repo: Path):
    parts=path.relative_to(repo).parts
    return repo/parts[0]/parts[1] if len(parts)>=2 and parts[0]=="sites" else repo

def head_audit(repo: Path, profile: str, findings: list[Finding]):
    workflows=[]; symbols=[]; funcs=collections.defaultdict(list); html_count=0; image_count=0; asset_refs=0; content_hashes=collections.defaultdict(list); binary_hashes=collections.defaultdict(list); manifests=[]; all_files=[]; dependency_files=[]; script_ids=set()
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or any(part in SKIP for part in path.relative_to(repo).parts): continue
        rel=path.relative_to(repo).as_posix(); all_files.append(rel); ext=path.suffix.lower()
        if path.name in {"package.json","package-lock.json","yarn.lock","pnpm-lock.yaml","requirements.txt","pyproject.toml","poetry.lock","Pipfile","Pipfile.lock","go.mod","Cargo.toml"}: dependency_files.append(rel)
        if rel.startswith(".github/workflows/") and ext in {".yml",".yaml"}:
            text=path.read_text(encoding="utf-8",errors="replace")
            try: data=yaml.safe_load(text) if yaml else {}
            except Exception as exc: findings.append(Finding("high","invalid_workflow_yaml",rel,None,str(exc)).done()); data={}
            workflows.append({"path":rel,"name":data.get("name") if isinstance(data,dict) else None,"permissions":data.get("permissions") if isinstance(data,dict) else None,"jobs":sorted((data.get("jobs") or {}).keys()) if isinstance(data,dict) else []})
            if "pull_request_target" in text: findings.append(Finding("high","pull_request_target",rel,None,"Potential untrusted-code secret exposure").done())
            if re.search(r"uses:\s*[^\s]+@(main|master|latest)\b",text): findings.append(Finding("medium","mutable_action_ref",rel,None,"Workflow action uses mutable ref").done())
            if "contents: write" in text and re.search(r"git\s+push",text): findings.append(Finding("medium","self_modifying_workflow",rel,None,"Workflow writes commits to repository").done())
            if "clasp push --force" in text: findings.append(Finding("high","force_apps_script_deploy",rel,None,"Workflow force-pushes Apps Script").done())
        if ext==".py":
            try:
                tree=ast.parse(path.read_text(encoding="utf-8"),filename=rel)
                for node in ast.walk(tree):
                    if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        end=getattr(node,"end_lineno",node.lineno); symbols.append({"name":node.name,"path":rel,"line":node.lineno,"end_line":end})
                        if end-node.lineno+1>120: findings.append(Finding("medium","long_function",rel,node.lineno,f"{node.name} spans {end-node.lineno+1} lines").done())
                    if isinstance(node,ast.ExceptHandler) and node.type is None: findings.append(Finding("medium","bare_except",rel,getattr(node,"lineno",None),"Bare except handler").done())
            except Exception as exc: findings.append(Finding("high","python_syntax",rel,getattr(exc,"lineno",None),str(exc)).done())
        elif ext in {".js",".mjs",".cjs",".gs"} and shutil.which("node"):
            proc=subprocess.run(["node","--check","--input-type=commonjs"] if ext==".gs" else ["node","--check",str(path)],input=path.read_bytes() if ext==".gs" else None,capture_output=True)
            if proc.returncode: findings.append(Finding("high","javascript_syntax",rel,None,proc.stderr.decode(errors="replace")[-1200:]).done())
        if path.name=="appsscript.json":
            try:
                data=json.loads(path.read_text()); manifests.append({"path":rel,"runtimeVersion":data.get("runtimeVersion"),"oauthScopes":data.get("oauthScopes",[]),"webapp":data.get("webapp")})
            except Exception as exc: findings.append(Finding("high","invalid_appsscript_manifest",rel,None,str(exc)).done())
        if ext in {".json"}:
            try: json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc: findings.append(Finding("high","invalid_json",rel,None,str(exc)).done())
        if ext in {".gs",".js",".mjs",".cjs",".py"}:
            try: text=path.read_text(encoding="utf-8")
            except Exception: text=""
            for item in functions(text,rel): funcs[item["name"]].append(item)
            for pattern in SCRIPT_ID_RE: script_ids.update(pattern.findall(text))
        if ext in {".html",".htm"} and BeautifulSoup:
            html_count+=1; text=path.read_text(encoding="utf-8",errors="replace"); soup=BeautifulSoup(text,"html.parser"); root=site_root(path,repo)
            if not soup.title or not soup.title.get_text(strip=True): findings.append(Finding("medium","missing_title",rel,None,"HTML page has no title").done())
            if not soup.find("link",rel=lambda x:x and "canonical" in x): findings.append(Finding("medium","missing_canonical",rel,None,"HTML page has no canonical").done())
            for schema in soup.find_all("script",attrs={"type":"application/ld+json"}):
                try: json.loads(schema.get_text())
                except Exception as exc: findings.append(Finding("medium","invalid_jsonld",rel,getattr(schema,"sourceline",None),str(exc)).done())
            for tag,attr in [("img","src"),("script","src"),("link","href"),("source","src"),("video","poster")]:
                for node in soup.find_all(tag):
                    value=str(node.get(attr) or "").strip(); target=local(root,path,value)
                    if target is None: continue
                    if tag=="link" and node.get("rel") and any(x in {"canonical","alternate"} for x in node.get("rel")): continue
                    if not target.exists(): findings.append(Finding("high","missing_asset",rel,getattr(node,"sourceline",None),f"{tag}[{attr}] -> {value}").done())
                    else: asset_refs+=1
            for a in soup.find_all("a"):
                href=str(a.get("href") or "").strip(); target=local(root,path,href)
                if target is None: continue
                if not any(x.exists() for x in [target,Path(str(target)+".html"),target/"index.html"]): findings.append(Finding("medium","broken_internal_link",rel,getattr(a,"sourceline",None),href).done())
            for selector in ["script","style","nav","footer","header"]:
                for node in soup.select(selector): node.decompose()
            normalized=re.sub(r"\s+"," ",soup.get_text(" ",strip=True)).lower()
            if normalized: content_hashes[hashlib.sha256(normalized.encode()).hexdigest()].append(rel)
        if ext in {".jpg",".jpeg",".png",".webp",".gif",".tif",".tiff"} and Image:
            try:
                with Image.open(path) as im: im.verify()
                with Image.open(path) as im:
                    image_count+=1; exif=im.getexif() if hasattr(im,"getexif") else {}
                    if exif and ExifTags and any(ExifTags.TAGS.get(k)=="GPSInfo" and v for k,v in exif.items()): findings.append(Finding("high","exif_gps",rel,None,"Image contains GPS metadata").done())
                    if path.stat().st_size>2_500_000: findings.append(Finding("medium","large_image",rel,None,f"{path.stat().st_size} bytes, {im.width}x{im.height}").done())
            except Exception as exc: findings.append(Finding("high","invalid_image",rel,None,str(exc)).done())
        if ext in {".jpg",".jpeg",".png",".webp",".gif",".mp4",".mov",".pdf",".zip"}:
            try: binary_hashes[hashlib.sha256(path.read_bytes()).hexdigest()].append(rel)
            except Exception: pass
    for name,locs in funcs.items():
        unique={(x["path"],x["line"]) for x in locs}
        if len(unique)>1: findings.append(Finding("high" if name in {"doGet","doPost","onOpen","onEdit"} else "medium","duplicate_global_function",locs[0]["path"],locs[0]["line"],f"{name} defined {len(unique)} times").done())
    duplicate_pages=[{"sha256":k,"paths":v} for k,v in content_hashes.items() if len(v)>1]
    duplicate_binaries=[{"sha256":k,"paths":v} for k,v in binary_hashes.items() if len(v)>1]
    return {"profile":profile,"file_count":len(all_files),"files":all_files,"dependency_files":dependency_files,"workflow_count":len(workflows),"workflows":workflows,"symbol_count":len(symbols),"symbols":symbols,"html_count":html_count,"asset_reference_count":asset_refs,"image_count":image_count,"apps_script_manifests":manifests,"script_ids":sorted(script_ids),"global_functions":dict(funcs),"duplicate_page_groups":duplicate_pages,"duplicate_binary_groups":duplicate_binaries}

def counts(findings):
    c=collections.Counter(x.severity for x in findings); return {k:c.get(k,0) for k in ["critical","high","medium","low","info"]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--repo",type=Path,default=Path(".")); ap.add_argument("--profile",default="generic"); ap.add_argument("--out",type=Path,required=True); args=ap.parse_args()
    repo=args.repo.resolve(); out=args.out.resolve(); out.mkdir(parents=True,exist_ok=True); findings=[]
    try: run(["git","fetch","--all","--tags","--prune"],cwd=repo)
    except Exception as exc: findings.append(Finding("info","git_fetch_failed",".git",None,str(exc)).done())
    history=scan_line_history(repo,findings); head=head_audit(repo,args.profile,findings); head_sha=git(repo,"rev-parse","HEAD").strip(); repo_name=os.environ.get("GITHUB_REPOSITORY",repo.name)
    findings=list({x.fingerprint:x for x in findings}.values()); order={"critical":0,"high":1,"medium":2,"low":3,"info":4}; findings.sort(key=lambda x:(order.get(x.severity,9),x.category,x.path,x.line or 0))
    compact_history={k:v for k,v in history.items() if k!="blob_records"}; compact_head={k:v for k,v in head.items() if k not in {"files","symbols","global_functions"}}
    report={"audit_version":VERSION,"generated_at_utc":dt.datetime.now(dt.timezone.utc).isoformat(),"repository":repo_name,"profile":args.profile,"head_sha":head_sha,"coverage":compact_history,"head_analysis":compact_head,"severity_counts":counts(findings),"finding_count":len(findings),"findings":[asdict(x) for x in findings]}
    (out/"report.json").write_text(json.dumps(report,indent=2)+"\n"); (out/"line-coverage.json").write_text(json.dumps({"repository":repo_name,"head_sha":head_sha,**{k:history[k] for k in ["refs","ref_count","commit_count","unique_blob_count","text_blob_count","binary_blob_count","text_line_count","coverage_digest","blob_records"]}},indent=2)+"\n")
    (out/"files.txt").write_text("\n".join(head["files"])+"\n"); (out/"symbols.json").write_text(json.dumps(head["symbols"],indent=2)+"\n"); (out/"findings.json").write_text(json.dumps([asdict(x) for x in findings],indent=2)+"\n")
    md=[f"# Exhaustive audit — {repo_name}","",f"Generated: {report['generated_at_utc']}",f"HEAD: `{head_sha}`",f"Profile: `{args.profile}`","","## Coverage certificate","",f"- Refs: **{history['ref_count']}**",f"- Reachable commits: **{history['commit_count']}**",f"- Unique blobs: **{history['unique_blob_count']}**",f"- Text blobs read line-by-line: **{history['text_blob_count']}**",f"- Binary blobs hashed: **{history['binary_blob_count']}**",f"- Text lines inspected: **{history['text_line_count']}**",f"- Coverage digest: `{history['coverage_digest']}`","","## Findings","",*(f"- {k.title()}: **{v}**" for k,v in counts(findings).items()),"","### Highest priority"]
    for item in findings[:120]: md.append(f"- **{item.severity.upper()} — {item.category}** `{item.path}{':' + str(item.line) if item.line else ''}` — {item.message}")
    (out/"report.md").write_text("\n".join(md)+"\n")
    digest=hashlib.sha256();
    for path in sorted(out.iterdir()):
        if path.is_file(): digest.update(path.name.encode()+b"\0"+path.read_bytes())
    (out/"artifact.sha256").write_text(digest.hexdigest()+"\n")
    print(json.dumps({"repository":repo_name,"profile":args.profile,"coverage":{k:history[k] for k in ["ref_count","commit_count","unique_blob_count","text_blob_count","binary_blob_count","text_line_count","coverage_digest"]},"severity_counts":counts(findings),"finding_count":len(findings)},indent=2))

if __name__=="__main__": main()
