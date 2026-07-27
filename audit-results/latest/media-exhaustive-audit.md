# Exhaustive audit — Rauthin/media

Generated: 2026-07-27T16:06:05.061960+00:00
HEAD: `3da0eb61a781fa5ff102893442b92d54d45a278e`
Profile: `media`

## Coverage certificate

- Refs: **3**
- Reachable commits: **8**
- Unique blobs: **7**
- Text blobs read line-by-line: **5**
- Binary blobs hashed: **2**
- Text lines inspected: **444**
- Coverage digest: `fb2f1cdc6f4e13cbfeee9c12785ea871f3edefabda3569b68987b4471551bde3`

## Findings

- Critical: **0**
- High: **1**
- Medium: **17**
- Low: **0**
- Info: **1**

### Highest priority
- **HIGH — clasp_force_push** `audit/exhaustive_code_audit.py:176` — if "clasp push --force" in text: findings.append(Finding("high","force_apps_script_deploy",rel,None,"Workflow force-pushes Apps Script").done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:17` — except Exception:
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:21` — except Exception:
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:25` — except Exception:
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:171` — except Exception as exc: findings.append(Finding("high","invalid_workflow_yaml",rel,None,str(exc)).done()); data={}
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:185` — except Exception as exc: findings.append(Finding("high","python_syntax",rel,getattr(exc,"lineno",None),str(exc)).done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:192` — except Exception as exc: findings.append(Finding("high","invalid_appsscript_manifest",rel,None,str(exc)).done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:195` — except Exception as exc: findings.append(Finding("high","invalid_json",rel,None,str(exc)).done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:198` — except Exception: text=""
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:207` — except Exception as exc: findings.append(Finding("medium","invalid_jsonld",rel,getattr(schema,"sourceline",None),str(exc)).done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:230` — except Exception as exc: findings.append(Finding("high","invalid_image",rel,None,str(exc)).done())
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:233` — except Exception: pass
- **MEDIUM — broad_exception** `audit/exhaustive_code_audit.py:248` — except Exception as exc: findings.append(Finding("info","git_fetch_failed",".git",None,str(exc)).done())
- **MEDIUM — delete_trigger** `audit/exhaustive_code_audit.py:49` — ("delete_trigger", re.compile(r"(?:deleteTrigger|ScriptApp\.getProjectTriggers)"), "medium"),
- **MEDIUM — destructive_sheet_clear** `audit/exhaustive_code_audit.py:48` — ("destructive_sheet_clear", re.compile(r"\.clear(?:Contents|Format|Notes|DataValidations)?\s*\("), "medium"),
- **MEDIUM — http_url** `audit/exhaustive_code_audit.py:47` — ("http_url", re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)"), "medium"),
- **MEDIUM — http_url** `audit/exhaustive_code_audit.py:154` — if not value or value.startswith(("http://","https://","//","data:","mailto:","tel:","javascript:","#")): return None
- **MEDIUM — self_modifying_workflow** `.github/workflows/exhaustive-architecture-audit.yml` — Workflow writes commits to repository
- **INFO — todo** `audit/exhaustive_code_audit.py:51` — ("todo", re.compile(r"(?i)\b(?:TODO|FIXME|HACK|XXX)\b"), "info"),
