from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from typing import Any
from .rpc import EthRpc

IMPLEMENTATION_SLOT="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
TRANSFER_TOPIC="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628a6f55a4df523b3ef"
ENTRY_POINT="0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
HANDLE_OPS="0x1fad948c"
BASE={"getNativeOwner":"0x66b46a7a","getInstalledPlugins":"0x3a0cac56","getEntryPoint":"0x44ab613f","PLUGIN_MANAGER":"0x16feeab7","ENTRY_POINT":"0x94430fa5","getNonce":"0xd087d288","getDeposit":"0xc399ec88"}
CONFIG="0x8d112184"; HOOKS="0x642f9dd4"; PRE_HOOKS="0xceaf1309"
TARGETS={"execute":"0xb61d27f6","executeBatch":"0x34fcd5be","executeFromPlugin":"0x94ed11e7","executeFromPluginExternal":"0x38997b11","validateUserOp":"0x3a871cdd","installPlugin":"0xf85730f4","uninstallPlugin":"0xc1a221f3","upgradeTo":"0x3659cfe6","upgradeToAndCall":"0x4f1ef286"}
@dataclass(frozen=True)
class TreasuryAudit:
    address:str; from_block:str; to_block:str; report:dict[str,Any]
def _n(b:str)->int:return int(b,16) if b.startswith("0x") else int(b)
def _tag(n:int)->str:return hex(n)
def _addr(w:str)->str:return "0x"+w[-40:]
def _sel(d:Any)->str|None:return d[:10].lower() if isinstance(d,str) and d.startswith("0x") and len(d)>=10 else None
def _sha(c:str)->str|None:
    try:return hashlib.sha256(bytes.fromhex(c[2:])).hexdigest()
    except (TypeError,ValueError):return None
def _array(v:str)->list[str]:
    try:
        r=v[2:];o=int(r[:64],16)*2;n=int(r[o:o+64],16);s=o+64;return ["0x"+r[s+i*64+24:s+(i+1)*64] for i in range(n)]
    except (ValueError,IndexError):return []
def _config(v:str)->dict[str,Any]:
    try:
        r=v[2:];return {"plugin":_addr(r[:64]),"userOpValidationFunction":{"plugin":_addr(r[64:128]),"functionId":int(r[128:192],16)},"runtimeValidationFunction":{"plugin":_addr(r[192:256]),"functionId":int(r[256:320],16)}}
    except (ValueError,IndexError):return {"raw":v,"decodeError":"invalid ExecutionFunctionConfig"}
def _refs(r:str,o:int)->list[dict[str,Any]]:
    b=o*2;n=int(r[b:b+64],16);s=b+64;return [{"plugin":"0x"+r[p+24:p+64],"functionId":int(r[p+64:p+128],16)} for p in (s+i*128 for i in range(n))]
def _pre(v:str)->dict[str,Any]:
    try:r=v[2:];return {"preUserOpValidationHooks":_refs(r,int(r[:64],16)),"preRuntimeValidationHooks":_refs(r,int(r[64:128],16))}
    except (ValueError,IndexError):return {"raw":v,"decodeError":"invalid pre-validation hooks"}
def _hooks(v:str)->list[dict[str,Any]]:
    try:
        r=v[2:];b=int(r[:64],16)*2;n=int(r[b:b+64],16);s=b+64;out=[]
        for i in range(n):
            p=s+i*256;out.append({"preExecHook":{"plugin":"0x"+r[p+24:p+64],"functionId":int(r[p+64:p+128],16)},"postExecHook":{"plugin":"0x"+r[p+152:p+192],"functionId":int(r[p+192:p+256],16)}})
        return out
    except (ValueError,IndexError):return [{"raw":v,"decodeError":"invalid execution hooks"}]
def _safe(e:EthRpc,a:str,d:str,b:str)->dict[str,Any]:
    try:return {"raw":e.call({"to":a,"data":d},b).result}
    except Exception as x:return {"error":str(x)}
def _identity(e:EthRpc,a:str,b:str)->dict[str,Any]:
    raw=e.get_storage_at(a,IMPLEMENTATION_SLOT,b).result;impl=_addr(raw);code=e.get_code(impl,b).result
    out={"proxy":{"address":a,"implementationSlot":IMPLEMENTATION_SLOT,"implementation":impl},"implementation":{"address":impl,"runtimeBytecodeSha256":_sha(code),"runtimeBytecodeLengthBytes":(len(code)-2)//2 if isinstance(code,str) else None}}
    for name,sel in BASE.items():
        x=_safe(e,a,sel,b);r=x.get("raw")
        if r and name in {"getNativeOwner","getEntryPoint","PLUGIN_MANAGER","ENTRY_POINT"}:x["address"]=_addr(r)
        elif r and name=="getInstalledPlugins":x["addresses"]=_array(r)
        elif r and name in {"getNonce","getDeposit"}:
            try:x["uint256"]=int(r,16)
            except ValueError:pass
        out[name]=x
    configs={};hooks={};pre={}
    for name,t in TARGETS.items():
        arg=t[2:].ljust(64,"0");configs[name]=_safe(e,a,CONFIG+arg,b);hooks[name]=_safe(e,a,HOOKS+arg,b);pre[name]=_safe(e,a,PRE_HOOKS+arg,b)
        if "raw" in configs[name]:configs[name]["decoded"]=_config(configs[name]["raw"])
        if "raw" in hooks[name]:hooks[name]["decoded"]=_hooks(hooks[name]["raw"])
        if "raw" in pre[name]:pre[name]["decoded"]=_pre(pre[name]["raw"])
    out["executionFunctionConfigs"]=configs;out["executionHooks"]=hooks;out["preValidationHooks"]=pre
    out["upgradeAuthorization"]={"status":"unproven","upgradeSelectors":{"upgradeTo":TARGETS["upgradeTo"],"upgradeToAndCall":TARGETS["upgradeToAndCall"]},"note":"Selector presence does not establish upgrade authority."}
    return out
def _logs(e:EthRpc,p:dict[str,Any],s:int,n:int)->list[dict[str,Any]]:
    q=dict(p);q["fromBlock"]=_tag(s);q["toBlock"]=_tag(n)
    try:return e.get_logs(q).result or []
    except Exception:
        if s>=n:raise
        m=(s+n)//2;return _logs(e,p,s,m)+_logs(e,p,m+1,n)
def _transfers(e:EthRpc,a:str,s:int,n:int)->list[dict[str,Any]]:
    pad="0x"+"0"*24+a[2:];found=[]
    for topics in ([TRANSFER_TOPIC,pad,None],[TRANSFER_TOPIC,None,pad]):
        for l in _logs(e,{"topics":topics},s,n):
            t=l.get("topics",[])
            if len(t)<3:continue
            f=_addr(t[1][2:]);to=_addr(t[2][2:]);
            try:amt=str(int(l.get("data","0x0"),16))
            except ValueError:amt="0"
            found.append({"direction":"inbound" if to.lower()==a.lower() else "outbound","token":l.get("address"),"from":f,"to":to,"amount":amt,"blockNumber":l.get("blockNumber"),"transactionHash":l.get("transactionHash"),"logIndex":l.get("logIndex")})
    return list({(x["transactionHash"],x["logIndex"]):x for x in found}.values())
def _impl_history(e:EthRpc,a:str,s:int,n:int)->list[dict[str,Any]]:
    logs=_logs(e,{"address":a},s,n);blocks=sorted({_n(x["blockNumber"]) for x in logs});blocks=sorted(set([s,*blocks,n]));out=[];prev=None
    for b in blocks:
        impl=_addr(e.get_storage_at(a,IMPLEMENTATION_SLOT,_tag(b)).result)
        if impl.lower()!=str(prev).lower():out.append({"blockNumber":_tag(b),"implementation":impl,"evidence":"historical EIP-1967 storage read"});prev=impl
    return out
def _classify(e:EthRpc,h:str,a:str)->dict[str,Any]:
    tx=e.get_transaction_by_hash(h).result or {};rc=e.get_transaction_receipt(h).result or {};to=(tx.get("to") or "").lower();sel=_sel(tx.get("input"));path="direct_treasury_call" if to==a.lower() else "erc4337_handleOps" if to==ENTRY_POINT and sel==HANDLE_OPS else "indirect_or_other"
    return {"hash":h,"from":tx.get("from"),"to":tx.get("to"),"inputSelector":sel,"path":path,"status":rc.get("status"),"gasUsed":rc.get("gasUsed"),"blockNumber":tx.get("blockNumber")}
def collect_treasury_audit(e:EthRpc,address:str,from_block:str,to_block:str,*,contribution_tx:str|None=None,application_contract:str|None=None,revert_selector:str|None=None,pod_id:str|None=None)->TreasuryAudit:
    s=_n(from_block);n=_n(to_block)
    if n<s:raise ValueError("--to-block must be >= --from-block")
    ident=_identity(e,address,_tag(n));tr=_transfers(e,address,s,n);hs=sorted({x["transactionHash"] for x in tr if x.get("transactionHash")});txs=[_classify(e,h,address) for h in hs];corr={"status":"configured" if any((contribution_tx,application_contract,revert_selector,pod_id)) else "not_configured","pod":{"id":pod_id} if pod_id else None,"contribution":{"transaction":contribution_tx} if contribution_tx else None,"stateUpdate":{"contract":application_contract,"knownRevertSelector":revert_selector} if any((application_contract,revert_selector)) else None,"failures":[]}
    report={"schemaVersion":"1.0","scope":{"address":address,"fromBlock":from_block,"toBlock":to_block,"readOnly":True},"treasuryIdentity":{**ident,"implementationHistory":_impl_history(e,address,s,n)},"authority":{"nativeOwner":ident.get("getNativeOwner"),"installedPlugins":ident.get("getInstalledPlugins"),"entryPoint":ident.get("getEntryPoint"),"pluginManager":ident.get("PLUGIN_MANAGER"),"nativeExecutionPermissions":ident.get("executionFunctionConfigs"),"userOpValidation":ident.get("executionFunctionConfigs",{}).get("validateUserOp"),"runtimeValidation":ident.get("executionFunctionConfigs"),"hooks":{"execution":ident.get("executionHooks"),"preValidation":ident.get("preValidationHooks")},"upgradeAuthorization":ident.get("upgradeAuthorization")},"assetHistory":{"inbound":[x for x in tr if x["direction"]=="inbound"],"outbound":[x for x in tr if x["direction"]=="outbound"],"tokenContracts":sorted({x["token"] for x in tr}),"recipients":sorted({x["to"] for x in tr if x["direction"]=="outbound"}),"senders":sorted({x["from"] for x in tr if x["direction"]=="inbound"}),"transferCount":len(tr)},"transactionPaths":{"transactions":txs,"counts":{"directCalls":sum(x["path"]=="direct_treasury_call" for x in txs),"erc4337UserOps":sum(x["path"]=="erc4337_handleOps" for x in txs),"indirectOrOther":sum(x["path"]=="indirect_or_other" for x in txs)},"selectors":TARGETS},"applicationCorrelation":corr,"evidence":{"sourceMethod":"historical eth_getStorageAt/eth_call + eth_getLogs + transaction/receipt reads","limitations":["Upgrade authorization is unproven until source or a successful historical authorization path establishes it.","Transaction-path classification uses top-level destination/selector; embedded UserOperation decoding remains separate.","Application correlation is opt-in and does not query UnitPay/Circle APIs."]}}
    return TreasuryAudit(address,from_block,to_block,report)
def write_treasury_audit(audit:TreasuryAudit,path:str)->None:
    with open(path,"w",encoding="utf-8") as f:json.dump(audit.report,f,indent=2);f.write("\n")
