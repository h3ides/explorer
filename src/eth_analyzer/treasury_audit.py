from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from .rpc import EthRpc

IMPLEMENTATION_SLOT="0x360894a13ba1a3210667c828492db98dca3a3ca3ca3ca3ca3ca3ca3ca3ca3ca3"
TRANSFER_TOPIC="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ENTRY_POINT="0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
HANDLE_OPS="0x1fad948c"
BASE={"getNativeOwner":"0x66b46a7a","getInstalledPlugins":"0x3a0cac56","getEntryPoint":"0x44ab613f","PLUGIN_MANAGER":"0x16feeab7","ENTRY_POINT":"0x94430fa5","getNonce":"0xd087d288","getDeposit":"0xc399ec88"}
CONFIG="0x8d112184"; HOOKS="0x642f9dd4"; PRE_HOOKS="0xceaf1309"
TARGETS={"execute":"0xb61d27f6","executeBatch":"0x34fcd5be","executeFromPlugin":"0x94ed11e7","executeFromPluginExternal":"0x38997b11","validateUserOp":"0x3a871cdd","installPlugin":"0xf85730f4","uninstallPlugin":"0xc1a221f3","upgradeTo":"0x3659cfe6","upgradeToAndCall":"0x4f1ef286"}

@dataclass(frozen=True)
class TreasuryAudit:
    address:str; from_block:str; to_block:str; report:dict[str,Any]

def _n(block:str)->int: return int(block,16) if block.startswith("0x") else int(block)
def _tag(block:int)->str: return hex(block)
def _addr(word:str)->str: return "0x"+word[-40:]
def _sel(data:Any)->str|None: return data[:10].lower() if isinstance(data,str) and data.startswith("0x") and len(data)>=10 else None

def _sha(code:str)->str|None:
    try:return hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()
    except (TypeError,ValueError):return None

def _array(value:str)->list[str]:
    try:
        raw=value[2:]; off=int(raw[:64],16)*2; count=int(raw[off:off+64],16); base=off+64
        return ["0x"+raw[base+i*64+24:base+(i+1)*64] for i in range(count)]
    except (ValueError,IndexError):return []

def _config(value:str)->dict[str,Any]:
    try:
        r=value[2:]; return {"plugin":_addr(r[:64]),"userOpValidationFunction":{"plugin":_addr(r[64:128]),"functionId":int(r[128:192],16)},"runtimeValidationFunction":{"plugin":_addr(r[192:256]),"functionId":int(r[256:320],16)}}
    except (ValueError,IndexError):return {"raw":value,"decodeError":"invalid ExecutionFunctionConfig"}

def _refs(raw:str,offset:int)->list[dict[str,Any]]:
    base=offset*2; count=int(raw[base:base+64],16); start=base+64
    return [{"plugin":"0x"+raw[p+24:p+64],"functionId":int(raw[p+64:p+128],16)} for p in (start+i*128 for i in range(count))]

def _pre_hooks(value:str)->dict[str,Any]:
    try:
        raw=value[2:]; return {"preUserOpValidationHooks":_refs(raw,int(raw[:64],16)),"preRuntimeValidationHooks":_refs(raw,int(raw[64:128],16))}
    except (ValueError,IndexError):return {"raw":value,"decodeError":"invalid pre-validation hooks"}

def _exec_hooks(value:str)->list[dict[str,Any]]:
    try:
        raw=value[2:]; base=int(raw[:64],16)*2; count=int(raw[base:base+64],16); start=base+64; out=[]
        for i in range(count):
            p=start+i*256; out.append({"preExecHook":{"plugin":"0x"+raw[p+24:p+64],"functionId":int(raw[p+64:p+128],16)},"postExecHook":{"plugin":"0x"+raw[p+152:p+192],"functionId":int(raw[p+192:p+256],16)}})
        return out
    except (ValueError,IndexError):return [{"raw":value,"decodeError":"invalid execution hooks"}]

def _safe(eth:EthRpc,address:str,data:str,block:str)->dict[str,Any]:
    try:return {"raw":eth.call({"to":address,"data":data},block).result}
    except Exception as exc:return {"error":str(exc)}

def _identity(eth:EthRpc,address:str,block:str)->dict[str,Any]:
    slot=eth.get_storage_at(address,IMPLEMENTATION_SLOT,block).result; impl=_addr(slot); code=eth.get_code(impl,block).result
    out={"proxy":{"address":address,"implementationSlot":IMPLEMENTATION_SLOT,"implementation":impl},"implementation":{"address":impl,"runtimeBytecodeSha256":_sha(code),"runtimeBytecodeLengthBytes":(len(code)-2)//2 if isinstance(code,str) else None}}
    for name,sel in BASE.items():
        e=_safe(eth,address,sel,block); raw=e.get("raw")
        if raw and name in {"getNativeOwner","getEntryPoint","PLUGIN_MANAGER","ENTRY_POINT"}:e["address"]=_addr(raw)
        elif raw and name=="getInstalledPlugins":e["addresses"]=_array(raw)
        elif raw and name in {"getNonce","getDeposit"}:
            try:e["uint256"]=int(raw,16)
            except ValueError:pass
        out[name]=e
    configs={}; hooks={}; pre={}
    for name,target in TARGETS.items():
        arg=target[2:].ljust(64,"0"); configs[name]=_safe(eth,address,CONFIG+arg,block); hooks[name]=_safe(eth,address,HOOKS+arg,block); pre[name]=_safe(eth,address,PRE_HOOKS+arg,block)
        if "raw" in configs[name]:configs[name]["decoded"]=_config(configs[name]["raw"])
        if "raw" in hooks[name]:hooks[name]["decoded"]=_exec_hooks(hooks[name]["raw"])
        if "raw" in pre[name]:pre[name]["decoded"]=_pre_hooks(pre[name]["raw"])
    out["executionFunctionConfigs"]=configs; out["executionHooks"]=hooks; out["preValidationHooks"]=pre
    out["upgradeAuthorization"]={"status":"unproven","upgradeSelectors":{"upgradeTo":TARGETS["upgradeTo"],"upgradeToAndCall":TARGETS["upgradeToAndCall"]},"note":"Selector presence does not establish upgrade authority."}
    return out

def _logs(eth:EthRpc,params:dict[str,Any],start:int,end:int)->list[dict[str,Any]]:
    p=dict(params); p["fromBlock"]=_tag(start); p["toBlock"]=_tag(end)
    try:return eth.get_logs(p).result or []
    except Exception:
        if start>=end:raise
        mid=(start+end)//2; return _logs(eth,params,start,mid)+_logs(eth,params,mid+1,end)

def _transfers(eth:EthRpc,address:str,start:int,end:int)->list[dict[str,Any]]:
    padded="0x"+"0"*24+address[2:]; found=[]
    for topics in ([TRANSFER_TOPIC,padded,None],[TRANSFER_TOPIC,None,padded]):
        for log in _logs(eth,{"topics":topics},start,end):
            t=log.get("topics",[])
            if len(t)<3:continue
            frm=_addr(t[1][2:]); to=_addr(t[2][2:])
            try:amount=str(int(log.get("data","0x0"),16))
            except ValueError:amount="0"
            found.append({"direction":"inbound" if to.lower()==address.lower() else "outbound","token":log.get("address"),"from":frm,"to":to,"amount":amount,"blockNumber":log.get("blockNumber"),"transactionHash":log.get("transactionHash"),"logIndex":log.get("logIndex")})
    return list({(x["transactionHash"],x["logIndex"]):x for x in found}.values())

def _implementation_history(eth:EthRpc,address:str,start:int,end:int)->list[dict[str,Any]]:
    logs=_logs(eth,{"address":address},start,end); blocks=sorted({_n(x["blockNumber"]) for x in logs}); blocks=sorted(set([start,*blocks,end])); history=[]; previous=None
    for block in blocks:
        impl=_addr(eth.get_storage_at(address,IMPLEMENTATION_SLOT,_tag(block)).result)
        if impl.lower()!=str(previous).lower():history.append({"blockNumber":_tag(block),"implementation":impl,"evidence":"historical EIP-1967 storage read"}); previous=impl
    return history

def _classify(eth:EthRpc,tx_hash:str,treasury:str)->dict[str,Any]:
    tx=eth.get_transaction_by_hash(tx_hash).result or {}; receipt=eth.get_transaction_receipt(tx_hash).result or {}; to=(tx.get("to") or "").lower(); sel=_sel(tx.get("input")); path="direct_treasury_call" if to==treasury.lower() else "erc4337_handleOps" if to==ENTRY_POINT and sel==HANDLE_OPS else "indirect_or_other"
    return {"hash":tx_hash,"from":tx.get("from"),"to":tx.get("to"),"inputSelector":sel,"path":path,"status":receipt.get("status"),"gasUsed":receipt.get("gasUsed"),"blockNumber":tx.get("blockNumber")}

def collect_treasury_audit(eth:EthRpc,address:str,from_block:str,to_block:str,*,contribution_tx:str|None=None,application_contract:str|None=None,revert_selector:str|None=None,pod_id:str|None=None)->TreasuryAudit:
    start=_n(from_block); end=_n(to_block)
    if end<start:raise ValueError("--to-block must be >= --from-block")
    final=_tag(end); identity=_identity(eth,address,final); transfers=_transfers(eth,address,start,end); hashes=sorted({x["transactionHash"] for x in transfers if x.get("transactionHash")}); txs=[_classify(eth,h,address) for h in hashes]; inbound=[x for x in transfers if x["direction"]=="inbound"]; outbound=[x for x in transfers if x["direction"]=="outbound"]
    correlation={"status":"configured" if any((contribution_tx,application_contract,revert_selector,pod_id)) else "not_configured","pod":{"id":pod_id} if pod_id else None,"contribution":{"transaction":contribution_tx} if contribution_tx else None,"stateUpdate":{"contract":application_contract,"knownRevertSelector":revert_selector} if any((application_contract,revert_selector)) else None,"failures":[]}
    report={"schemaVersion":"1.0","scope":{"address":address,"fromBlock":from_block,"toBlock":to_block,"readOnly":True},"treasuryIdentity":{**identity,"implementationHistory":_implementation_history(eth,address,start,end)},"authority":{"nativeOwner":identity.get("getNativeOwner"),"installedPlugins":identity.get("getInstalledPlugins"),"entryPoint":identity.get("getEntryPoint"),"pluginManager":identity.get("PLUGIN_MANAGER"),"nativeExecutionPermissions":identity.get("executionFunctionConfigs"),"userOpValidation":identity.get("executionFunctionConfigs",{}).get("validateUserOp"),"runtimeValidation":identity.get("executionFunctionConfigs"),"hooks":{"execution":identity.get("executionHooks"),"preValidation":identity.get("preValidationHooks")},"upgradeAuthorization":identity.get("upgradeAuthorization")},"assetHistory":{"inbound":inbound,"outbound":outbound,"tokenContracts":sorted({x["token"] for x in transfers}),"recipients":sorted({x["to"] for x in outbound}),"senders":sorted({x["from"] for x in inbound}),"transferCount":len(transfers)},"transactionPaths":{"transactions":txs,"counts":{"directCalls":sum(x["path"]=="direct_treasury_call" for x in txs),"erc4337UserOps":sum(x["path"]=="erc4337_handleOps" for x in txs),"indirectOrOther":sum(x["path"]=="indirect_or_other" for x in txs)},"selectors":TARGETS},"applicationCorrelation":correlation,"evidence":{"sourceMethod":"historical eth_getStorageAt/eth_call + eth_getLogs + transaction/receipt reads","limitations":["Upgrade authorization is intentionally unproven until source or a successful historical authorization path establishes it.","Transaction-path classification is based on top-level transaction destination/selector; embedded UserOperation decoding remains a separate transaction-analysis concern.","Application correlation is opt-in and does not query UnitPay/Circle APIs."]}}
    return TreasuryAudit(address,from_block,to_block,report)

def write_treasury_audit(audit:TreasuryAudit,path:str)->None:
    with open(path,"w",encoding="utf-8") as fh:json.dump(audit.report,fh,indent=2); fh.write("\n")
