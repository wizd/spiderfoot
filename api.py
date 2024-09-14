from fastapi import FastAPI, HTTPException, Query, Path, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootHelpers
from spiderfoot.db import SpiderFootDb
import time
import os
from datetime import datetime, timedelta

# 从环境变量获取服务器URL,如果未设置则使用默认值
server_url = os.getenv("SPIDERFOOT_SERVER_URL", "http://localhost:7000")

app = FastAPI(
    title="SpiderFoot API", 
    description="API for SpiderFoot OSINT tool",
    version="1.0.0",
    servers=[
        {"url": server_url, "description": "SpiderFoot API Server"}
    ]
)

# 数据模型
class ScanInfo(BaseModel):
    id: str
    name: str
    status: str

class EventType(BaseModel):
    event: str
    event_descr: str
    event_raw: int
    event_type: str

class SearchResult(BaseModel):
    generated: float
    data: str
    module: str
    type: str

class ScanOptions(BaseModel):
    scanname: str
    scantarget: str
    usecase: str
    modulelist: Optional[str] = None
    typelist: Optional[str] = None

class ScanInstance(BaseModel):
    guid: str
    name: str
    seed_target: str
    created: int
    started: int
    ended: int
    status: str

# 辅助函数
import os

def get_db():
    data_path = os.getenv("SPIDERFOOT_DB_PATH", os.path.join(os.path.expanduser("~"), ".spiderfoot", "spiderfoot.db"))
    db_dir = os.path.dirname(data_path)
    os.makedirs(db_dir, exist_ok=True)
    
    # 确保目录有正确的权限
    os.chmod(db_dir, 0o755)
    
    return SpiderFootDb({"__database": data_path})

def get_sf():
    return SpiderFoot(dict())

# 应用启动事件
@app.on_event("startup")
async def startup_event():
    try:
        dbh = get_db()
        dbh.scanInstanceList()
    except Exception as e:
        print(f"Error connecting to database: {e}")
        exit(1)

# API端点
@app.get("/scanlist", response_model=List[ScanInfo])
def scan_list():
    """List all previously run scans."""
    try:
        dbh = get_db()
        scans = dbh.scanInstanceList()
        return [ScanInfo(id=scan[0], name=scan[1], status=scan[6]) for scan in scans]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/eventtypes", response_model=List[EventType])
def event_types():
    """List all event types."""
    try:
        dbh = get_db()
        types = dbh.eventTypes()
        return [EventType(event=t[0], event_descr=t[1], event_raw=t[2], event_type=t[3]) for t in types]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/modules")
def modules():
    """List all modules."""
    sf = get_sf()
    modinfo = sf.modulesProducing([])
    return [{"name": m, "descr": sf.moduleDesc(m)} for m in modinfo]

@app.get("/ping")
def ping():
    """For the CLI to test connectivity to this server."""
    return ["SUCCESS", SpiderFoot.__version__]

@app.get("/scanstatus/{id}")
def scan_status(id: str = Path(..., description="Scan ID")):
    """Get the status of a scan."""
    try:
        dbh = get_db()
        return dbh.scanInstanceGet(id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/scansummary/{id}")
def scan_summary(id: str = Path(..., description="Scan ID"), by: str = Query("type", description="Group by type or module")):
    """Summary of scan results."""
    try:
        dbh = get_db()
        return dbh.scanResultSummary(id, by)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/scaneventresults/{id}")
def scan_event_results(
    id: str = Path(..., description="扫描ID"),
    eventType: Optional[str] = Query(None, description="事件类型过滤"),
    filterfp: bool = Query(False, description="过滤误报")
):
    """获取扫描事件结果。"""
    try:
        dbh = get_db()
        # 如果 eventType 为 None，则将其设置为 'ALL'
        eventType = eventType or 'ALL'
        raw_results = dbh.scanResultEvent(id, eventType, filterFp=filterfp)
        
        # 将原始结果转换为结构化的字典列表
        formatted_results = [
            {
                "type": result[0],
                "module": result[1],
                "data": result[2],
                "source_event": result[3],
                "source_event_hash": result[4],
                "confidence": result[5],
                "visibility": result[6],
                "risk": result[7],
                "false_positive": result[8],
                "last_seen": result[9],
                "source_data": result[10],
                "source_module": result[11]
            }
            for result in raw_results
        ]
        
        return {"results": formatted_results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"数据库错误：{str(e)}")

@app.post("/startscan")
def start_scan(scan_options: ScanOptions):
    """Initiate a scan."""
    sf = get_sf()
    dbh = get_db()
    
    scanId = SpiderFootHelpers.genScanInstanceId()
    try:
        sf.dbh = dbh
        sf.scanId = scanId
        sf.targetValue = scan_options.scantarget
        sf.targetType = SpiderFootHelpers.targetTypeFromString(scan_options.scantarget)
        
        # Start the scan
        # Note: This is a simplified version. You might need to adjust this based on your actual implementation
        sf.start()
        
        return {"scanId": scanId}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/stopscan/{id}")
def stop_scan(id: str = Path(..., description="Scan ID")):
    """Stop a scan."""
    try:
        dbh = get_db()
        scan = dbh.scanInstanceGet(id)
        if scan[5] in ["FINISHED", "ABORTED", "ERROR-FAILED"]:
            raise HTTPException(status_code=400, detail="Scan is not running.")
        dbh.scanInstanceSet(id, status="ABORTED")
        return {"message": "Scan aborted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/scandelete/{id}")
def scan_delete(id: str = Path(..., description="Scan ID")):
    """Delete a scan."""
    try:
        dbh = get_db()
        dbh.scanInstanceDelete(id)
        return {"message": "Scan deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scanhistory/{id}")
def scan_history(id: str = Path(..., description="扫描ID")):
    """获取扫描的历史数据。"""
    try:
        dbh = get_db()
        raw_history = dbh.scanResultHistory(id)
        
        # 获取扫描开始时间
        scan_info = dbh.scanInstanceGet(id)
        if not scan_info:
            raise ValueError("无法获取扫描信息")
        scan_start_time = datetime.fromtimestamp(scan_info[3])  # 假设 scanInstanceGet 返回的第四个元素是开始时间
        
        def format_relative_timestamp(ts, start_time):
            try:
                hour, minute, day = ts.split()
                hour, minute = map(int, hour.split(':'))
                day = int(day)
                
                # 计算相对时间
                relative_time = start_time + timedelta(days=day, hours=hour, minutes=minute)
                return relative_time.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return str(ts)
        
        # 转换原始数据为更有意义的格式，并显示完整的时间戳
        formatted_history = [
            {
                "timestamp": format_relative_timestamp(item[0], scan_start_time),
                "event_type": item[1],
                "count": item[2]
            }
            for item in raw_history
        ]
        
        return {"history": formatted_history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"数据库错误：{str(e)}")

@app.get("/search/{id}")
def search(
    id: str = Path(..., description="Scan ID"),
    eventType: Optional[str] = Query(None, description="Event type filter"),
    value: Optional[str] = Query(None, description="Value to search for")
):
    """Search scan results."""
    try:
        dbh = get_db()
        criteria = {"scan_id": id}
        if eventType:
            criteria["type"] = eventType
        if value:
            criteria["value"] = value
        return dbh.search(criteria)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scanconfig/{id}")
def scan_config_set(id: str = Path(..., description="Scan ID"), config: Dict[str, Any] = Body(...)):
    """Set configuration for a scan."""
    try:
        dbh = get_db()
        dbh.scanConfigSet(id, config)
        return {"message": "Scan configuration updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scanconfig/{id}")
def scan_config_get(id: str = Path(..., description="Scan ID")):
    """Get configuration for a scan."""
    try:
        dbh = get_db()
        return dbh.scanConfigGet(id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scanopts")
def scan_opts(id: str = Body(..., embed=True)):
    """Return configuration used for a scan."""
    try:
        dbh = get_db()
        return dbh.scanConfigGet(id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scaneventresultsunique/{id}")
def scan_event_results_unique(
    id: str = Path(..., description="扫描ID"),
    eventType: str = Query(..., description="事件类型"),
    filterfp: bool = Query(False, description="过滤误报")
):
    """获取扫描的唯一结果，按事件类型筛选。"""
    try:
        dbh = get_db()
        raw_results = dbh.scanResultEventUnique(id, eventType, filterfp)
        
        # 将原始结果转换为结构化的字典列表
        formatted_results = [
            {
                "value": result[0],
                "type": result[1],
                "count": result[2]
            }
            for result in raw_results
        ]
        
        return {"results": formatted_results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"数据库错误：{str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7000)