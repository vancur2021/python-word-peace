#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import asyncio
import aiohttp
import logging
import time
import ipaddress
from datetime import datetime, timezone, timedelta
from aiohttp import web

# 环境变量
UUID = os.environ.get('UUID', 'b8596c11-691a-4f72-b05d-d867e60af1c6')   # 节点UUID
WSPATH = os.environ.get('WSPATH', 'b8596c11')          # 节点路径
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)  # http和ws端口，默认自动优先获取容器分配的端口
DEBUG = os.environ.get('DEBUG', '').lower() == 'true' # 保持默认,调试使用,true开启调试

BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# 全局 DNS 缓存 与 全局复用 Session、限流器 (防止 Serverless OOM 及 FD 耗尽)
DNS_CACHE = {}
DNS_CACHE_TTL = 300  # 缓存 5 分钟
MAX_DNS_CACHE_SIZE = 1000  # 防止 Serverless 内存泄露的最大条目数
MAX_CONCURRENT_CONNECTIONS = 500  # 最大同时连接数限制，保护底层文件描述符
GLOBAL_DOH_SESSION = None  # 全局 DoH Session，复用 TLS 握手连接池
global_semaphore = None  # 并发控制锁

# 设置日志时间为东八区 (北京时间)
def get_beijing_time(*args):
    timestamp = args[-1] if args else None
    utc_dt = datetime.fromtimestamp(timestamp, timezone.utc) if timestamp else datetime.now(timezone.utc)
    return utc_dt.astimezone(timezone(timedelta(hours=8))).timetuple()

logging.Formatter.converter = get_beijing_time

# 日志级别
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 禁用访问,连接等日志
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def req_doh(host: str, url: str) -> str:
    global GLOBAL_DOH_SESSION
    if GLOBAL_DOH_SESSION is None or GLOBAL_DOH_SESSION.closed:
        # 建立具备连接池复用能力的 Session
        conn = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        GLOBAL_DOH_SESSION = aiohttp.ClientSession(connector=conn)
        
    try:
        async with GLOBAL_DOH_SESSION.get(url, headers={'accept': 'application/dns-json'}, timeout=2.5) as resp:
            if resp.status == 200:
                data = await resp.json()
                if data.get('Status') == 0 and data.get('Answer'):
                    for answer in data['Answer']:
                        if answer.get('type') == 1:
                            return answer.get('data')
    except Exception:
        pass
    return None

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass
    
    # DNS LRU 缓存检查
    now = time.time()
    if host in DNS_CACHE:
        ip, exp = DNS_CACHE[host]
        if now < exp:
            return ip
        else:
            del DNS_CACHE[host]
    
    # 内存保护机制：如果堆积的老化记录超过限制，强制清空 30% 最旧条目或直接清空
    if len(DNS_CACHE) > MAX_DNS_CACHE_SIZE:
        # 为了极致性能，不排序，直接随机弹出一半
        for k in list(DNS_CACHE.keys())[:MAX_DNS_CACHE_SIZE // 2]:
            DNS_CACHE.pop(k, None)

    doh_urls = [
        f'https://cloudflare-dns.com/dns-query?name={host}&type=A',
        f'https://dns.google/resolve?name={host}&type=A'
    ]
    
    tasks = [asyncio.create_task(req_doh(host, url)) for url in doh_urls]
    
    async def sys_resolve():
        try:
            loop = asyncio.get_event_loop()
            # 给底层耗尽线程池的原生解析加上硬性超时挂起
            info = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_INET), 
                timeout=1.5
            )
            if info:
                return info[0][4][0]
        except:
            pass
        return None
    
    tasks.append(asyncio.create_task(sys_resolve()))
    
    try:
        while tasks:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED, timeout=2.5)
            for task in done:
                try:
                    res = task.result()
                    if res:
                        for p in pending:
                            p.cancel()
                        DNS_CACHE[host] = (res, now + DNS_CACHE_TTL)
                        return res
                except Exception:
                    pass
            tasks = list(pending)
            if not pending:
                break
    except:
        pass
        
    return host

class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid_bytes = bytes.fromhex(uuid)

    async def _forward_data(self, websocket, resolved_host, port, early_data=b''):
        """核心双向数据透传模块，已全面执行底层的反 NAT 优化"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_host, port), timeout=10.0
            )
            
            # --- [ TCP 底层双重优化开始 ] ---
            sock = writer.get_extra_info('socket')
            if sock is not None:
                try:
                    # 1. 禁用 Nagle 算法 (TCP_NODELAY)，极致降低节点中转时的首包延迟 Ping 值
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    # 2. 强制开启 TCP Keep-Alive，强力抵御网络中间件或云平台网关切断空闲连接
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    # 3. 针对各种底层宿主机，植入更激进的 Linux 原生 KeepAlive 探针
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                    if hasattr(socket, 'TCP_KEEPINTVL'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    if hasattr(socket, 'TCP_KEEPCNT'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                except Exception as e:
                    if DEBUG:
                        logger.warning(f"Failed to set socket options: {e}")
            # --- [ TCP 底层双重优化结束 ] ---
            
            if early_data:
                writer.write(early_data)
                await writer.drain()

            task1 = asyncio.create_task(self.forward_ws_to_tcp(websocket, writer))
            task2 = asyncio.create_task(self.forward_tcp_to_ws(reader, websocket))
            
            # 解决死等隐患：一方结束或断开后，另一方最多允许收尾 5 秒，否则强行被主控协程回收
            done, pending = await asyncio.wait(
                [task1, task2],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 宽恕期等待优雅半关闭
            if pending:
                for task in pending:
                    try:
                        await asyncio.wait_for(task, timeout=5.0)
                    except asyncio.TimeoutError:
                        task.cancel()
                    except Exception as e:
                        if DEBUG and not isinstance(e, (ConnectionResetError, BrokenPipeError, asyncio.CancelledError)):
                            logger.error(f"Error during half-close gracefully wait: {e}")
                
        except asyncio.TimeoutError:
            if DEBUG:
                logger.error(f"Connection timeout to {resolved_host}:{port}")
        except Exception as e:
            if DEBUG:
                logger.error(f"Connection error to {resolved_host}:{port} -> {e}")
        finally:
            # 无论出现任何异常，最终兜底清理，防止雪崩泄露
            if 'writer' in locals():
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
            if not websocket.closed:
                await websocket.close()
            if 'task1' in locals() and not task1.done():
                task1.cancel()
            if 'task2' in locals() and not task2.done():
                task2.cancel()

    async def forward_ws_to_tcp(self, websocket, writer):
        try:
            async for msg in websocket:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if DEBUG and not isinstance(e, (ConnectionResetError, BrokenPipeError, asyncio.CancelledError)):
                logger.debug(f"WS to TCP Forward Exception: {e}")
        finally:
            try:
                # 实现优雅的 TCP 半关闭 (Half-Close)，主动触发 FIN 流但依然能持续接收 TCP 剩余返程数据
                if writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass
                
    async def forward_tcp_to_ws(self, reader, websocket):
        try:
            while True:
                # 将 4KB 缓冲扩容到了 64KB，极大改善看视频和下载大文件吞吐量并显著降低 CPU 使用度
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send_bytes(data)
                
                # --- [ 大文件满速下载级 OOM 防御：手动注入下行读写背压 (Manual Backpressure) ] ---
                # Aiohttp WebSocket 对象在极其暴力的下载吞吐且外网发包缓慢时，底层 _writer 会累积惊人内存数据。
                # 设置极客级的高通透防爆闸：挂起发送队列如果大于 2MB (2 * 1024 * 1024 = 2097152 bytes)
                # 即代表底层外网物理带宽完全吃满发不出去，强制休眠当前协程 10 毫秒，阻断 TCP 疯狂抢读，倒逼源头降速。
                try:
                    if websocket._writer and hasattr(websocket._writer, 'transport'):
                        transport = websocket._writer.transport
                        if transport:
                            # 侦测底层物理 Socket 发送缓冲带的挂起尺寸
                            pending_size = transport.get_write_buffer_size()
                            while pending_size > 2097152: # > 2MB  
                                await asyncio.sleep(0.01)
                                if websocket.closed:
                                    break
                                pending_size = transport.get_write_buffer_size()
                except Exception:
                    # 获取底层挂起数据量失败不阻断核心主干，保证不同操作系统的绝对兼容
                    pass
                # --- [ 防御结束 ] ---
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if DEBUG and not isinstance(e, (ConnectionResetError, BrokenPipeError, asyncio.CancelledError)):
                logger.debug(f"TCP to WS Forward Exception: {e}")
        finally:
            try:
                if not websocket.closed:
                    await websocket.close()
            except Exception:
                pass

    async def handle_vless(self, websocket, first_msg: bytes) -> bool:
        """纯净且极限运行的 VLESS 协议直接解析器"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            cmd = first_msg[first_msg[17] + 18]
            if cmd != 1:  # 仅支持 TCP (0x01)
                return False
                
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            host = ''
            if atyp == 1:
                if i + 4 > len(first_msg): return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:
                if i >= len(first_msg): return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg): return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:
                if i + 16 > len(first_msg): return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            
            await self._forward_data(websocket, resolved_host, port, first_msg[i:])
            return True
            
        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False

async def websocket_handler(request):
    global global_semaphore
    if global_semaphore is None:
        global_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
        
    # 高能限流熔断保护：并发若超载，瞬间闪电防御，秒抛连接防雪崩
    if global_semaphore.locked():
        if DEBUG:
            logger.warning("Max concurrent connections reached. Dropping new connection.")
        return web.Response(status=503, text="Service Unavailable")

    # 增加 heartbeat 控制 (25秒)，防止 PaaS/Serverless 平台的系统网关自杀式断开长连接
    ws = web.WebSocketResponse(heartbeat=25.0)
    await ws.prepare(request)
    CUUID = UUID.replace('-', '')
    path = request.path
    
    if path != f'/{WSPATH}':
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID)
    
    # 进入并发管辖区
    await global_semaphore.acquire()
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        
        # 移除臃肿杂质，所有的协议判断全被砍掉，只要满足最低长度，强制当作 VLESS 进行高速纯内存解析
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await proxy.handle_vless(ws, msg_data):
                return ws
        
        await ws.close()
        
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
        await ws.close()
    finally:
        # 释放并发令牌
        global_semaphore.release()
    
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except:
            return web.Response(text='Hello world!', content_type='text/html')
    
    return web.Response(status=404, text='Not Found\n')

async def main():
    actual_port = PORT
    
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    
    app = web.Application()
    
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"✅ server is running on port {actual_port}")
    
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        global GLOBAL_DOH_SESSION
        if GLOBAL_DOH_SESSION and not GLOBAL_DOH_SESSION.closed:
            await GLOBAL_DOH_SESSION.close()
        await runner.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
