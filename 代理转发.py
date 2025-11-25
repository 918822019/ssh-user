import base64
import io
import logging
import socket
import threading
import time
from typing import Tuple, Optional

import paramiko
from paramiko.ssh_exception import SSHException

# ==================== 配置参数 ====================
LISTEN_PORT = 33000
LISTEN_HOST = "0.0.0.0"
REAL_SSH_HOST = "localhost"
REAL_SSH_PORT = 2222

# ==================== 超时配置（统一定义）====================
SOCKET_TIMEOUT = 100        # Socket操作超时
SSH_HANDSHAKE_TIMEOUT = 5  # SSH握手超时（包括密钥交换和认证）
CHANNEL_ACCEPT_TIMEOUT = 10  # 等待通道超时

# HTTP 404 响应
FAKE_HTTP_RESPONSE = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

# ==================== 服务器私钥配置（代码内管理）====================
# 生成方式: ssh-keygen -t rsa -b 2048 -f ssh_host_key -N ""
# 或使用下面的示例私钥（测试用）
SERVER_PRIVATE_KEY_RSA = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA9gPqSHemj9IyRo3cZdnDxlgjq32dNzWJ0kSWmQ6GZw0vEafR
XGLJdX1zXzYR+is70IEU9J1G1HzkSyyZOE8A/HrkjsUJZLZsJFO+kxUnL+IdC/RV
5LvR/1fM0KFHJo5PPSDDgm9P0hWvl7gzEHkTiNV4k63LjaltQoQARLg2qfFQk8nv
9SBo6+KMOs+A4JeImt+IGSkVmjZ92A8FjbXb9FMKc2D44mMCE45ymy9z4lPvoD6x
bb6ybe9AFo4XEeyB8dZ5WLVRWr2+cmVLJUWMKpqMNCACQRlb50FHyz7l67B8VUtC
CFEWzDaag2Lc9h01DVKHS6HbPAK09Ws3gdKlZQIDAQABAoIBAQCivXpIz+W99AVQ
CN3H/mL0nS+TbPgIIoF2N+sLesFMADunyUTEgZDVCNS+Ig2IWPsrdYhAPJ4zSB7Y
37rHtfNoEX+KNit9lPM6oK9Lqs2OblxaoRoEwn4rFJCnXlir163xOPA8I5hA2Bmd
Gruk5QMYHGa0Al7J6k8dliZ7TwTSK0TlAnZUBjaymQU01VtiHOZ9c4z2CgMOiF6R
7HYulTqAlhR1ZdchU0nZBG3wWKVoPW95/Wx6FkGq+mTTEHZRRE6dAYesq6DZu2qA
sSYuYwavTqm69jkG6u2wb65p2+YWbYS67uPiwtc37xKzuw0Iim7w+AdKb8ZE6LCI
DYbJ1Q4BAoGBAPsCEocIOqratNyXZUwFB70Wb9dS9ql0O8PBChc4wAxUezEk52L1
I2+K47fwlZn+hFL3nju1xPpGrGd02qpOa6u0axBWWjaho5ZwGguVoz6+eHDHn8gR
jIzVFxPtKVfmcSuMsoAIUd6NzzPhNa6wkQe68LMDahyIL0XrHHTKKYuBAoGBAPro
bG0P2hZsx1dxIuJrwShG73Ltcp8F0XTH83IUDkfpG+7yElDQQhY/zynRWiS2hT1w
F8GMPRXOM4woth2DnP4gXbZjJigvMeekyMKUDLphNPeu2ZH4BQH51YIF59+4Zt3M
a2QDEDJdG7Zt2QSbuny5YKcQjoVUynejtS2XElvlAoGBAN396jbkb0Z14OkLOHpw
JHT15/oOlLovYz/wdSUueqMtADrpgX7CgRGAS399VkH4mDzsZFQ4oTob0RQ6g72F
V7JnAR1U0bppYE2HXXGLaPHv8IMF+ekupBhVyXBFGoBz/PjgGWokcYub7Xnbnued
ntawXXpk9a7APtbeZa9gsDeBAoGBAKqd5CUhk2aOX9tpNpSLO5T875TSPJBAb5ce
5L+dPbzOmk0Y1TWY+GeSynegQdEXQHFvyOe3Sk6KomjbwkM9nUL9lVwR/f9zYFcp
qc8Ox7zxnwgSISbuZdFbJ0G8bFmoVmLav+gJYTkuMUsTVXCZyO1JTZ0tWAz4hJlo
fCpdQYG1AoGAVPNQW6WeE7qZwPmnrBF6qArSmFYI8f538hsOa4stJEWCO9f9+c5M
wv6eTGscx5NFy2/2/Rx/LLavbgmpccuZ6p6FUjsOOt+f7uEqX/K6LYy8cYzfFV1B
UuEd5vqsbyvFmOH+DaKG9hoDZvOqQTgcPt5dU1ppVRrEmUPwMKjx06c=
-----END RSA PRIVATE KEY-----"""

# 授权的客户端公钥（在代码中管理）
AUTHORIZED_CLIENT_KEYS = [
    # ssh-rsa 格式的公钥
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD1o34PflhtwLvByFa5BPdHAwnkKRmW4TTab5Xuh+3m7PEnCwqDX1WyaJoJsHoGcGzncQIYFvzlbyBhF4BSKcNs5YEkUU26uxB9qQbqxj90ckURruJ72xQ31zcq4iE5dL6bUapnlJXzuXPkF5xp+p7VHt04W/DSrMxmXwUXRJisVpcaQzz0ZKppFp1Rp5FURfDx0VNWlvSpHn7ihiWHz8z/cScliu9F8lIAg7oT3qYFSIAJRKArKS3mJXpZduOmzdgBmizFqrxbSHh6ciz1eC2/jyurTgZwK42HY0R6TLt1F/yKpi8sIN8aMsHJRzmg45S3vQozRpZlftlNHfNCspM9rgDpuGr2Trgzy/5l/NVSdSNQVpxxk/b1V0CHkrZSegQ1H7zfFO+X2XgXXCZu0XNNI1MxbejFiK6DzS7LOvx1k6uQg9r6ay9CzKql/FAJwKkt+DY5DL4l0iY/7kFpmpJ4oalseZwv9u+tsyQbQtwr/L1SwNSOJH2kQVM2Rq+zvIs= bytedance@M52H709YV1",
    # 可添加更多授权的公钥
]

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("ssh_proxy.log")]
)
logger = logging.getLogger(__name__)


# ==================== 核心代理类 ====================
class SSHProxyWithRSA:
    """SSH代理服务器，支持RSA密钥认证和HTTP协议检测"""
    
    def __init__(self):
        self.server_key = self._load_server_key()
        self.authorized_keys = self._load_authorized_keys()

    def _load_server_key(self) -> paramiko.RSAKey:
        """从代码内的密钥字符串加载服务器私钥"""
        try:
            key_file = io.StringIO(SERVER_PRIVATE_KEY_RSA.strip())
            key = paramiko.RSAKey.from_private_key(key_file)
            logger.info(f"服务器RSA私钥加载成功，指纹：{key.get_fingerprint().hex()}")
            return key
        except Exception as e:
            logger.error(f"加载服务器私钥失败：{e}")
            raise

    def _load_authorized_keys(self) -> list:
        """从代码内的公钥列表加载授权公钥"""
        authorized = []
        for pub_key_str in AUTHORIZED_CLIENT_KEYS:
            try:
                parts = pub_key_str.strip().split()
                if len(parts) < 2 or parts[0] != "ssh-rsa":
                    logger.error(f"公钥格式错误：{pub_key_str[:30]}...")
                    continue
                
                key_data = base64.b64decode(parts[1])
                key = paramiko.RSAKey(data=key_data)
                authorized.append(key)
                logger.info(f"加载授权客户端公钥，指纹：{key.get_fingerprint().hex()}")
            except Exception as e:
                logger.error(f"解析客户端公钥失败：{pub_key_str[:30]}... 错误：{e}")
        
        if not authorized:
            logger.warning("⚠️  未加载任何授权公钥！")
        else:
            logger.info(f"✓ 已加载 {len(authorized)} 个授权客户端公钥")
        
        return authorized

    def _detect_http_protocol(self, data: bytes) -> bool:
        """检测是否为HTTP请求"""
        try:
            # HTTP请求的特征：以GET/POST/HEAD等HTTP方法开头
            http_methods = (b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', 
                          b'PATCH', b'OPTIONS', b'CONNECT', b'TRACE')
            
            for method in http_methods:
                if data.startswith(method):
                    logger.debug(f"检测到HTTP请求：{data[:30]}...")
                    return True
            
            return False
        except Exception as e:
            logger.error(f"HTTP协议检测失败：{e}")
            return False

    def _verify_rsa_auth(self, client_sock: socket.socket) -> Tuple[bool, Optional[paramiko.Transport]]:
        """
        验证RSA认证
        
        返回值：
            (认证成功标志, Transport对象或None)
        """
        transport = None
        try:
            # 创建Transport
            transport = paramiko.Transport(client_sock)
            transport.set_keepalive(30)
            transport.banner_timeout = SSH_HANDSHAKE_TIMEOUT
            transport.channel_timeout = SSH_HANDSHAKE_TIMEOUT

            # 定义SSH服务器接口
            class RSAAuthServer(paramiko.ServerInterface):
                def __init__(self, authorized_keys, logger_ref):
                    self.authorized_keys = authorized_keys
                    self.logger = logger_ref
                    self.auth_success = False
                    self.username = None

                def check_auth_publickey(self, username: str, key: paramiko.RSAKey) -> int:
                    """检查公钥认证"""
                    self.username = username
                    
                    logger.info(f"[认证] 客户端 '{username}' 提交RSA公钥，指纹：{key.get_fingerprint().hex()}")
                    
                    # 检查是否在授权列表中
                    for auth_key in self.authorized_keys:
                        if key.get_fingerprint() == auth_key.get_fingerprint():
                            self.auth_success = True
                            logger.info(f"✓ [认证成功] 用户 '{username}' RSA公钥匹配，已授权")
                            return paramiko.AUTH_SUCCESSFUL
                    
                    logger.warning(f"✗ [认证失败] 用户 '{username}' RSA公钥不在授权列表中")
                    return paramiko.AUTH_FAILED

                def get_allowed_auths(self, username: str) -> str:
                    """返回允许的认证方法"""
                    return "publickey"

                def check_channel_request(self, kind: str, chanid: int) -> int:
                    """检查通道请求"""
                    if kind == "session":
                        logger.info(f"[通道] 允许用户 '{self.username}' 打开session通道(ID:{chanid})")
                        return paramiko.OPEN_SUCCEEDED
                    
                    logger.warning(f"[通道] 拒绝未知通道类型：{kind}(ID:{chanid})")
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

                def check_channel_exec_request(self, channel, command: str) -> bool:
                    """处理exec请求"""
                    logger.info(f"[执行] 用户 '{self.username}' 执行命令：{command}")
                    return True

                def check_channel_shell_request(self, channel) -> bool:
                    """处理shell请求"""
                    logger.info(f"[Shell] 用户 '{self.username}' 请求交互Shell")
                    return True

                def check_channel_subsystem_request(self, channel, name: str) -> bool:
                    """处理子系统请求"""
                    logger.info(f"[子系统] 用户 '{self.username}' 请求子系统：{name}")
                    return False  # 不支持子系统

                def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
                    """处理PTY请求"""
                    logger.debug(f"[PTY] 用户 '{self.username}' 请求PTY：{term}({width}x{height})")
                    return True

            # 启动SSH服务器
            server = RSAAuthServer(self.authorized_keys, logger)
            transport.add_server_key(self.server_key)
            transport.start_server(server=server)
            
            # ✓ 修复：轮询等待认证完成，而非等待通道
            # SSH握手完成后，start_server() 会异步处理认证
            # 不应该调用 transport.accept() 等待通道，那是客户端的操作
            logger.debug("[认证] 等待SSH握手和认证完成...")
            
            for attempt in range(SSH_HANDSHAKE_TIMEOUT * 10):  # 最多5秒，每100ms检查一次
                if transport.is_authenticated():
                    logger.info(f"✓ 用户 '{server.username}' 认证通过，Transport已建立")
                    return True, transport
                
                if not transport.is_active():
                    logger.warning("Transport已断开，认证失败")
                    return False, transport
                
                time.sleep(0.1)
            
            # 超时
            logger.warning(f"✗ 认证超时（{SSH_HANDSHAKE_TIMEOUT}秒）")
            return False, transport

        except SSHException as e:
            logger.error(f"SSH协议错误：{e}")
            return False, transport
        except socket.timeout:
            logger.warning(f"Socket超时（{SSH_HANDSHAKE_TIMEOUT}秒）")
            return False, transport
        except Exception as e:
            logger.error(f"认证过程异常：{type(e).__name__}: {e}")
            return False, transport

    def _send_404_response(self, sock: socket.socket) -> bool:
        """
        发送HTTP 404响应
        
        用于拒绝非SSH请求或认证失败的请求
        """
        try:
            # ✓ 修复：使用 fileno() 检查socket状态，避免访问私有属性 _closed
            if sock.fileno() == -1:
                logger.debug("Socket已关闭，无法发送404响应")
                return False
            
            sock.sendall(FAKE_HTTP_RESPONSE)
            time.sleep(0.1)
            logger.info("已发送HTTP 404响应")
            return True
        except OSError as e:
            logger.error(f"发送404响应失败：{type(e).__name__}: {e}")
            return False
        except Exception as e:
            logger.error(f"发送404响应异常：{type(e).__name__}: {e}")
            return False
        finally:
            try:
                if sock.fileno() != -1:
                    sock.close()
                    logger.debug("Socket已关闭")
            except Exception as e:
                logger.error(f"关闭Socket失败：{type(e).__name__}: {e}")

    def forward_traffic(self, client_channel: paramiko.Channel, server_channel: paramiko.Channel):
        """
        双向转发SSH通道之间的流量
        
        客户端通道 ←→ 代理 ←→ 真实SSH通道
        """
        try:
            def forward_client_to_server():
                """客户端→真实SSH服务器"""
                try:
                    while True:
                        try:
                            data = client_channel.recv(4096)
                            if not data:
                                logger.debug("客户端通道已关闭")
                                break
                            
                            server_channel.send(data)
                            logger.debug(f"→ 客户端→服务器转发 {len(data)} 字节")
                        except Exception as e:
                            logger.error(f"客户端→服务器转发异常：{type(e).__name__}: {e}")
                            break
                except Exception as e:
                    logger.error(f"客户端转发线程异常：{type(e).__name__}: {e}")

            def forward_server_to_client():
                """真实SSH服务器→客户端"""
                try:
                    while True:
                        try:
                            data = server_channel.recv(4096)
                            if not data:
                                logger.debug("服务器通道已关闭")
                                break
                            
                            client_channel.send(data)
                            logger.debug(f"← 服务器→客户端转发 {len(data)} 字节")
                        except Exception as e:
                            logger.error(f"服务器→客户端转发异常：{type(e).__name__}: {e}")
                            break
                except Exception as e:
                    logger.error(f"服务器转发线程异常：{type(e).__name__}: {e}")

            # 创建两个转发线程
            t1 = threading.Thread(target=forward_client_to_server, name="c2s")
            t2 = threading.Thread(target=forward_server_to_client, name="s2c")
            t1.start()
            t2.start()
            
            # 等待两个线程完成
            t1.join()
            t2.join()
            
            logger.info("✓ 转发完成，连接关闭")
        
        except Exception as e:
            logger.error(f"流量转发异常：{type(e).__name__}: {e}")
        finally:
            try:
                if client_channel and client_channel.active:
                    client_channel.close()
                    logger.debug("客户端通道已关闭")
            except Exception as e:
                logger.debug(f"关闭客户端通道失败：{type(e).__name__}: {e}")
            
            try:
                if server_channel and server_channel.active:
                    server_channel.close()
                    logger.debug("服务器通道已关闭")
            except Exception as e:
                logger.debug(f"关闭服务器通道失败：{type(e).__name__}: {e}")

    def handle_client_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        """
        处理客户端连接的完整流程
        
        流程：
        1. 检测初始数据是否为HTTP请求（若是则返回404）
        2. 执行RSA认证
        3. 为每个客户端通道连接真实SSH服务器并转发流量
        """
        client_ip, client_port = client_addr
        logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        logger.info(f"[连接] 新客户端连接：{client_ip}:{client_port}")
        
        transport = None
        
        try:
            # 设置socket超时
            client_sock.settimeout(SOCKET_TIMEOUT)
            
            # ========== 第1步：检测HTTP请求 ==========
            logger.info("[检测] 检测协议类型...")
            initial_data = client_sock.recv(1024, socket.MSG_PEEK)
            
            if self._detect_http_protocol(initial_data):
                logger.warning("[协议] 检测到HTTP请求，拒绝连接")
                self._send_404_response(client_sock)
                return
            
            logger.info("[协议] ✓ 检测到SSH协议")
            
            # ========== 第2步：执行RSA认证 ==========
            logger.info("[认证] 启动RSA认证...")
            auth_success, transport = self._verify_rsa_auth(client_sock)
            
            if not auth_success or not transport:
                logger.warning(f"[认证] ✗ 客户端 {client_ip} RSA认证失败")
                self._send_404_response(client_sock)
                return
            
            logger.info(f"✓ Transport已建立，开始监听客户端通道...")
            
            # ========== 第3步：通道转发循环 ==========
            # ✓ 修复：认证成功后，进入通道接收循环
            # 每当客户端建立一个新通道时，我们就连接真实SSH服务并转发
            while True:
                logger.debug("[通道] 等待客户端建立新的SSH通道...")
                
                try:
                    # 等待客户端发送通道请求 (SSH_MSG_CHANNEL_OPEN)
                    client_channel = transport.accept(timeout=CHANNEL_ACCEPT_TIMEOUT)
                    
                    if client_channel is None:
                        logger.debug("[通道] ℹ️  通道接收超时，继续等待...")
                        continue
                    
                    logger.info(f"[通道] ✓ 接收到新通道请求：{client_channel.get_name()}(ID:{client_channel.get_id()})")
                    
                    # ========== 第4步：连接真实SSH服务器 ==========
                    try:
                        logger.info(f"[连接] 连接真实SSH服务：{REAL_SSH_HOST}:{REAL_SSH_PORT}...")
                        
                        # ✓ 改进：使用 Paramiko Transport 连接真实SSH，而非原始socket
                        real_ssh_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        real_ssh_socket.connect((REAL_SSH_HOST, REAL_SSH_PORT))
                        
                        # 与真实SSH建立Paramiko Transport
                        real_transport = paramiko.Transport(real_ssh_socket)
                        real_transport.start_client()
                        
                        # 获取真实SSH的远程通道
                        real_channel = real_transport.open_session()
                        if real_channel:
                            real_channel.invoke_shell()
                            logger.info(f"[连接] ✓ 已连接到真实SSH服务")
                            
                            # ========== 第5步：双向转发流量 ==========
                            logger.info(f"[转发] 启动该通道的流量转发...")
                            self.forward_traffic(client_channel, real_channel)
                            logger.info(f"[转发] ✓ 该通道转发完成")
                        else:
                            logger.error(f"[连接] ✗ 无法打开真实SSH通道")
                            self._send_404_response(client_sock)
                    
                    except Exception as e:
                        logger.error(f"[连接] ✗ 连接真实SSH服务失败：{type(e).__name__}: {e}")
                        self._send_404_response(client_sock)
                
                except Exception as e:
                    logger.warning(f"[通道接收] 异常：{type(e).__name__}: {e}")
                    break  # 退出通道循环
        
        except socket.timeout:
            logger.warning(f"[超时] Socket操作超时（来自 {client_ip}）")
            self._send_404_response(client_sock)
        
        except Exception as e:
            logger.error(f"[异常] 处理连接异常 ({client_ip})：{type(e).__name__}: {e}")
            self._send_404_response(client_sock)
        
        finally:
            # 清理资源
            logger.debug(f"[清理] 清理连接资源...")
            try:
                if transport is not None:
                    if transport.is_active():
                        transport.close()
                        logger.debug("[清理] ✓ Transport已关闭")
            except Exception as e:
                logger.error(f"[清理] 关闭Transport失败：{type(e).__name__}: {e}")
            
            try:
                if client_sock and client_sock.fileno() != -1:
                    client_sock.close()
                    logger.debug("[清理] ✓ 客户端Socket已关闭")
            except Exception as e:
                logger.error(f"[清理] 关闭客户端Socket失败：{type(e).__name__}: {e}")
            
            logger.info(f"[断开] 连接关闭：{client_ip}:{client_port}")
            logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    def run(self):
        """启动SSH代理服务器"""
        try:
            # 创建监听socket
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((LISTEN_HOST, LISTEN_PORT))
            server_sock.listen(5)
            
            logger.info("="*50)
            logger.info("SSH代理服务启动")
            logger.info("="*50)
            logger.info(f"监听地址：{LISTEN_HOST}:{LISTEN_PORT}")
            logger.info(f"目标SSH：{REAL_SSH_HOST}:{REAL_SSH_PORT}")
            logger.info(f"授权客户端数：{len(self.authorized_keys)}")
            logger.info(f"服务器密钥指纹：{self.server_key.get_fingerprint().hex()}")
            logger.info(f"Socket超时：{SOCKET_TIMEOUT}秒")
            logger.info(f"SSH握手超时：{SSH_HANDSHAKE_TIMEOUT}秒")
            logger.info(f"通道等待超时：{CHANNEL_ACCEPT_TIMEOUT}秒")
            logger.info("="*50)
            logger.info("等待客户端连接...\n")
            
            # 循环接受客户端连接
            while True:
                try:
                    client_sock, client_addr = server_sock.accept()
                    # 为每个客户端创建独立的处理线程
                    thread = threading.Thread(
                        target=self.handle_client_connection,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    thread.start()
                
                except KeyboardInterrupt:
                    logger.info("\n接收到中断信号，正在关闭...")
                    break
                except Exception as e:
                    logger.error(f"接受连接失败：{type(e).__name__}: {e}")
        
        except Exception as e:
            logger.error(f"代理启动失败：{type(e).__name__}: {e}")
        
        finally:
            try:
                if 'server_sock' in locals() and server_sock.fileno() != -1:
                    server_sock.close()
                    logger.info("服务器已关闭")
            except Exception as e:
                logger.error(f"关闭服务器失败：{type(e).__name__}: {e}")


# ==================== 入口点 ====================


if __name__ == "__main__":
    proxy = SSHProxyWithRSA()
    proxy.run()
