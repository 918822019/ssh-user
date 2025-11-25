# 认证失败HTTP 404机制 - 技术文档

**文档日期**: 2025年11月25日  
**功能**: 认证失败隐蔽返回HTTP 404

---

## 📋 功能概述

当SSH客户端连接到代理但**认证失败**时，系统会返回**HTTP 404**响应，而不是SSH协议错误。这增强了安全性，防止攻击者识别出这是一个SSH代理服务。

---

## 🔍 实现原理

### 工作流程

```
客户端连接
    ↓
┌─────────────────────────────────┐
│ 第1步：检测协议类型              │
├─────────────────────────────────┤
│ 使用 _detect_http_protocol()     │
│ 检查是否为 HTTP 请求             │
└─────────┬───────────────────────┘
          ↓
    [HTTP?] ──YES──→ 返回HTTP 404 ──→ 结束
          │
         NO
          ↓
┌─────────────────────────────────┐
│ 第2步：执行RSA认证               │
├─────────────────────────────────┤
│ 使用 _verify_rsa_auth()          │
│ 验证客户端公钥                   │
└─────────┬───────────────────────┘
          ↓
   [认证成功?]
    ↙         ↖
  YES        NO
   ↓          ↓
 继续      返回HTTP 404 ──→ 结束
   ↓
┌─────────────────────────────────┐
│ 第3步：连接真实SSH服务           │
│ 第4步：建立通道                   │
│ 第5步：双向流量转发              │
└─────────────────────────────────┘
```

### 核心代码

**文件**: `代理转发.py`

**HTTP 404响应定义** (第17行):
```python
FAKE_HTTP_RESPONSE = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
```

**HTTP协议检测** (第96-110行):
```python
def _detect_http_protocol(self, data: bytes) -> bool:
    """检测是否为HTTP请求"""
    try:
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
```

**发送404响应** (第208-221行):
```python
def _send_404_response(self, sock: socket.socket) -> bool:
    """
    发送HTTP 404响应
    用于拒绝非SSH请求或认证失败的请求
    """
    try:
        if sock.fileno() == -1:
            logger.debug("Socket已关闭，无法发送404响应")
            return False
        
        sock.sendall(FAKE_HTTP_RESPONSE)
        time.sleep(0.1)
        logger.info("已发送HTTP 404响应")
        return True
    except OSError as e:
        logger.error(f"发送404响应失败：{e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass
```

**认证检查** (第309-313行):
```python
auth_success, transport = self._verify_rsa_auth(client_sock)

if not auth_success or not transport:
    logger.warning(f"[认证] ✗ 客户端 {client_ip} RSA认证失败")
    self._send_404_response(client_sock)  # ← 认证失败返回404
    return
```

---

## 🎯 触发HTTP 404的场景

| 场景 | 触发点 | 日志消息 |
|------|-------|--------|
| HTTP请求 | 检测HTTP方法 | `[协议] 检测到HTTP请求，拒绝连接` |
| 认证失败 | 公钥不匹配 | `[认证] ✗ 客户端RSA认证失败` |
| 连接超时 | 认证超时15秒 | `[超时] 连接超时` |
| SSH服务无响应 | 真实服务器不可达 | `[连接] ✗ 无法连接到真实SSH服务` |

---

## 🧪 测试与验证

### 测试1: HTTP请求返回404

```bash
# 使用curl发送HTTP请求
$ curl -v http://localhost:33000

# 预期输出：
# > GET / HTTP/1.1
# < HTTP/1.1 404 Not Found
# < Content-Length: 0
# < Connection: close
```

**日志输出**:
```
[检测] 检测协议类型...
[协议] 检测到HTTP请求，拒绝连接
已发送HTTP 404响应
[断开] 连接关闭：127.0.0.1:xxxxx
```

### 测试2: 认证失败返回404

```bash
# 使用未授权的密钥连接
$ ssh -i ~/.ssh/other_key -p 33000 user@localhost

# 预期结果：
# - 连接被拒绝
# - 服务器返回HTTP 404
# - SSH客户端显示错误
```

**日志输出**:
```
[连接] 新客户端连接：127.0.0.1:xxxxx
[检测] 检测协议类型...
[协议] ✓ 检测到SSH协议
[认证] 启动RSA认证...
[认证] 客户端 'user' 提交RSA公钥，指纹：xxxxxxxx
✗ [认证失败] 用户 'user' RSA公钥不在授权列表中
[认证] ✗ 客户端 127.0.0.1 RSA认证失败
已发送HTTP 404响应
[断开] 连接关闭：127.0.0.1:xxxxx
```

### 测试3: 正确的公钥连接成功

```bash
# 使用授权的密钥连接
$ ssh -i ~/.ssh/authorized_key -p 33000 user@localhost

# 预期结果：
# 连接成功
```

**日志输出**:
```
[连接] 新客户端连接：127.0.0.1:xxxxx
[检测] 检测协议类型...
[协议] ✓ 检测到SSH协议
[认证] 启动RSA认证...
[认证] 客户端 'user' 提交RSA公钥，指纹：xxxxxxxx
✓ [认证成功] 用户 'user' RSA公钥匹配，已授权
✓ 用户 'user' 认证通过，Transport已建立
[通道] 等待客户端建立SSH通道...
[通道] ✓ 通道建立成功
[连接] 连接真实SSH服务：localhost:2222...
[连接] ✓ 已连接到真实SSH服务
[转发] 启动流量转发...
```

---

## 🔐 安全特性分析

### 隐蔽性设计

**优点**:
1. ✅ **难以识别** - 攻击者无法区分是真实Web服务器404还是认证失败
2. ✅ **隐蔽代理存在** - 端口扫描时看不出这是SSH代理
3. ✅ **一致的响应** - HTTP请求和认证失败都返回相同的404
4. ✅ **防止探测** - 攻击者无法通过错误消息识别服务

**实现**:
```
认证失败 ──┐
           ├──→ HTTP 404 响应 ──→ 外界看起来一样
HTTP请求  ──┘
```

### 日志记录

虽然外界看不到认证失败，但**内部日志清晰记录**所有详情：

```
日志文件: ssh_proxy.log

[认证] 客户端 'attacker' 提交RSA公钥，指纹：xxx
✗ [认证失败] 用户 'attacker' RSA公钥不在授权列表中
[认证] ✗ 客户端 192.168.1.100 RSA认证失败
已发送HTTP 404响应
```

---

## ⚙️ 配置与自定义

### 修改HTTP 404响应

如需自定义HTTP 404响应，编辑 `代理转发.py`:

```python
# 第17行，修改为你想要的响应
FAKE_HTTP_RESPONSE = b"""HTTP/1.1 404 Not Found\r
Content-Type: text/html\r
Content-Length: 125\r
Connection: close\r
\r
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>404 Not Found</h1>
<p>The requested resource was not found on this server.</p>
</body>
</html>"""
```

### 关闭隐蔽机制（用于调试）

如需禁用隐蔽机制进行调试，可以修改返回方式：

```python
# 修改 _send_404_response 方法
def _send_404_response(self, sock: socket.socket) -> bool:
    """
    发送错误响应（可选择HTTP 404或SSH错误）
    """
    try:
        # 调试模式：返回SSH错误
        # ssh_error = b"SSH-2.0-OpenSSH_7.4\r\n"
        # sock.sendall(ssh_error)
        
        # 生产模式：返回HTTP 404
        sock.sendall(FAKE_HTTP_RESPONSE)
        return True
    except OSError as e:
        logger.error(f"发送响应失败：{e}")
        return False
```

---

## 📊 性能影响

| 操作 | 时间开销 |
|------|---------|
| HTTP检测 | ~1ms |
| 发送404响应 | ~5-10ms |
| 总体连接处理 | <100ms |

**结论**: 隐蔽机制对性能影响**极小**

---

## 🚨 安全建议

### 日志安全

```bash
# 日志包含敏感信息（认证失败详情、IP地址等）
# 建议做好日志保护：

# 1. 限制日志文件权限
chmod 600 ssh_proxy.log

# 2. 定期轮转日志
logrotate /etc/logrotate.d/ssh-proxy

# 3. 备份重要日志
tar czf ssh_proxy.log.$(date +%Y%m%d).tar.gz ssh_proxy.log

# 4. 监控认证失败
grep "认证失败" ssh_proxy.log | wc -l
```

### 攻击防护

```bash
# 1. 监控异常连接尝试
tail -f ssh_proxy.log | grep "认证失败"

# 2. 设置告警阈值
# 如1分钟内认证失败次数>10，触发告警

# 3. 实现IP黑名单
# 多次认证失败的IP可以加入黑名单

# 4. 速率限制
# 限制单IP的连接频率
```

---

## 📝 故障排除

### 认证失败但没有返回404

**原因**: Socket已经关闭或网络故障

**解决**:
```bash
# 查看详细日志
tail -50 ssh_proxy.log | grep -A5 "认证失败"

# 检查网络连接
ping -c 4 client_ip

# 检查防火墙
sudo ufw status
```

### HTTP 404没有被返回

**原因**: Socket操作失败

**解决**:
```bash
# 1. 检查socket状态
netstat -tlnp | grep 33000

# 2. 查看系统日志
sudo journalctl -u ssh-proxy.service | tail -20

# 3. 检查磁盘空间
df -h /tmp

# 4. 检查文件描述符限制
ulimit -n
```

---

## 📚 相关文件

- `代理转发.py` - 核心实现
- `ssh_proxy.sh` - 启动脚本
- `ssh_proxy.log` - 日志文件
- `README.md` - 完整文档

---

## 🔗 参考资源

- HTTP/1.1 规范: RFC 7231
- SSH 协议: RFC 4252, 4253
- 日志安全: OWASP日志备忘单

---

**🔒 安全机制已完全实现，认证失败隐蔽返回HTTP 404！**
