# memory-shell-sweeper

无文件内存马（memory-resident backdoor）的**运行时发现与安全摘除**工具。

攻击者利用反序列化等漏洞进入后，不向磁盘写入任何文件，而是在运行的 Java 进程中
`defineClass(byte[])` 定义恶意类、动态注册一个 Filter / Servlet / 请求处理器，
通过特定请求执行命令，重启前一直存在，传统文件扫描完全无法发现。

本工具通过 **JVM Attach API + Instrumentation + 容器反射适配**，在**不停止服务**的前提下：

1. 枚举进程内所有已注册的请求处理组件（Filter / Servlet / Listener / Spring Handler）
2. 基于类来源取证 + 字节码探针 + 多信号评分，识别内存中动态注册的可疑类
3. 调用容器自身的公共 API 安全摘除，保护正在处理的在途请求

## 核心能力

| 能力 | 实现方式 |
|------|----------|
| 跨进程无侵入挂载 | Attach API `VirtualMachine.loadAgent`，agent jar 零第三方依赖（约 77KB） |
| 内存类识别 | `ProtectionDomain.CodeSource == null` + 非启动类加载器 + 资源取证 |
| 字节码取证 | 一次性 `retransformClasses` 取回字节，常量池扫描 `Runtime.exec`/`ProcessBuilder`/脚本引擎等特征，扫描完即注销 transformer，**永不修改字节码** |
| 容器组件枚举 | JMX 平台 MBeanServer 内部结构反射 + 线程根对象图 + Tomcat 容器链显式下行 |
| 多容器适配 | Tomcat / Jetty 支持发现+摘除；Undertow / WebLogic / 通用 Servlet API 支持发现定级，摘除给出安全处置建议 |
| 在途请求保护 | 通过容器自身加锁的注销方法摘除注册表，再宽限等待，最后 `destroy()`；在途请求已持有组件快照不受影响 |
| 误伤防护 | 监控探针/框架动态类白名单、多信号叠加评分、强信号+字节码双重确认、两步确认摘除 |

## 组件定级

- `MALICIOUS`：内存定义类命中强信号（null CodeSource / hidden class / 可疑加载器），
  或叠加字节码命令执行 API 特征。达到自动摘除门槛。
- `SUSPICIOUS`：多个弱信号，需人工确认。
- `DYNAMIC_BENIGN`：动态生成但命中白名单（CGLIB / ByteBuddy / JDK 代理 / APM 探针等）。
- `NORMAL`：磁盘可加载的常规组件。

## 用法

```bash
# 1. 列出本机 Java 进程
java -jar memory-shell-sweeper-agent-1.0.0.jar list

# 2. 只读扫描（默认，不修改目标进程）
java -jar memory-shell-sweeper-agent-1.0.0.jar <pid> scan
java -jar memory-shell-sweeper-agent-1.0.0.jar <pid> scan --no-bytecode   # 跳过字节码扫描

# 3. 演练：完整走摘除流程但不修改注册表
java -jar memory-shell-sweeper-agent-1.0.0.jar <pid> dry-run

# 4a. 推荐：两步确认，先看报告再按 id 精确摘除
java -jar memory-shell-sweeper-agent-1.0.0.jar <pid> remove --ids tomcat-bb07659e

# 4b. 自动模式：仅摘除评分达 MALICIOUS 且通过强信号门槛的组件
java -jar memory-shell-sweeper-agent-1.0.0.jar <pid> remove --grace-ms 5000
```

输出为 JSON 报告，包含每个组件的类型、映射、类加载器、CodeSource、信号、评分与定级；
摘除模式额外给出每个目标的 `REMOVED / DRY_RUN / NOT_SUPPORTED / FAILED` 状态。

## 安全设计原则

- **只读优先**：默认 `scan` 不做任何修改；`dry-run` 用于预演；摘除是显式动作。
- **复用容器锁**：所有摘除走容器自身的注销方法（如 Tomcat `removeFilterMap/removeFilterDef`、
  Jetty `setFilters/setFilterMappings`），不直接改内部数组，遵守容器并发协议。
- **先摘映射后宽限再销毁**：新请求立即不再命中恶意组件，已构建调用链的在途请求走完后才 `destroy()`。
- **摘除前复评**：自动模式在摘除瞬间重新校验定级，防止状态变化后误删。
- **反射全兜底**：所有容器访问零编译依赖且异常隔离，单个适配器失败不影响其它容器发现。

## 模块结构

```
agent/        JVM agent 入口（premain/agentmain）与 CLI 启动器
core/         编排引擎、类来源取证、字节码探针、评分定级、选项模型
discovery/    JMX 仓库遍历、线程根遍历、Tomcat 容器链定位、已加载类探测
adapters/     Tomcat / Jetty / Spring MVC / Undertow / WebLogic / 通用 Servlet API 适配器
model/        组件记录数据模型
util/         反射工具、零依赖 JSON
```

## 已知边界

- Undertow / WebLogic 的运行期单点摘除缺少稳定公共 API，强反射改写有破坏在途请求风险，
  因此本工具对其只做发现定级，并在报告中给出热重载/网关封禁等安全处置建议。
- 线程根对象图遍历设深度上限，超大堆上优先依赖 JMX 与容器链定位而非全量堆遍历。
- 工具本身需要与目标 JVM 同版本或兼容的 JDK 运行；JDK 17+ 跨进程 Attach 需具备本机进程权限。

## 构建与测试

```bash
gradle agentJar          # 产出 build/libs/memory-shell-sweeper-agent-*.jar
gradle test              # 22 个测试：单元测试 + Tomcat/Jetty 端到端集成测试
```

集成测试会真实启动内嵌容器、用内存 ClassLoader 注入 Filter 马、经 Attach 自挂载扫描定级，
再验证摘除后内存马请求失效而正常业务请求全程 200。
