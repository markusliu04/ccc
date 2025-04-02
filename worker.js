/**
 * Cursor API Proxy Worker
 * 保留令牌池、机器ID生成、checksum逻辑和降低风控任务
 */

// KV绑定
// 使用Workers KV作为数据存储
// 请在Cloudflare Dashboard中创建KV命名空间并配置绑定
// 或使用wrangler添加: wrangler kv:namespace create "TOKENS"
// 然后在wrangler.toml中添加: kv_namespaces = [{ binding = "TOKENS", id = "xxx" }]

// 内存缓存
const TOKEN_COOLDOWN = new Map(); // token -> expiry timestamp
const TOKEN_METADATA = new Map(); // token -> { machineId, macMachineId }
const ONE_TIME_EXECUTED = new Set(); // 记录哪些token已经执行过一次性任务
const LAST_MINUTE_EXECUTIONS = new Map(); // token -> 上次执行分钟任务的时间戳

// 降低风控任务配置
const IMMEDIATE_ENDPOINTS = [
  {
    url: 'https://api2.cursor.sh/aiserver.v1.AiService/AvailableDocs',
    method: 'POST',
    hasBody: false
  },
  {
    url: 'https://api2.cursor.sh/aiserver.v1.DashboardService/GetUsageBasedPremiumRequests',
    method: 'POST',
    hasBody: false
  },
  {
    url: 'https://api2.cursor.sh/aiserver.v1.DashboardService/GetHardLimit',
    method: 'POST',
    hasBody: false
  }
];

const MINUTE_ENDPOINTS = [
  {
    url: 'https://api2.cursor.sh/aiserver.v1.DashboardService/GetTeams',
    method: 'POST',
    hasBody: false
  },
  {
    url: 'https://api2.cursor.sh/auth/full_stripe_profile',
    method: 'GET',
    hasBody: false
  }
];

const ONE_TIME_ENDPOINTS = [
  {
    url: 'https://api2.cursor.sh/aiserver.v1.AiService/GetLastDefaultModelNudge',
    method: 'POST',
    hasBody: false
  },
  {
    url: 'https://api2.cursor.sh/aiserver.v1.ServerConfigService/GetServerConfig',
    method: 'POST',
    hasBody: false
  }
];

// Cursor客户端版本
const CURSOR_CLIENT_VERSION = "0.45.11";

// 令牌冷却时间配置
const COOLDOWN_TIME_MS = 20 * 1000; // 请求之间的冷却时间，20秒

// 路由处理器
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // CORS配置
  if (request.method === "OPTIONS") {
    return handleCors();
  }

  // 添加CORS头部的包装函数
  const withCors = (response) => {
    return addCorsHeaders(response);
  };
  
  // API路由
  try {
    // v1 API - OpenAI兼容接口
    if (path.startsWith("/v1/")) {
      return withCors(await handleV1Request(request, path));
    }
    
    // v2 API - 令牌管理接口
    if (path.startsWith("/v2/")) {
      return withCors(await handleV2Request(request, path));
    }
    
    // 返回简单的欢迎页面
    if (path === "/" || path === "") {
      return withCors(new Response("Cursor API Proxy - Ready", {
        status: 200,
        headers: { "Content-Type": "text/plain" }
      }));
    }
    
    // 404 Not Found
    return withCors(new Response(JSON.stringify({
      error: {
        message: "Route not found",
        type: "invalid_request_error",
        status: 404
      }
    }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    }));
  } catch (err) {
    console.error(`Error handling request: ${err.message}`);
    
    // 500 Internal Server Error
    return withCors(new Response(JSON.stringify({
      error: {
        message: "An unexpected error occurred",
        type: "server_error",
        status: 500
      }
    }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    }));
  }
}

// 处理V1 API请求 (OpenAI兼容接口)
async function handleV1Request(request, path) {
  // 从请求中获取令牌
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : null;
  
  if (!token) {
    return new Response(JSON.stringify({
      error: {
        message: "Authentication required",
        type: "authentication_error",
        status: 401
      }
    }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 1. 从令牌池获取有效令牌
  const validToken = await getAvailableToken();
  if (!validToken) {
    return new Response(JSON.stringify({
      error: {
        message: "No available tokens in the pool. Please try again later.",
        type: "server_error",
        status: 503
      }
    }), {
      status: 503,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 将请求转发到Cursor API
  const cursorApiUrl = "https://api2.cursor.sh" + path;
  
  // 创建headers对象
  const headers = new Headers();
  
  // 获取令牌的元数据
  const tokenMetadata = await getTokenMetadata(validToken);
  
  // 随机会话ID和客户端密钥
  const sessionId = crypto.randomUUID();
  const clientKey = generateHashed64Hex(validToken, 'clientKey');
  
  // 生成Cursor特殊请求头
  const cursorHeaders = getCursorHeaders(validToken, clientKey, sessionId, tokenMetadata);
  
  // 复制原始请求的headers
  for (const [key, value] of request.headers.entries()) {
    // 跳过一些headers
    if (["host", "connection", "content-length", "authorization"].includes(key.toLowerCase())) {
      continue;
    }
    headers.set(key, value);
  }
  
  // 添加Cursor特殊请求头
  Object.keys(cursorHeaders).forEach(key => {
    headers.set(key, cursorHeaders[key]);
  });
  
  // 使用有效的令牌
  headers.set("Authorization", `Bearer ${validToken}`);
  
  // 发送请求
  const requestInit = {
    method: request.method,
    headers: headers,
    redirect: "follow"
  };
  
  // 如果请求有body，添加body
  if (["POST", "PUT", "PATCH"].includes(request.method)) {
    const clonedRequest = request.clone();
    const contentType = request.headers.get("content-type") || "";
    
    if (contentType.includes("application/json")) {
      requestInit.body = JSON.stringify(await clonedRequest.json());
    } else {
      requestInit.body = await clonedRequest.text();
    }
  }
  
  try {
    // 标记令牌为已使用
    await markTokenAsUsed(validToken);
    
    // 发送请求到Cursor API
    const response = await fetch(cursorApiUrl, requestInit);
    
    // 创建响应
    const responseBody = await response.text();
    const responseInit = {
      status: response.status,
      statusText: response.statusText,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "application/json"
      }
    };
    
    // 请求后执行降低风控任务（不等待完成）
    executePostRequestTasks(validToken, tokenMetadata);
    
    // 返回响应
    return new Response(responseBody, responseInit);
  } catch (error) {
    console.error(`Error forwarding request: ${error.message}`);
    return new Response(JSON.stringify({
      error: {
        message: "Failed to connect to API server",
        type: "server_error",
        status: 502
      }
    }), {
      status: 502,
      headers: { "Content-Type": "application/json" }
    });
  }
}

// 处理V2 API请求 (令牌管理)
async function handleV2Request(request, path) {
  // 验证主密钥
  const authHeader = request.headers.get("Authorization") || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : null;
  
  if (!token || token !== MASTER_KEY) {
    return new Response(JSON.stringify({
      error: {
        message: "Invalid master key",
        type: "authentication_error",
        status: 403
      }
    }), {
      status: 403,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 路由逻辑
  // 添加令牌
  if (path === "/v2/add_token" && request.method === "POST") {
    const body = await request.json();
    const tokenToAdd = body.token;
    
    if (!tokenToAdd) {
      return new Response(JSON.stringify({
        error: {
          message: "Token is required",
          type: "invalid_request_error",
          status: 400
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    const result = await addToken(tokenToAdd);
    
    if (!result.success) {
      return new Response(JSON.stringify({
        error: {
          message: result.error || "Failed to add token",
          type: "server_error",
          status: 400
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    return new Response(JSON.stringify({
      success: true,
      message: "Token added successfully"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 删除令牌
  if (path === "/v2/delete_token" && request.method === "POST") {
    const body = await request.json();
    const tokenToDelete = body.token;
    
    if (!tokenToDelete) {
      return new Response(JSON.stringify({
        error: {
          message: "Token is required",
          type: "invalid_request_error",
          status: 400
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    const result = await deleteToken(tokenToDelete);
    
    if (!result.success) {
      return new Response(JSON.stringify({
        error: {
          message: result.error || "Failed to delete token",
          type: "server_error",
          status: 400
        }
      }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    
    return new Response(JSON.stringify({
      success: true,
      message: "Token deleted successfully"
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 获取令牌数量
  if (path === "/v2/token_counts" && request.method === "GET") {
    const count = await countAllTokens();
    
    return new Response(JSON.stringify({
      count,
      success: true
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 获取所有令牌状态
  if (path === "/v2/tokens" && request.method === "GET") {
    const tokens = await getAllTokens();
    
    // 格式化令牌信息
    const formattedTokens = tokens.map(token => {
      const isInCooldown = isTokenInCooldown(token);
      const cooldownRemaining = isInCooldown ? 
        getRemainingCooldown(token) : 0;
      
      // 限制令牌长度
      const displayToken = token.substring(0, 60) + '...';
      
      return {
        token: displayToken,
        isInCooldown,
        canUse: !isInCooldown,
        cooldownRemaining
      };
    });
    
    return new Response(JSON.stringify({
      tokens: formattedTokens,
      total_count: formattedTokens.length,
      usable_now: formattedTokens.filter(t => t.canUse).length,
      in_cooldown: formattedTokens.filter(t => !t.canUse).length,
      success: true
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 清除所有令牌
  if (path === "/v2/clear_all_tokens" && request.method === "POST") {
    const tokens = await getAllTokens();
    let deletedCount = 0;
    
    for (const token of tokens) {
      const result = await deleteToken(token);
      if (result.success) {
        deletedCount++;
      }
    }
    
    return new Response(JSON.stringify({
      success: true,
      message: `成功删除${deletedCount}个令牌`,
      total: tokens.length
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }
  
  // 未找到对应的路由
  return new Response(JSON.stringify({
    error: {
      message: "Not found",
      type: "invalid_request_error",
      status: 404
    }
  }), {
    status: 404,
    headers: { "Content-Type": "application/json" }
  });
}

// 添加CORS头
function addCorsHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

// 处理CORS预检请求
function handleCors() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400"
    }
  });
}

// 令牌池操作
// 添加令牌
async function addToken(token) {
  if (!token || typeof token !== 'string' || token.trim() === '') {
    return { success: false, error: 'Invalid token' };
  }
  
  const processedToken = processToken(token);
  if (!processedToken) {
    return { success: false, error: 'Invalid token format' };
  }
  
  try {
    // 检查令牌是否已存在
    const existingToken = await TOKENS.get(processedToken);
    if (existingToken) {
      return { success: false, error: 'Token already exists', duplicate: true };
    }
    
    // 生成令牌的machineId和macMachineId
    const { machineId, macMachineId } = generateMachineIds(processedToken);
    
    // 存储令牌和元数据
    await TOKENS.put(processedToken, JSON.stringify({ 
      addedAt: Date.now(),
      machineId,
      macMachineId
    }));
    
    // 在内存中存储元数据
    TOKEN_METADATA.set(processedToken, { machineId, macMachineId });
    
    // 移除冷却状态（如果存在）
    TOKEN_COOLDOWN.delete(processedToken);
    
    return { success: true };
  } catch (error) {
    console.error(`Error adding token: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// 删除令牌
async function deleteToken(token) {
  if (!token) {
    return { success: false, error: 'Token is required' };
  }
  
  const processedToken = processToken(token);
  if (!processedToken) {
    return { success: false, error: 'Invalid token format' };
  }
  
  try {
    // 检查令牌是否存在
    const existingToken = await TOKENS.get(processedToken);
    if (!existingToken) {
      return { success: true, changes: 0 }; // 不存在，视为成功但无变化
    }
    
    // 从KV中删除令牌
    await TOKENS.delete(processedToken);
    
    // 从内存中删除
    TOKEN_COOLDOWN.delete(processedToken);
    TOKEN_METADATA.delete(processedToken);
    ONE_TIME_EXECUTED.delete(processedToken);
    LAST_MINUTE_EXECUTIONS.delete(processedToken);
    
    return { success: true, changes: 1 };
  } catch (error) {
    console.error(`Error deleting token: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// 获取所有令牌
async function getAllTokens() {
  try {
    const { keys } = await TOKENS.list();
    return keys.map(key => key.name);
  } catch (error) {
    console.error(`Error getting all tokens: ${error.message}`);
    return [];
  }
}

// 计数所有令牌
async function countAllTokens() {
  try {
    const { keys } = await TOKENS.list();
    return keys.length;
  } catch (error) {
    console.error(`Error counting tokens: ${error.message}`);
    return 0;
  }
}

// 获取可用令牌（不在冷却中）
async function getAvailableToken() {
  try {
    const tokens = await getAllTokens();
    
    // 随机排序令牌以平衡负载
    const shuffledTokens = tokens.sort(() => 0.5 - Math.random());
    
    // 找到第一个不在冷却中的令牌
    for (const token of shuffledTokens) {
      if (!isTokenInCooldown(token)) {
        return token;
      }
    }
    
    // 如果所有令牌都在冷却中，选择冷却时间最早结束的令牌
    if (shuffledTokens.length > 0) {
      let earliestExpiry = Infinity;
      let earliestToken = null;
      
      for (const token of shuffledTokens) {
        const expiry = TOKEN_COOLDOWN.get(token) || 0;
        if (expiry < earliestExpiry) {
          earliestExpiry = expiry;
          earliestToken = token;
        }
      }
      
      return earliestToken;
    }
    
    return null;
  } catch (error) {
    console.error(`Error getting available token: ${error.message}`);
    return null;
  }
}

// 标记令牌为已使用（添加冷却时间）
async function markTokenAsUsed(token) {
  if (!token) return;
  
  const now = Date.now();
  const expiry = now + COOLDOWN_TIME_MS;
  TOKEN_COOLDOWN.set(token, expiry);
}

// 检查令牌是否在冷却中
function isTokenInCooldown(token) {
  if (!token || !TOKEN_COOLDOWN.has(token)) return false;
  
  const expiry = TOKEN_COOLDOWN.get(token);
  const now = Date.now();
  
  return now < expiry;
}

// 获取令牌的剩余冷却时间（秒）
function getRemainingCooldown(token) {
  if (!token || !TOKEN_COOLDOWN.has(token)) return 0;
  
  const expiry = TOKEN_COOLDOWN.get(token);
  const now = Date.now();
  
  if (now >= expiry) return 0;
  return Math.ceil((expiry - now) / 1000);
}

// 获取令牌元数据（machineId和macMachineId）
async function getTokenMetadata(token) {
  if (!token) return null;
  
  // 首先从内存中获取
  if (TOKEN_METADATA.has(token)) {
    return TOKEN_METADATA.get(token);
  }
  
  // 从存储中获取
  try {
    const tokenData = await TOKENS.get(token, { type: 'json' });
    if (tokenData && tokenData.machineId && tokenData.macMachineId) {
      // 缓存到内存
      TOKEN_METADATA.set(token, {
        machineId: tokenData.machineId,
        macMachineId: tokenData.macMachineId
      });
      return {
        machineId: tokenData.machineId,
        macMachineId: tokenData.macMachineId
      };
    }
  } catch (error) {
    console.error(`Error getting token metadata: ${error.message}`);
  }
  
  // 如果没有找到，生成新的
  const { machineId, macMachineId } = generateMachineIds(token);
  
  // 保存到KV存储
  try {
    await TOKENS.put(token, JSON.stringify({
      addedAt: Date.now(),
      machineId,
      macMachineId
    }));
  } catch (error) {
    console.error(`Error saving token metadata: ${error.message}`);
  }
  
  // 缓存到内存
  TOKEN_METADATA.set(token, { machineId, macMachineId });
  
  return { machineId, macMachineId };
}

// 生成机器ID
function generateMachineIds(token) {
  if (!token) return { machineId: null, macMachineId: null };
  
  // 使用令牌创建一致的哈希
  const randomSeed = token.substring(0, 10);
  const machineId = generateHashed64Hex(token + randomSeed, 'machineId');
  const macMachineId = generateHashed64Hex(token + randomSeed + '1', 'macMachineId');
  
  return { machineId, macMachineId };
}

// 生成哈希值
function generateHashed64Hex(input, salt = '') {
  // 在Cloudflare Workers中使用Web Crypto API
  const encoder = new TextEncoder();
  const data = encoder.encode(input + salt);
  
  // 简单的字符串哈希代替原来的加密哈希
  // 我们在Worker中不需要真正的安全性，只需要一个一致性固定的值
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data[i];
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // 转为32位整数
  }
  
  // 转为十六进制并填充到64位
  const hashStr = Math.abs(hash).toString(16);
  // 重复字符串直到它达到64个字符
  return hashStr.padEnd(64, hashStr);
}

// 处理不同格式的令牌
function processToken(token) {
  if (!token) return null;
  
  let processedToken = token.trim();
  
  // 处理特殊令牌格式
  if (processedToken.includes('%3A%3A')) {
    processedToken = processedToken.split('%3A%3A')[1];
  } else if (processedToken.includes('::')) {
    processedToken = processedToken.split('::')[1];
  }
  
  return processedToken;
}

// 混淆字节数组
function obfuscateBytes(byteArray) {
  let t = 165;
  for (let r = 0; r < byteArray.length; r++) {
    byteArray[r] = (byteArray[r] ^ t) + (r % 256);
    t = byteArray[r];
  }
  return byteArray;
}

// 生成Cursor校验和
function generateCursorChecksum(token, metadata = null) {
  // 获取或生成 machineId 和 macMachineId
  let machineId, macMachineId;
  
  if (metadata && metadata.machineId && metadata.macMachineId) {
    machineId = metadata.machineId;
    macMachineId = metadata.macMachineId;
  } else {
    const ids = generateMachineIds(token);
    machineId = ids.machineId;
    macMachineId = ids.macMachineId;
  }

  // 获取时间戳并转换为字节数组
  const timestamp = Math.floor(Date.now() / 1e6);
  const byteArray = new Uint8Array([
    (timestamp >> 40) & 255,
    (timestamp >> 32) & 255,
    (timestamp >> 24) & 255,
    (timestamp >> 16) & 255,
    (timestamp >> 8) & 255,
    255 & timestamp,
  ]);

  // 混淆字节数组并进行base64编码
  const obfuscatedBytes = obfuscateBytes(byteArray);
  const encodedChecksum = btoa(String.fromCharCode.apply(null, [...obfuscatedBytes]));

  // 组合最终的checksum
  return `${encodedChecksum}${machineId}/${macMachineId}`;
}

// 获取Cursor API请求头
function getCursorHeaders(authToken, clientKey = null, sessionId = null, tokenMetadata = null) {
  // 获取令牌的元数据，用于生成checksum
  const checksum = generateCursorChecksum(authToken.trim(), tokenMetadata);
  
  // 基本请求头
  const headers = {
    'authorization': `Bearer ${authToken}`,
    'connect-protocol-version': '1',
    'user-agent': 'connect-es/1.6.1',
    'x-cursor-checksum': checksum,
    'x-cursor-client-version': CURSOR_CLIENT_VERSION,
    'x-cursor-timezone': 'Asia/Shanghai',
    'x-ghost-mode': 'true',
    'Host': 'api2.cursor.sh',
    'x-new-onboarding-completed': 'false'
  };
  
  // 追加客户端特定头
  if (clientKey) {
    headers['x-client-key'] = clientKey;
    headers['x-amzn-trace-id'] = `Root=${crypto.randomUUID()}`;
    headers['x-request-id'] = crypto.randomUUID();
    
    // 添加额外的跟踪头信息
    // 使用Web Crypto API生成随机值
    const traceId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    const spanId = Array.from(crypto.getRandomValues(new Uint8Array(8)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    headers['traceparent'] = `00-${traceId}-${spanId}-00`;
    
    // 添加配置版本
    headers['x-cursor-config-version'] = crypto.randomUUID();
  }
  
  // 添加会话ID
  if (sessionId) {
    headers['x-session-id'] = sessionId;
  } else {
    headers['x-session-id'] = crypto.randomUUID();
  }
  
  return headers;
}

// 执行请求后风控任务
async function executePostRequestTasks(token, metadata) {
  if (!token) return;
  
  // 使用token生成固定的客户端密钥
  const clientKey = generateHashed64Hex(token, 'clientKey');
  
  // 立即执行的任务
  executeImmediateTasks(token, metadata, clientKey);
  
  // 每分钟执行一次任务
  const now = Date.now();
  const lastExecution = LAST_MINUTE_EXECUTIONS.get(token) || 0;
  
  if (now - lastExecution >= 60000) { // 1分钟
    executeMinuteTasks(token, metadata, clientKey);
    LAST_MINUTE_EXECUTIONS.set(token, now);
  }
  
  // 一次性任务（每个token只执行一次）
  if (!ONE_TIME_EXECUTED.has(token)) {
    setTimeout(() => {
      executeOneTimeTasks(token, metadata, clientKey);
      ONE_TIME_EXECUTED.add(token);
    }, 30000); // 30秒后执行
  }
}

// 执行立即任务
async function executeImmediateTasks(token, metadata, clientKey) {
  for (let i = 0; i < IMMEDIATE_ENDPOINTS.length; i++) {
    const endpoint = IMMEDIATE_ENDPOINTS[i];
    const delay = i * 500; // 每个任务间隔0.5秒
    
    setTimeout(() => {
      executeTask(endpoint, token, metadata, clientKey);
    }, delay);
  }
}

// 执行每分钟任务
async function executeMinuteTasks(token, metadata, clientKey) {
  // 固定执行GetTeams一次
  const teamsEndpoint = MINUTE_ENDPOINTS[0];
  
  // 随机决定执行full_stripe_profile的次数 (1-5次)
  const fullProfileEndpoint = MINUTE_ENDPOINTS[1];
  const profileCount = Math.floor(Math.random() * 5) + 1;
  
  // 先执行GetTeams
  setTimeout(() => {
    executeTask(teamsEndpoint, token, metadata, clientKey);
  }, 500);
  
  // 然后执行full_stripe_profile
  for (let i = 0; i < profileCount; i++) {
    const delay = 1500 + i * 1500; // 间隔1.5秒
    setTimeout(() => {
      executeTask(fullProfileEndpoint, token, metadata, clientKey);
    }, delay);
  }
}

// 执行一次性任务
async function executeOneTimeTasks(token, metadata, clientKey) {
  ONE_TIME_ENDPOINTS.forEach((endpoint, index) => {
    const delay = index * 1000; // 每个任务间隔1秒
    setTimeout(() => {
      executeTask(endpoint, token, metadata, clientKey);
    }, delay);
  });
}

// 执行单个API请求任务
async function executeTask(endpoint, token, metadata, clientKey) {
  // 为不同的端点类型准备不同的头
  let headers;
  
  if (endpoint.url.includes('/auth/')) {
    // full_stripe_profile 使用简单的认证头
    headers = {
      'Host': 'api2.cursor.sh',
      'Authorization': `Bearer ${token}`
    };
  } else {
    // 其他API使用完整的Cursor头
    headers = getCursorHeaders(token, clientKey, null, metadata);
    headers['connect-protocol-version'] = '1';
    headers['content-type'] = 'application/proto';
  }
  
  try {
    // 准备请求体
    let body = undefined;
    
    if (endpoint.hasBody) {
      if (endpoint.bodyBase64) {
        // 使用Buffer进行Base64解码
        body = atob(endpoint.bodyBase64);
      } else if (endpoint.bodyText) {
        body = endpoint.bodyText;
      }
    }
    
    // 发送请求
    const response = await fetch(endpoint.url, {
      method: endpoint.method,
      headers: headers,
      body: body
    });
    
    // 忽略响应处理，只是为了降低风控
  } catch (error) {
    console.error(`[DEBUG] 降低风控任务执行出错: ${error.message}`);
  }
}

// 全局变量和事件监听器
const MASTER_KEY = "sk-chatify-MoLu154!"; // 默认主密钥，可通过环境变量覆盖

// 如果有环境变量设置，使用环境变量中的主密钥
export default {
  async fetch(request, env) {
    // 使用环境变量中的KV绑定和主密钥
    globalThis.TOKENS = env.TOKENS;
    const masterKey = env.MASTER_KEY || MASTER_KEY;
    
    // 覆盖全局主密钥
    globalThis.MASTER_KEY = masterKey;
    
    return handleRequest(request);
  },
  async scheduled(event, env) {
    // 使用环境变量中的KV绑定
    globalThis.TOKENS = env.TOKENS;
    
    // 清理过期的冷却状态
    const now = Date.now();
    for (const [token, expiry] of TOKEN_COOLDOWN.entries()) {
      if (now >= expiry) {
        TOKEN_COOLDOWN.delete(token);
      }
    }
  }
}; 