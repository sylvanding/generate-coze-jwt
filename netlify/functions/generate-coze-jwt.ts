// netlify/functions/generate-coze-jwt.ts
import type {
  Handler,
  HandlerEvent,
  HandlerContext,
  HandlerResponse,
} from "@netlify/functions";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

/**
 * 生成用于调用 Coze API 的 JWT
 * (这是从你的原始代码中复制或导入的函数)
 */
const generateCozeJwt = (
  privateKey: string,
  cozeAppId: string,
  keyId: string,
  audience: string = "api.coze.cn",
  expiresInSeconds: number = 600
): string | null => {
  try {
    const nowInSeconds = Math.floor(Date.now() / 1000);
    const expirationTime = nowInSeconds + expiresInSeconds;

    const payload = {
      iat: nowInSeconds, // JWT开始生效的时间，秒级时间戳
      exp: expirationTime, // JWT过期时间，秒级时间戳
      jti: uuidv4(), // 随机字符串，防止重放攻击
      aud: audience, //扣子 API 的Endpoint
      iss: cozeAppId, // OAuth 应用的 ID
    };

    const headers = {
      alg: "RS256", // 固定为RS256
      typ: "JWT", // 固定为JWT
      kid: keyId, // OAuth 应用的公钥指纹
    };

    // **重要**: 处理可能从环境变量读取的私钥格式问题
    // Netlify 环境变量有时会转义换行符，确保它是正确的 PEM 格式
    // const formattedPrivateKey = privateKey.replace(/\\n/g, "\n");
    // 或者，如果您使用 Base64 编码存储私钥，您可以这样解码：
    const formattedPrivateKey = Buffer.from(privateKey, "base64")
      .toString("utf-8")
      .replace(/\\n/g, "\n");

    const token = jwt.sign(payload, formattedPrivateKey, {
      algorithm: "RS256",
      header: headers,
    });

    console.log("成功生成 Coze JWT");
    return token;
  } catch (error) {
    console.error("生成 Coze JWT 失败:", error);
    // 在 Serverless Function 中，更详细地记录错误可能有助于调试
    if (error instanceof Error) {
      console.error("错误详情:", error.message);
      if (error.message.includes("PEM routines")) {
        console.error(
          "请检查私钥格式是否正确，以及是否在环境变量中正确配置（注意换行符）。"
        );
      }
    }
    return null;
  }
};

const handler: Handler = async (
  event: HandlerEvent,
  context: HandlerContext
): Promise<HandlerResponse> => {
  // --- 1. 检查请求方法 ---
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405, // Method Not Allowed
      body: JSON.stringify({ message: "只允许 POST 请求。" }),
      headers: { Allow: "POST" },
    };
  }

  // --- 2. 从 Netlify 环境变量获取私钥 ---
  const privateKey = process.env.COZE_PRIVATE_KEY;
  if (!privateKey) {
    console.error("缺少必要的 Coze 配置环境变量 (COZE_PRIVATE_KEY)");
    return {
      statusCode: 500,
      body: JSON.stringify({
        message: "服务器配置错误：缺少 COZE_PRIVATE_KEY 环境变量。",
      }),
    };
  }

  // --- 3. 解析请求体 ---
  let body;
  try {
    if (!event.body) {
      throw new Error("请求体为空。");
    }
    body = JSON.parse(event.body);
  } catch (error) {
    console.error("解析请求体失败:", error);
    return {
      statusCode: 400, // Bad Request
      body: JSON.stringify({
        message: "无法解析请求体，请确保是有效的 JSON 格式。",
      }),
    };
  }

  // --- 4. 从请求体中获取参数 ---
  const {
    cozeAppId,
    keyId,
    audience = "api.coze.cn", // 如果请求体中没有，则使用默认值
    expiresIn = 600, // 如果请求体中没有，则使用默认值 (注意变量名)
  } = body;

  // --- 5. 检查必要的参数是否存在 ---
  if (!cozeAppId || !keyId) {
    console.error("请求体中缺少必要的参数 (cozeAppId, keyId)");
    return {
      statusCode: 400, // Bad Request
      body: JSON.stringify({
        message: "请求体中缺少必要的参数：cozeAppId 和 keyId。",
      }),
    };
  }

  // --- 6. 调用核心逻辑 ---
  // 注意将 expiresIn 传递给函数
  const cozeJwtToken = generateCozeJwt(
    privateKey,
    cozeAppId,
    keyId,
    audience,
    expiresIn
  );

  // --- 7. 返回结果 ---
  if (!cozeJwtToken) {
    // generateCozeJwt 内部已经打印了错误
    return {
      statusCode: 500, // Internal Server Error
      body: JSON.stringify({
        message: "生成 Coze JWT 失败，请查看函数日志获取详情。",
      }),
    };
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: "Coze JWT 生成成功。",
      token: cozeJwtToken,
    }),
    headers: {
      "Content-Type": "application/json",
    },
  };
};

export { handler };
