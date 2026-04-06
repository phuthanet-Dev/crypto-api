const CryptoJS = require("crypto-js");
const moment = require("moment");
const axios = require("axios");
const express = require("express");
const crypto = require("crypto");

const app = express();

// แก้ไขพอร์ตให้รองรับ DirectAdmin/Cloud
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "5mb" }));

// --- CONFIGURATION ---
const VSPHONE_CONFIG = {
  accessKeyId: "di5cgGh6sPKz2TLLW638nmXIT9d4FrDm",
  secretAccessKey: "fJEOyi2lI8Z4hs7TBzMsYAaM",
  baseURL: "https://api.vsphone.com",
};

const AES_CONFIG = {
  passphrase:
    "vH33r_2025_AES_GCM_S3cur3_K3y_9X7mP4qR8nT2wE5yU1oI6aS3dF7gH0jK9lZ",
  salt: "vheer-salt-2024",
  iter: 10000,
  keyLength: 32,
  ivLength: 12,
  tagLength: 16,
};

// --- VSPhone SIGNER LOGIC ---
class VmosAPISigner {
  constructor(accessKeyId, secretAccessKey) {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.contentType = "application/json;charset=UTF-8";
    this.host = "api.vsphone.com";
    this.service = "armcloud-paas";
    this.algorithm = "HMAC-SHA256";
  }

  signRequest(requestOptions) {
    const { method, body = null, queryParams = {} } = requestOptions;
    let params = "";
    if (method === "POST" && body) {
      params = typeof body === "string" ? body : JSON.stringify(body);
    } else if (method === "GET" && Object.keys(queryParams).length > 0) {
      params = new URLSearchParams(queryParams).toString();
    }

    const xDate = moment().utc().format("YYYYMMDDTHHmmss[Z]");
    const shortXDate = xDate.substring(0, 8);
    const credentialScope = `${shortXDate}/${this.service}/request`;

    const canonicalString = [
      `host:${this.host}`,
      `x-date:${xDate}`,
      `content-type:${this.contentType}`,
      `signedHeaders:content-type;host;x-content-sha256;x-date`,
      `x-content-sha256:${CryptoJS.SHA256(params).toString()}`,
    ].join("\n");

    const stringToSign = [
      this.algorithm,
      xDate,
      credentialScope,
      CryptoJS.SHA256(canonicalString).toString(),
    ].join("\n");

    const kDate = CryptoJS.HmacSHA256(shortXDate, this.secretAccessKey);
    const kService = CryptoJS.HmacSHA256(this.service, kDate);
    const signKey = CryptoJS.HmacSHA256("request", kService);
    const signature = CryptoJS.HmacSHA256(stringToSign, signKey).toString(
      CryptoJS.enc.Hex
    );

    return {
      "x-date": xDate,
      "x-host": this.host,
      authorization: `HMAC-SHA256 Credential=${this.accessKeyId}/${credentialScope}, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=${signature}`,
      "content-type": this.contentType,
    };
  }
}

class VSPhoneClient {
  constructor() {
    this.signer = new VmosAPISigner(
      VSPHONE_CONFIG.accessKeyId,
      VSPHONE_CONFIG.secretAccessKey
    );
    this.baseURL = VSPHONE_CONFIG.baseURL;
  }

  async callApi(method, endpoint, payload = {}) {
    const upperMethod = method.toUpperCase();
    const headers = this.signer.signRequest({
      method: upperMethod,
      path: endpoint,
      body: upperMethod !== "GET" ? payload : null,
      queryParams: upperMethod === "GET" ? payload : {},
    });

    const response = await axios({
      baseURL: this.baseURL,
      url: endpoint,
      method: upperMethod,
      headers: headers,
      params: upperMethod === "GET" ? payload : undefined,
      data: upperMethod !== "GET" ? payload : undefined,
    });
    return response.data;
  }
}

const vsClient = new VSPhoneClient();

// --- AES ENCRYPTION LOGIC ---
function deriveKey() {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      AES_CONFIG.passphrase,
      AES_CONFIG.salt,
      AES_CONFIG.iter,
      AES_CONFIG.keyLength,
      "sha256",
      (err, key) => {
        if (err) return reject(err);
        resolve(key);
      }
    );
  });
}

async function encryptPlaintext(plaintextUtf8) {
  const key = await deriveKey();
  const iv = crypto.randomBytes(AES_CONFIG.ivLength);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([
    cipher.update(Buffer.from(plaintextUtf8, "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString("base64");
}

async function decryptParamsBase64(paramsB64) {
  const packed = Buffer.from(paramsB64, "base64");
  const iv = packed.subarray(0, AES_CONFIG.ivLength);
  const tag = packed.subarray(packed.length - AES_CONFIG.tagLength);
  const ct = packed.subarray(
    AES_CONFIG.ivLength,
    packed.length - AES_CONFIG.tagLength
  );

  const key = await deriveKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

// --- API ROUTES ---

// 1. AES Crypto Routes
app.post("/encrypt", async (req, res) => {
  try {
    const plaintext = JSON.stringify(req.body ?? {});
    const base64 = await encryptPlaintext(plaintext);
    res.json({ params: base64 });
  } catch (error) {
    res.status(500).json({ error: "Encryption failed", detail: error.message });
  }
});

app.post("/decrypt", async (req, res) => {
  try {
    const params = req.body?.params;
    if (!params) return res.status(400).json({ error: "Missing params" });
    const plaintext = await decryptParamsBase64(params);
    try {
      res.json({ ok: true, data: JSON.parse(plaintext) });
    } catch {
      res.json({ ok: true, data: plaintext });
    }
  } catch (error) {
    res.status(500).json({ error: "Decryption failed", detail: error.message });
  }
});

// 2. VSPhone API Routes
app.post("/vsphone/listInstalledApp", async (req, res) => {
  try {
    const payloadString = JSON.stringify(req.body);
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/listInstalledApp",
      payloadString
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/syncCmd", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/syncCmd",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/startApp", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/startApp",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/stopApp", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/stopApp",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/simulateTouch", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/simulateTouch",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/padTaskDetail", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/padTaskDetail",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.post("/vsphone/fileTaskDetail", async (req, res) => {
  try {
    const data = await vsClient.callApi(
      "POST",
      "/vsphone/api/padApi/fileTaskDetail",
      req.body
    );
    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: "API failed",
      detail: error.response?.data || error.message,
    });
  }
});

app.get("/health", (req, res) => res.json({ status: "ok", time: new Date() }));

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
