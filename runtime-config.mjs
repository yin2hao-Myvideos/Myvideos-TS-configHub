#!/usr/bin/env node
/**
 * 本地加密运行配置解析器（默认操作 data/runtime-config.enc）。
 *
 * 文件格式与后端 RuntimeConfigStore 保持一致：
 *   信封 JSON  { "version": "1", "iv": <base64url>, "ciphertext": <base64url> }
 *   密钥文件   data/runtime-config.key（base64url 编码的 32 字节 AES 密钥）
 *   算法       AES-256-GCM，IV 12 字节，认证标签 128 位（附在密文末尾）
 *   明文       JSON 对象，键为运行配置键（如 captcha.turnstileAllowedHostnames）
 *
 * 常用命令（在项目根目录执行）：
 *   node test/runtime-config.mjs list --reveal
 *   node test/runtime-config.mjs get captcha.turnstileAllowedHostnames
 *   node test/runtime-config.mjs set captcha.turnstileAllowedHostnames "videos.yin2hao.dev,localhost"
 *   node test/runtime-config.mjs delete some.unused.key
 *
 * 注意：直接修改文件后必须重启后端才会生效（后端仅在启动时读取并缓存该文件）。
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import process from 'node:process';

/** 命中这些关键字的配置项在 list 输出中默认脱敏。 */
const SENSITIVE_PATTERN = /(secret|password|apikey|api-key|masterkey|pepper)/i;
const GCM_TAG_BYTES = 16;
const IV_BYTES = 12;

const HELP = `本地加密运行配置解析器（data/runtime-config.enc）

用法:
  node test/runtime-config.mjs <命令> [选项]

命令:
  list   [--prefix <前缀>] [--reveal]   列出配置项，默认隐藏敏感值
  get    <key>                          打印某个配置项的明文值
  set    <key> <value...>               修改配置项并重新加密写回
  delete <key>                          删除配置项并重新加密写回

选项:
  --config <path>   加密配置文件路径（默认 $SETUP_CONFIG_PATH 或 data/runtime-config.enc）
  --key <path>      密钥文件路径（默认 $SETUP_CONFIG_KEY_PATH 或 data/runtime-config.key）
  --reveal          list 时显示敏感项明文
  --no-backup       写回时不生成 .bak 备份（默认会在同目录生成）
  -h, --help        显示本帮助

示例:
  node test/runtime-config.mjs list --prefix captcha.
  node test/runtime-config.mjs get captcha.turnstileAllowedHostnames
  node test/runtime-config.mjs set captcha.turnstileAllowedHostnames "videos.yin2hao.dev,localhost"

注意: 直接修改文件后必须重启后端进程（配置在启动时加载并缓存于内存）。`;

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const opts = { reveal: false, backup: true, positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg === '--reveal') opts.reveal = true;
    else if (arg === '--no-backup') opts.backup = false;
    else if (arg === '--config' || arg === '--key' || arg === '--prefix') {
      const value = argv[++i];
      if (value === undefined) fail(`选项 ${arg} 缺少参数值`);
      if (arg === '--config') opts.config = value;
      else if (arg === '--key') opts.key = value;
      else opts.prefix = value;
    } else if (!opts.command) opts.command = arg;
    else opts.positional.push(arg);
  }
  return opts;
}

function loadKey(keyPath) {
  if (!existsSync(keyPath)) fail(`找不到密钥文件: ${keyPath}`);
  const key = Buffer.from(readFileSync(keyPath, 'utf8').trim(), 'base64url');
  if (key.length !== 32) fail(`密钥长度应为 32 字节，实际为 ${key.length} 字节: ${keyPath}`);
  return key;
}

function decryptConfig(configPath, key) {
  if (!existsSync(configPath)) fail(`找不到配置文件: ${configPath}`);
  let envelope;
  try {
    envelope = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    fail(`配置文件不是合法 JSON: ${configPath}`);
  }
  if (envelope.version !== '1') fail(`不支持的信封版本: ${envelope.version}`);
  const iv = Buffer.from(envelope.iv, 'base64url');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64url');
  if (iv.length !== IV_BYTES) fail(`IV 长度异常: ${iv.length} 字节`);
  if (ciphertext.length <= GCM_TAG_BYTES) fail('密文长度异常');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(ciphertext.subarray(ciphertext.length - GCM_TAG_BYTES));
    const plain = Buffer.concat([
      decipher.update(ciphertext.subarray(0, ciphertext.length - GCM_TAG_BYTES)),
      decipher.final(),
    ]);
    return JSON.parse(plain.toString('utf8'));
  } catch {
    fail('解密失败：密钥与密文不匹配，或文件已损坏');
  }
}

function encryptConfig(values, key) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(values, null, 2)), cipher.final()]);
  const ciphertext = Buffer.concat([body, cipher.getAuthTag()]);
  return `${JSON.stringify(
    { iv: iv.toString('base64url'), ciphertext: ciphertext.toString('base64url'), version: '1' },
    null,
    2,
  )}\n`;
}

function saveConfig(configPath, key, values, backup) {
  // 与后端 RuntimeConfigStore.write 的语义保持一致：写入时确保该标记存在。
  values['bootstrap.completed'] ??= 'true';
  if (backup && existsSync(configPath)) copyFileSync(configPath, `${configPath}.bak`);
  writeFileSync(configPath, encryptConfig(values, key), 'utf8');
}

function truncate(value, max = 80) {
  return value.length > max ? `${value.slice(0, max)}…(共 ${value.length} 字符)` : value;
}

function display(name, value, reveal) {
  if (value === undefined || value === null) return '';
  if (reveal || !SENSITIVE_PATTERN.test(name)) return truncate(String(value));
  return `${String(value).slice(0, 3)}****（已隐藏，加 --reveal 显示明文）`;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(HELP);
    return;
  }
  if (!opts.command) {
    console.log(HELP);
    process.exitCode = 1;
    return;
  }
  const configPath = opts.config || process.env.SETUP_CONFIG_PATH || 'data/runtime-config.enc';
  const keyPath = opts.key || process.env.SETUP_CONFIG_KEY_PATH || 'data/runtime-config.key';
  const key = loadKey(keyPath);

  switch (opts.command) {
    case 'list': {
      const config = decryptConfig(configPath, key);
      const entries = Object.entries(config)
        .filter(([name]) => !opts.prefix || name.startsWith(opts.prefix))
        .sort(([a], [b]) => a.localeCompare(b));
      if (!entries.length) {
        console.log('（无匹配的配置项）');
        return;
      }
      const width = Math.max(...entries.map(([name]) => name.length));
      for (const [name, value] of entries) {
        console.log(`${name.padEnd(width)} = ${display(name, value, opts.reveal)}`);
      }
      console.log(`\n共 ${entries.length} 项（文件: ${configPath}）`);
      return;
    }
    case 'get': {
      const [name] = opts.positional;
      if (!name) fail('用法: get <key>');
      const config = decryptConfig(configPath, key);
      if (!(name in config)) fail(`键不存在: ${name}`);
      console.log(config[name]);
      return;
    }
    case 'set': {
      const [name, ...rest] = opts.positional;
      const value = rest.join(' ').trim();
      if (!name) fail('用法: set <key> <value>');
      if (!value) fail('值为空：如需删除该配置项请使用 delete 命令（后端语义中留空表示保持原值）');
      const config = decryptConfig(configPath, key);
      const before = config[name];
      config[name] = value;
      saveConfig(configPath, key, config, opts.backup);
      console.log(`已写入 ${name}`);
      console.log(`  旧值: ${before === undefined ? '（不存在）' : display(name, before, true)}`);
      console.log(`  新值: ${value}`);
      console.log('注意: 需重启后端进程后才会生效。');
      return;
    }
    case 'delete': {
      const [name] = opts.positional;
      if (!name) fail('用法: delete <key>');
      const config = decryptConfig(configPath, key);
      if (!(name in config)) fail(`键不存在: ${name}`);
      const before = config[name];
      delete config[name];
      saveConfig(configPath, key, config, opts.backup);
      console.log(`已删除 ${name}（原值: ${display(name, before, true)}）`);
      console.log('注意: 需重启后端进程后才会生效。');
      return;
    }
    default:
      fail(`未知命令: ${opts.command}（可用: list / get / set / delete）`);
  }
}

try {
  main();
} catch (error) {
  console.error(`错误: ${error.message}`);
  process.exitCode = 1;
}
