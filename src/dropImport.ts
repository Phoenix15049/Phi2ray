const MAX_IMPORT_BYTES = 8 * 1024 * 1024;

const nativeFileMessages = {
  dark: "darkTunnelFile",
  hc: "httpCustomFile",
  ehi: "httpInjectorFile",
  sks: "socksHttpFile",
  nm: "netModFile",
  ovpn: "openVpnFile",
} as const;

export function importFileError(error: unknown) {
  if (error instanceof Error) {
    if (Object.prototype.hasOwnProperty.call(nativeFileMessages, error.message)) {
      return nativeFileMessages[error.message as keyof typeof nativeFileMessages];
    }
    switch (error.message) {
      case "large": return "dropTooLarge";
      case "npv": return "unreadableNpvFile";
      case "npvs": return "protectedNpvFile";
      case "npvs-passphrase": return "npvPassphraseFile";
      case "npvs-app-key": return "npvAppKeyFile";
      case "npvs-recipient": return "npvRecipientFile";
    }
  }
  return "dropUnreadable";
}

function isStandardConfig(text: string): boolean {
  return /^\s*(?:vless|vmess|trojan|ss|socks5?):\/\//im.test(text)
    || /^\s*\[Interface\]/im.test(text)
    || /^\s*\[/.test(text)
    || /^\s*\{/.test(text) && /"(?:outbounds|protocol)"\s*:/.test(text);
}

function isStandardFile(text: string): boolean {
  if (isStandardConfig(text)) return true;
  const base64 = text.replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) return false;
  try {
    return isStandardConfig(atob(base64));
  } catch {
    return false;
  }
}

function protectedNpvFile(bytes: Uint8Array): string | undefined {
  if (bytes.length < 5 || bytes[0] !== 78 || bytes[1] !== 80 ||
      bytes[2] !== 86 || bytes[3] !== 83 || bytes[4] >= 32) return;
  // NPVS v5 stores the compact header length in big-endian order.
  if (bytes[4] === 5 && bytes.length >= 62 && bytes[9] === 1) {
    const headerLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(5);
    if (headerLength >= 53 && headerLength <= bytes.length - 9) {
      switch (bytes[59]) {
        case 0: return "npvs-recipient";
        case 1: return "npvs-passphrase";
        case 2: return "npvs-app-key";
      }
    }
  }
  return "npvs";
}

export function canDropImport(data: DataTransfer | null): boolean {
  return !!data && (data.types.includes("Files") || data.types.includes("text/plain") || data.types.includes("text/uri-list"));
}

export async function readDroppedImport(data: DataTransfer): Promise<string> {
  const files = Array.from(data.files);
  if (files.length) return readImportFiles(files);
  const text = data.getData("text/plain") || data.getData("text/uri-list").split(/\r?\n/).filter((x) => !x.startsWith("#")).join("\n");
  if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error("large");
  return text.trim();
}

export async function readImportFiles(files: File[]): Promise<string> {
  if (files.reduce((total, file) => total + file.size + 1, 0) > MAX_IMPORT_BYTES) throw new Error("large");
  const parts: string[] = [];
  for (const file of files) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const protectedFormat = protectedNpvFile(bytes);
    if (protectedFormat) throw new Error(protectedFormat);
    const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le" :
      bytes[0] === 0xfe && bytes[1] === 0xff ? "utf-16be" : "utf-8";
    const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
    const knownNative = Object.prototype.hasOwnProperty.call(nativeFileMessages, extension);
    let content: string;
    try {
      content = new TextDecoder(encoding, { fatal: true }).decode(bytes).trim();
      if (content.includes("\0")) throw new Error("binary");
    } catch {
      throw new Error(knownNative ? extension : /\.npvs?$/i.test(file.name) ? "npv" : "binary");
    }
    if (knownNative && content && !isStandardFile(content)) throw new Error(extension);
    parts.push(content);
  }
  const text = parts.join("\n").trim();
  if (new TextEncoder().encode(text).length > MAX_IMPORT_BYTES) throw new Error("large");
  return text;
}
