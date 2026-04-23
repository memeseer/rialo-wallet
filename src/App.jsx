import { useEffect, useMemo, useState } from "react";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import bs58 from "bs58";
import { HDKey } from "micro-ed25519-hdkey";
import nacl from "tweetnacl";
import rialoLogo from "./assets/rialo-logo.svg";

const STORAGE_KEY = "rialo-wallet-v1";
const THEME_KEY = "rialo-theme-v1";
const RPC_PATH = "/api/rpc";
const KELVINS_PER_RLO = 1_000_000_000;
const CLAIM_AMOUNT = 1_000_000_000;
const SYSTEM_PROGRAM = "11111111111111111111111111111111";

function encodeShortvec(value) {
  const out = [];
  let current = value;
  for (;;) {
    const elem = current & 0x7f;
    current >>= 7;
    if (current === 0) {
      out.push(elem);
      return Uint8Array.from(out);
    }
    out.push(elem | 0x80);
  }
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function u64Le(value) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(value), true);
  return new Uint8Array(view.buffer);
}

function i64Le(value) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigInt64(0, BigInt(value), true);
  return new Uint8Array(view.buffer);
}

function deriveWalletFromMnemonic(mnemonic) {
  const seed = mnemonicToSeedSync(mnemonic);
  const hd = HDKey.fromMasterSeed(seed);
  const derived = hd.derive("m/44'/501'/0'/0'/0'");
  const keyPair = nacl.sign.keyPair.fromSeed(derived.privateKey);
  const secretKey = keyPair.secretKey.slice(0, 64);
  const address = bs58.encode(keyPair.publicKey);

  return {
    mnemonic,
    address,
    secretKey: Array.from(secretKey),
  };
}

function persistWallet(wallet) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(wallet));
}

function loadStoredWallet() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed?.mnemonic || !parsed?.address || !Array.isArray(parsed?.secretKey)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

async function rpcCall(method, params = []) {
  const response = await fetch(RPC_PATH, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });

  const data = await response.json();
  if (data.error) {
    const message = data.error?.data?.details || data.error?.message || "RPC error";
    throw new Error(message);
  }
  return data.result;
}

async function rpcCallRaw(method, params = []) {
  const response = await fetch(RPC_PATH, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params,
    }),
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("Invalid RPC response.");
  }

  if (data.error) {
    const message = data.error?.data?.details || data.error?.message || "RPC error";
    throw new Error(message);
  }

  return { result: data.result, text };
}

async function getBalance(address) {
  const result = await rpcCall("getBalance", [{ address }]);
  return result.value;
}

async function requestAirdrop(address, kelvins) {
  return rpcCall("requestAirdrop", [{ pubkey: address, kelvins }]);
}

async function getRecentValidatorConfigHashPrefix() {
  const { result, text } = await rpcCallRaw("getRecentValidatorConfigHash");
  const match = text.match(/"configHashPrefix"\s*:\s*(\d+)/);
  if (match) {
    return BigInt(match[1]);
  }
  if (typeof result?.configHashPrefix === "string") {
    return BigInt(result.configHashPrefix);
  }
  throw new Error("Cannot read configHashPrefix from RPC response.");
}

async function sendSignedTransaction(base64Tx) {
  return rpcCall("sendTransaction", [base64Tx]);
}

function buildTransferInstructionData(kelvins) {
  return concatBytes(Uint8Array.of(2, 0, 0, 0), u64Le(kelvins));
}

function buildMessageBytes({ sender, receiver, kelvins, validFrom, configHashPrefix, occ = false }) {
  const header = Uint8Array.of(1, 0, 1);
  const accountKeys = concatBytes(
    bs58.decode(sender),
    bs58.decode(receiver),
    bs58.decode(SYSTEM_PROGRAM),
  );
  const instructionData = buildTransferInstructionData(kelvins);

  return concatBytes(
    header,
    encodeShortvec(3),
    accountKeys,
    i64Le(validFrom),
    u64Le(configHashPrefix),
    Uint8Array.of(occ ? 1 : 0),
    encodeShortvec(1),
    Uint8Array.of(2),
    encodeShortvec(2),
    Uint8Array.of(0, 1),
    encodeShortvec(instructionData.length),
    instructionData,
  );
}

function signMessage(secretKeyArray, messageBytes) {
  const signature = nacl.sign.detached(messageBytes, Uint8Array.from(secretKeyArray));
  return Uint8Array.from(signature);
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function explorerUrl(signature) {
  return `https://rialo-explorer-devnet-direct.vercel.app/txs/${signature}?network=devnet`;
}

function formatRlo(value) {
  return new Intl.NumberFormat("en-US", {
    minimumFractionDigits: 0,
    maximumFractionDigits: 9,
  }).format(value);
}

function shortenAddress(value) {
  return `${value.slice(0, 6)}...${value.slice(-6)}`;
}

function ActivityItem({ item }) {
  return (
    <div className="activity-item">
      <div className="activity-head">
        <strong>{item.title}</strong>
        <span>{new Date(item.timestamp).toLocaleString()}</span>
      </div>
      <div className="activity-body">{item.details}</div>
      {item.signature ? (
        <a href={explorerUrl(item.signature)} target="_blank" rel="noreferrer">
          Open explorer
        </a>
      ) : null}
    </div>
  );
}

export default function App() {
  const [wallet, setWallet] = useState(null);
  const [mnemonicInput, setMnemonicInput] = useState("");
  const [balance, setBalance] = useState(null);
  const [loadingBalance, setLoadingBalance] = useState(false);
  const [sendAddress, setSendAddress] = useState("");
  const [sendRlo, setSendRlo] = useState("0.0001");
  const [theme, setTheme] = useState("light");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [activities, setActivities] = useState([]);

  useEffect(() => {
    const stored = loadStoredWallet();
    if (stored) {
      setWallet(stored);
    }
    const storedTheme = localStorage.getItem(THEME_KEY);
    if (storedTheme === "light" || storedTheme === "dark") {
      setTheme(storedTheme);
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const hasWallet = Boolean(wallet);
  const address = wallet?.address ?? "";
  const rloBalance = useMemo(() => {
    if (balance == null) {
      return null;
    }
    return balance / KELVINS_PER_RLO;
  }, [balance]);

  async function refreshBalance() {
    if (!wallet) {
      return;
    }
    setLoadingBalance(true);
    setError("");
    try {
      const nextBalance = await getBalance(wallet.address);
      setBalance(nextBalance);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingBalance(false);
    }
  }

  function rememberWallet(nextWallet, sourceLabel) {
    persistWallet(nextWallet);
    setWallet(nextWallet);
    setMnemonicInput(nextWallet.mnemonic);
    setActivities((current) => [
      {
        title: sourceLabel,
        details: `Address ${shortenAddress(nextWallet.address)} is ready on this device.`,
        timestamp: Date.now(),
      },
      ...current,
    ]);
    setTimeout(() => {
      refreshBalance();
    }, 0);
  }

  function handleCreateWallet() {
    setError("");
    const mnemonic = generateMnemonic(wordlist, 128);
    const nextWallet = deriveWalletFromMnemonic(mnemonic);
    rememberWallet(nextWallet, "Wallet created");
  }

  function handleImportWallet() {
    setError("");
    const normalized = mnemonicInput.trim().toLowerCase().replace(/\s+/g, " ");
    if (!validateMnemonic(normalized, wordlist)) {
      setError("Invalid seed phrase.");
      return;
    }
    rememberWallet(deriveWalletFromMnemonic(normalized), "Wallet imported");
  }

  function handleForgetWallet() {
    localStorage.removeItem(STORAGE_KEY);
    setWallet(null);
    setBalance(null);
    setActivities([]);
    setError("");
  }

  async function handleAirdrop(event) {
    event.preventDefault();
    if (!wallet) {
      return;
    }
    setBusy("airdrop");
    setError("");
    try {
      const result = await requestAirdrop(wallet.address, CLAIM_AMOUNT);
      setActivities((current) => [
        {
          title: "Claim completed",
          details: `${formatRlo(CLAIM_AMOUNT / KELVINS_PER_RLO)} $RLO added to your wallet.`,
          signature: result,
          timestamp: Date.now(),
        },
        ...current,
      ]);
      await refreshBalance();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  async function handleSend(event) {
    event.preventDefault();
    if (!wallet) {
      return;
    }
    const receiver = sendAddress.trim();
    if (!receiver) {
      setError("Recipient address is required.");
      return;
    }

    let receiverBytes;
    try {
      receiverBytes = bs58.decode(receiver);
    } catch {
      setError("Recipient address is invalid.");
      return;
    }

    if (receiverBytes.length !== 32) {
      setError("Recipient address is invalid.");
      return;
    }

    const kelvins = Math.trunc(Number(sendRlo) * KELVINS_PER_RLO);
    if (!Number.isFinite(kelvins) || kelvins <= 0) {
      setError("Send amount must be positive.");
      return;
    }

    setBusy("send");
    setError("");

    try {
      const validFrom = Date.now();
      const configHashPrefix = await getRecentValidatorConfigHashPrefix();
      const messageBytes = buildMessageBytes({
        sender: wallet.address,
        receiver,
        kelvins,
        validFrom,
        configHashPrefix,
      });
      const signature = signMessage(wallet.secretKey, messageBytes);
      const txBytes = concatBytes(encodeShortvec(1), signature, messageBytes);
      const result = await sendSignedTransaction(toBase64(txBytes));

      setActivities((current) => [
        {
          title: "Transfer sent",
          details: `${formatRlo(Number(sendRlo))} $RLO sent to ${shortenAddress(receiver)}.`,
          signature: result,
          timestamp: Date.now(),
        },
        ...current,
      ]);
      await refreshBalance();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy("");
    }
  }

  function toggleTheme() {
    setTheme((current) => (current === "light" ? "dark" : "light"));
  }

  return (
    <div className="page-shell">
      <div className="hero">
        <div className="hero-copy">
          <div className="brand-row">
            <img className="brand-logo" src={rialoLogo} alt="Rialo" />
            <div className="brand-lockup">
              <p className="eyebrow">Rialo Wallet</p>
              <span className="brand-caption">Simple wallet for claiming and sending $RLO</span>
            </div>
          </div>
          <h1>Your wallet, ready in one tab.</h1>
          <p className="lede">
            Create or import a wallet, save your recovery phrase, claim $RLO, and send it to any address.
          </p>
          <div className="hero-pills">
            <span>Create</span>
            <span>Claim</span>
            <span>Send</span>
          </div>
        </div>
        <div className="status-card">
          <span>Theme</span>
          <button className="ghost-button theme-toggle" onClick={toggleTheme}>
            {theme === "light" ? "Switch to night" : "Switch to day"}
          </button>
          <div className="status-strip">
            <span>Wallet</span>
            <strong>{hasWallet ? shortenAddress(address) : "Not connected yet"}</strong>
          </div>
        </div>
      </div>

      {error ? <div className="banner error">{error}</div> : null}

      <div className="grid">
        <section className="panel">
          <div className="panel-head">
            <h2>Wallet</h2>
            {hasWallet ? (
              <button className="ghost-button" onClick={handleForgetWallet}>
                Forget this device
              </button>
            ) : null}
          </div>

          {!hasWallet ? (
            <>
              <button className="primary-button" onClick={handleCreateWallet}>
                Create wallet
              </button>
              <div className="divider">or import an existing seed phrase</div>
              <textarea
                className="seed-box"
                rows="4"
                placeholder="Enter 12-word seed phrase"
                value={mnemonicInput}
                onChange={(event) => setMnemonicInput(event.target.value)}
              />
              <button className="secondary-button" onClick={handleImportWallet}>
                Import wallet
              </button>
            </>
          ) : (
            <>
              <div className="data-block">
                <span>Address</span>
                <code>{address}</code>
              </div>
              <div className="data-block">
                <span>Recovery phrase</span>
                <div className="seed-box reveal">{wallet.mnemonic}</div>
              </div>
              <div className="actions-row">
                <button className="secondary-button" onClick={() => navigator.clipboard.writeText(wallet.mnemonic)}>
                  Copy phrase
                </button>
                <button className="secondary-button" onClick={() => navigator.clipboard.writeText(address)}>
                  Copy address
                </button>
                <button
                  className="secondary-button"
                  onClick={refreshBalance}
                  disabled={loadingBalance}
                >
                  {loadingBalance ? "Refreshing..." : "Refresh balance"}
                </button>
              </div>
              <p className="hint">
                Your recovery phrase stays on this device.
              </p>
            </>
          )}
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Balance</h2>
          </div>
          <div className="metric">
            <span>$RLO</span>
            <strong>{rloBalance == null ? "Not loaded" : formatRlo(rloBalance)}</strong>
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Claim $RLO</h2>
          </div>
          <form onSubmit={handleAirdrop} className="stack">
            <button className="primary-button" disabled={!hasWallet || busy === "airdrop"}>
              {busy === "airdrop" ? "Claiming..." : "Claim 1 $RLO"}
            </button>
          </form>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Send</h2>
          </div>
          <form onSubmit={handleSend} className="stack">
            <label>
              Recipient address
              <input
                type="text"
                placeholder="Enter address"
                value={sendAddress}
                onChange={(event) => setSendAddress(event.target.value)}
              />
            </label>
            <label>
              Amount
              <input
                type="number"
                min="0"
                step="0.000000001"
                value={sendRlo}
                onChange={(event) => setSendRlo(event.target.value)}
              />
            </label>
            <button className="primary-button" disabled={!hasWallet || busy === "send"}>
              {busy === "send" ? "Sending..." : "Send"}
            </button>
          </form>
        </section>

        <section className="panel full-width">
          <div className="panel-head">
            <h2>Activity</h2>
          </div>
          {activities.length === 0 ? (
            <p className="empty-state">No activity yet.</p>
          ) : (
            <div className="activity-list">
              {activities.map((item, index) => (
                <ActivityItem key={`${item.timestamp}-${index}`} item={item} />
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
