# Alpha Wallet — mobile app (Android + iOS)

Self-custody ALPHA wallet built with Expo / React Native. One codebase,
both platforms. Three features:

- **◈ Wallet** — key generated on-device (secp256k1, WIF), QR receive,
  client-side signing, send via the public API. Keys never leave the
  phone (SecureStore/keystore when available).
- **◇ Stake** — real CLTV time-locks built + signed on-device and
  broadcast (`stakeopen` / `unstake` equivalents). Positions tracked via
  `/api/stakes`.
- **⛏ Mine** — real SHA256d proof-of-work via `/api/minework` +
  `/api/submitwork`. Honest note: phones are slow — this is for
  learning/network support, not profit.

## Run (dev)

```bash
cd mobile
npm install
npx expo start        # scan QR with Expo Go (Android/iOS)
```

`react-native-get-random-values` must load before any crypto — App.js
imports it first. If a dep version nags, run `npx expo install <pkg>`.

## Production builds

```bash
npm install -g eas-cli
eas build -p android          # .aab / .apk
eas build -p ios              # needs Apple developer account
```

## Security notes

- The app talks only to the **public** read API
  (`api.alphacoin.network` → `alphacoin.network` fallback) — no RPC
  credentials in the app, ever.
- Transactions are built and signed on-device; the server only sees the
  final raw tx via `/api/broadcast`.
- WIF backup is the user's responsibility — show it once, warn loudly.
