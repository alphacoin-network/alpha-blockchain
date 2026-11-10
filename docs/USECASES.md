# Alpha Blockchain — Real-World Use Cases

Every LIVE feature below is verified on-chain. All commands work via
`alpha_cli <method> [args]` against a running node (or the public seed at
`68.178.163.58:8333`). Features are composable — real apps combine them.

---

## 1. Merchant checkout (Pay + QR + Invoice)
A shop wants ALPHA payments with a verifiable receipt.
```bash
alpha_cli createinvoice 5.0 "Order #1042"        # → invoice_id + payment link
# shop shows the customer a QR of "alpha:<merchant_addr>" (see wallet.html)
alpha_cli payinvoice <invoice_id>                 # customer pays — merchant gets ALPHA
alpha_cli listinvoices                            # "paid": true — verifiable on-chain
```
**Real flow:** invoice → QR payment → on-chain paid status → fulfil order.

## 2. P2P trade with escrow (Escrow)
Buyer & seller don't trust each other — an arbiter settles disputes.
```bash
alpha_cli escrowopen <token> 100 <buyer> <arbiter> 1008   # seller locks goods-token
# buyer inspects; on agreement:
alpha_cli escrowrelease <escrow_id>    # → tokens to buyer
# OR dispute:
alpha_cli escrowdispute <escrow_id>    # frozen
alpha_cli escrowrefund  <escrow_id>    # arbiter returns to seller
alpha_cli escrowclaim   <escrow_id>    # buyer auto-claims after expiry
```

## 3. Collateralized lending (Lending)
Borrow ALPHA against token collateral.
```bash
alpha_cli loanopen <coll_token> 200 5.0 500 4032   # lock 200 tokens, want 5 ALPHA, 5%, ~28d
alpha_cli loanfund <loan_id>        # lender pays the borrower 5 ALPHA
alpha_cli loanrepay <loan_id>       # borrower repays 5.25 → collateral released
# if unpaid past due_height:
alpha_cli loanseize <loan_id>       # lender takes the collateral
```

## 4. Token launch & trade (Tokens + DEX + AMM)
```bash
alpha_cli createtoken "MyCoin" 2 1000000      # issue
alpha_cli dexsell <token_id> 1000 50          # order-book: 1000 for 50 ALPHA
alpha_cli dexswap <token_id> 10               # buyer: instant best-price fill
alpha_cli ammcreate <token_a> <token_b> 30    # AMM pool, 0.3% fee
alpha_cli ammadd <pool_id> 500 500            # add liquidity → LP shares
alpha_cli ammswap <pool_id> <token_in> 10 8   # swap w/ slippage cap
```

## 5. Property investment (RWA + KYC + dividends)
Tokenize a building; only verified investors can hold.
```bash
alpha_cli issuecredential <investor> kyc <kyc_hash>        # KYC provider verifies
alpha_cli createrwatoken "MarinaTower" 2 100000 --kyc_required --kyc_issuer <provider>
alpha_cli rwabacking <token_id> "real_estate" "Registar Custody" <appraisal_hash>
alpha_cli sendtoken <token_id> <investor_addr> 100         # fractional shares (KYC-checked)
alpha_cli rwadistribute <token_id> 20                      # rent: pro-rata ALPHA to holders
```
Non-KYC transfers are **rejected on-chain** — compliant security token.

## 6. Carbon offset (Carbon credits)
```bash
alpha_cli createtoken "CO2-Credit" 2 10000    # 1 token = 1 tonne
alpha_cli rwaretire <token_id> 50 "GreenCorp FY25"  # permanent offset
alpha_cli retirementcerts                     # public proof — no double-count
```

## 7. Supply chain tracking (Enterprise)
```bash
alpha_cli registeritem "Organic Mangoes" "LOT-2025-07"
alpha_cli supplyevent <item_id> "harvested" "Farm, Ratnagiri"
alpha_cli supplyevent <item_id> "shipped"   "Mumbai hub"
alpha_cli supplyevent <item_id> "delivered" "Delhi store"
alpha_cli itemhistory <item_id>             # full auditable timeline
```

## 8. Tamper-evident certificates (Audit)
```bash
alpha_cli issuecertificate <sha256(doc)> "degree" "Vikas Sharma"
# later, anyone verifies the doc is unmodified:
alpha_cli verifycertificate <sha256(doc)>   # verified:true + issuer + height
```

## 9. Digital identity + sign-in (DID + ID + KYC)
```bash
alpha_cli registeridentity "Vikas"               # did:alpha:<addr>
# an app challenges you to prove ownership:
alpha_cli alphaidchallenge <addr> "app.alpha"    # canonical message
alpha_cli signmessage <addr> "<message>"         # you sign
alpha_cli verifymessage <addr> <sig> "<message>" # app verifies → logged in
alpha_cli kycstatus <addr>                       # app's KYC check
```

## 10. Web3 assets (NFT + Domains + Gaming)
```bash
alpha_cli mintnft "Sword #1" "ipfs://sword.png"   # game item
alpha_cli nftsell <nft_id> 2.0                    # list for sale
alpha_cli nftbuy <order_id>                       # someone buys
alpha_cli registerdomain "vikas.alpha"            # human-readable name
alpha_cli resolvedomain "vikas.alpha"             # → address for payments
alpha_cli gameachieve "AlphaQuest" "Boss defeated"  # provable achievement
```

## 11. AI agents + oracle (AI)
```bash
alpha_cli oraclecreate "ALPHA/USD" "price feed"   # data feed
alpha_cli oraclepublish <feed_id> "0.85" <ts>     # signed price updates
alpha_cli oraclelatest <feed_id>                  # dapps read it
alpha_cli agentregister "TradeBot" "https://bot/svc"
alpha_cli agentreceipt "job-42"                   # M2M payment proof
```

## 12. Cross-border remittance (Pay)
```bash
alpha_cli sendtoaddress <recipient> 25      # global, ~10-min settle, low fee
# oracle feed gives the exchange rate; recipient swaps via DEX to local token
```

## 13. Notarized business records (Registry)
```bash
alpha_cli registerbusiness "Acme Ltd" "U74999" "IN" <filing_hash>
alpha_cli updatebusiness <biz_id> "license" "FSSAI-2231"
alpha_cli businessinfo <biz_id>             # verifiable corporate record
```

---

## Combined example — a real shop
1. `registerbusiness` → on-chain identity
2. `createinvoice` → customer QR-pays → `payinvoice` → paid on-chain
3. `supplyevent` → shipment tracking
4. `issuecertificate` → warranty NFT/cert on delivery
5. `agentreceipt` → auto-settle with a supplier bot

All verified against the running chain — every op is an on-chain,
deterministically-indexed transaction.
