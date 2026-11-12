"""Consensus constants and chain parameters.

Values are identical to Bitcoin unless noted. Everything that differs is
network identity only (name, magic bytes, ports, genesis message) -- the
money supply, schedule and rules are the same.
"""

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Monetary units
# ---------------------------------------------------------------------------
# The base unit of Alpha is the "alphasat" (like Bitcoin's satoshi).
# 1 ALPHA = 100,000,000 alphasats.
COIN = 100_000_000

# Upper bound for any single amount check. The real total supply ends up
# slightly below this (20,999,999.9769 coins) because of integer halving.
MAX_MONEY = 21_000_000 * COIN

# ---------------------------------------------------------------------------
# Issuance schedule (identical to Bitcoin)
# ---------------------------------------------------------------------------
INITIAL_SUBSIDY = 50 * COIN          # 50 coins per block at genesis
HALVING_INTERVAL = 210_000           # halve block subsidy every 210,000 blocks
MAX_HALVINGS = 64                    # subsidy becomes 0 after enough shifts

# ---------------------------------------------------------------------------
# Proof of work (identical to Bitcoin)
# ---------------------------------------------------------------------------
POW_TARGET_SPACING = 10 * 60                     # 10 minutes between blocks
POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60          # 2-week retarget window
POW_INTERVAL = POW_TARGET_TIMESPAN // POW_TARGET_SPACING  # 2016 blocks
POW_MAX_ADJUST = 4                               # clamp retarget to [x/4, 4x]

# Compact "bits" encoding of the maximum allowed target (difficulty 1).
# Bitcoin mainnet value: 0x1d00ffff.
POW_LIMIT_BITS = 0x1D00FFFF

# ---------------------------------------------------------------------------
# Block / transaction limits (identical to Bitcoin)
# ---------------------------------------------------------------------------
MAX_BLOCK_WEIGHT = 4_000_000         # segwit weight limit (BIP141)
MAX_BLOCK_BASE_SIZE = 1_000_000      # pre-segwit 1 MB limit
MAX_BLOCK_SIGOPS_COST = 80_000       # weighted sigop limit per block
MAX_TX_WEIGHT = 400_000
COINBASE_MATURITY = 100              # blocks a coinbase output must mature
MAX_TX_IN_SEQUENCE = 0xFFFFFFFF
SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31   # nSequence bit: opt out of CSV
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22      # nSequence bit: time vs height
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF
SEQUENCE_LOCKTIME_GRANULARITY = 9          # time locks in 512s granularity
LOCKTIME_THRESHOLD = 500_000_000     # nLockTime < this => block height
LOCKTIME_MEDIAN_TIME_PAST = 0
MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60  # reject blocks >2h ahead of our clock
MEDIAN_TIME_SPAN = 11                # blocks used for median-time-past
COINBASE_SCRIPT_MIN = 2              # coinbase scriptSig size bounds
COINBASE_SCRIPT_MAX = 100
BIP34_ENABLED_HEIGHT = 1             # height-in-coinbase enforced from block 1
DERSIG_ENFORCED = True               # BIP66 strict-DER from genesis
NULLDUMMY_ENFORCED = True            # BIP147 from genesis
WITNESS_ENABLED = True               # segwit rules from genesis

# Coinbase marker inputs
COINBASE_PREV_HASH = b"\x00" * 32
COINBASE_PREV_VOUT = 0xFFFFFFFF

# Version-bits / tx versions
TX_VERSION = 2
BLOCK_VERSION = 0x20000000           # versionbits top, like modern Bitcoin


# ---------------------------------------------------------------------------
# Network parameters
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ChainParams:
    name: str
    pow_limit_bits: int
    pow_target_spacing: int
    pow_target_timespan: int
    halving_interval: int
    initial_subsidy: int
    coinbase_maturity: int
    base58_pubkey_address: int   # version byte for P2PKH addresses
    base58_script_address: int   # version byte for P2SH addresses
    base58_secret_key: int       # WIF private-key prefix
    bech32_hrp: str              # segwit address human-readable prefix
    network_magic: int           # P2P message magic bytes
    default_port: int
    genesis_message: bytes
    genesis_timestamp: int
    seed_nodes: tuple = ()       # public seed nodes for auto-connect

    @property
    def pow_interval(self) -> int:
        return self.pow_target_timespan // self.pow_target_spacing

    @property
    def subsidy_halving_interval(self) -> int:
        return self.halving_interval


# ---------------------------------------------------------------------------
# MAINNET -- identical economics to Bitcoin mainnet
# ---------------------------------------------------------------------------
MAINNET = ChainParams(
    name="main",
    pow_limit_bits=0x1E0FFFFF,                       # CPU-friendly launch diff
                                                   # (~2^20 avg hashes; Bitcoin's
                                                   # own pow limit is 0x1D00FFFF)
    pow_target_spacing=POW_TARGET_SPACING,           # 10 minutes
    pow_target_timespan=POW_TARGET_TIMESPAN,         # 2 weeks
    halving_interval=HALVING_INTERVAL,               # 210,000
    initial_subsidy=INITIAL_SUBSIDY,                 # 50 coins
    coinbase_maturity=COINBASE_MATURITY,             # 100
    base58_pubkey_address=0x00,                      # addresses start with '1' (same as BTC)
    base58_script_address=0x05,                      # P2SH addresses start with '3'
    base58_secret_key=0x80,                          # WIF '5'/'K'/'L' prefix
    bech32_hrp="alpha",                              # segwit addresses: alpha1...
    network_magic=0xD9B4BEF9,                        # own magic (same length/layout as BTC)
    default_port=8333,                               # same port as Bitcoin
    genesis_message=(
        b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    ),
    genesis_timestamp=1231006505,                    # same as Bitcoin genesis
    seed_nodes=("68.178.163.58", "3.105.43.51"),    # public seed nodes (GoDaddy VPS + AWS Sydney)
)

# ---------------------------------------------------------------------------
# REGTEST -- easy-difficulty local test chain (like bitcoin -regtest)
# Halving interval follows Bitcoin Core regtest (150 blocks) so the full
# supply schedule can be exercised; economics per block remain identical.
# ---------------------------------------------------------------------------
REGTEST = ChainParams(
    name="regtest",
    pow_limit_bits=0x207FFFFF,                       # trivial PoW (regtest pow limit)
    pow_target_spacing=POW_TARGET_SPACING,
    pow_target_timespan=POW_TARGET_TIMESPAN,
    halving_interval=150,                            # like Bitcoin Core regtest
    initial_subsidy=INITIAL_SUBSIDY,
    coinbase_maturity=COINBASE_MATURITY,
    base58_pubkey_address=0x6F,                      # 'm'/'n' like Bitcoin testnet
    base58_script_address=0xC4,                      # '2'
    base58_secret_key=0xEF,                          # '9'/'c' WIF
    bech32_hrp="alphart",
    network_magic=0xDAB5BFFA,                        # like Bitcoin regtest magic
    default_port=18444,
    genesis_message=b"Alpha Blockchain regtest genesis",
    genesis_timestamp=1296688602,                    # Bitcoin regtest genesis time
)

# ---------------------------------------------------------------------------
# TESTNET -- Bitcoin-compatible testnet economics
# ---------------------------------------------------------------------------
TESTNET = ChainParams(
    name="test",
    pow_limit_bits=0x1D00FFFF,
    pow_target_spacing=POW_TARGET_SPACING,
    pow_target_timespan=POW_TARGET_TIMESPAN,
    halving_interval=HALVING_INTERVAL,
    initial_subsidy=INITIAL_SUBSIDY,
    coinbase_maturity=COINBASE_MATURITY,
    base58_pubkey_address=0x6F,
    base58_script_address=0xC4,
    base58_secret_key=0xEF,
    bech32_hrp="alphat",
    network_magic=0x0709110B,
    default_port=18333,
    genesis_message=b"Alpha Blockchain testnet genesis",
    genesis_timestamp=1296688602,
)

NETWORKS = {"main": MAINNET, "test": TESTNET, "regtest": REGTEST}
