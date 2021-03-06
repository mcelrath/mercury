# Mercury Client

## Introduction
Mercury client is a bitcoin minimalist decentralized wallet CLI app with a client side
state chain implementation.

## Requirement
Mercury server is required to interact with the client, for instruction on how to run it see [here](../server/README.md).

## Installation
```bash
git clone https://github.com/commerceblock/mercury.git
cd mercury/client
cargo build --release
```

## Using the CLI
```bash
../target/release/cli --help            
```

```text
Command Line Interface for a minimalist decentralized crypto-currency wallet

USAGE:
    cli [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Sets the level of verbosity

SUBCOMMANDS:
    create-wallet    Create a new wallet
    help             Prints this message or the help of the given subcommand(s)
    wallet           Operation on wallet
```

## Wallet creation (required)
```bash
../target/release/cli create-wallet
```


## Wallet operations
```bash
../target/release/cli wallet --help
```

```text
Operation on wallet

USAGE:
    cli wallet [FLAGS] [SUBCOMMAND]

FLAGS:
    -b               Total balance
    -h, --help       Prints help information
    -u               List unspent transactions (tx hash)
    -a               Generate a new address
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    send    Send a transaction
```
### Get a derived/new address (HD)
```bash
../target/release/cli wallet -a
```

* Output:
```text
Network: [testnet], Address: [tb1quxl4c4cyl3586s7tuql7tqqsv233sumxz0588a]
```

### Get total balance
```bash
../target/release/cli wallet -b
```

* Output:
```text
Network: [testnet], Balance: [balance: 1100000, pending: 0]
```

### Get list unspent
```bash
../target/release/cli wallet -u
```

* Output:
```text
Network: [testnet], Unspent tx hashes: [
bc32ff53c1b9f71d7a6a5e3f5ec7bc8d20afe50214110a0718c9004be33d57d6
53bc8eca351446f0ec2c13a978243b726a132792305a6758bfc75c67209f9d6b
]
```

### Send a transaction
```bash
../target/release/cli wallet send -t [ADDRESS] -a [BTC_AMOUNT]
```

* Example:
```bash
../target/release/cli wallet send -t tb1quxl4c4cyl3586s7tuql7tqqsv233sumxz0588a -a 0.0001
```

* Output:
```text
Network: [testnet], Sent 0.0001 BTC to address tb1quxl4c4cyl3586s7tuql7tqqsv233sumxz0588a. Transaction ID: 44545bf81fc8aebcde855c2e33a5f83a17a93f76164330e1ee9e366e8e039444
```

* Explorer:
https://www.blocktrail.com/tBTC/tx/44545bf81fc8aebcde855c2e33a5f83a17a93f76164330e1ee9e366e8e039444
