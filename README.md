# btc-collider-rs


## What
The Bitcoin address collider
1. generates public/private keys
2. derives the corresponding wallet addresses
3. determines if the address has been used

## How
TODO

## Why
This project enabled me to
- learn Rust
- explore cryptographical security of bitcoin addresses

## Usage

By default, the collider searches for collisions with the top 10 funded bitcoin addresses (as of April 2022).

```rust
cargo run --release
```


To increase the probabilty of a collision you can use an extended list of bitcoin addresses, e.g. all funded addresses or all addresses ever used.
Once you downloaded the list, replace the soft link in the `addresses` folder as shown below.

```bash
ln -sf <addresses_file>.txt.gz latest.txt.gz
```
