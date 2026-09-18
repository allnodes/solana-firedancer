<p align="center">
    <br /><br />
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="allnodes/images/firedancer-dark-mode.png" />
      <img alt="Firedancer Allnodes Edition" src="allnodes/images/firedancer-light-mode.png" style="width: 16em" />
    </picture>
</p>

# Firedancer Solana validator with modifications from Allnodes

# [Firedancer](https://jumpcrypto.com/firedancer/) 🔥💃

Firedancer is a new validator client for Solana.

* **Fast** Designed from the ground up to be *fast*. The concurrency
  model draws from experience in the low latency trading space, and the code
  contains many novel high-performance reimplementations of core Solana
  primitives.
* **Secure** The architecture of the validator allows it to run with a
  highly restrictive sandbox and almost no system calls.
* **Independent** Firedancer is written from scratch. This brings client
  diversity to the Solana network and helps it stay resilient to supply
  chain attacks in build tooling or dependencies.

## Modifications made by Allnodes

This repository features the following enhancements to the Firedancer codebase:

### Fast snapshot distribution

✅ Only on [Allnodes Bare-Metal Servers](https://www.allnodes.com/hosting/solana)

Our infrastructure includes modifications that improve default snapshot downloading, which combined with
ultra-high-speed channels deliver ultra-fast snapshot downloads. This dramatically reduces the initial sync time for
new validators and enables faster deployment and recovery scenarios.



## Documentation
If you are an operator or looking to run the validator, see the Getting
Started guide in the [Firedancer
docs](https://docs.firedancer.io/)

## Releases
If you are an operator looking to run the validator, see the [Releases
Guide](https://docs.firedancer.io/guide/getting-started.html#releases)
in the documentation.

The Firedancer project is producing two validators,

* **Frankendancer** A hybrid validator using parts of Firedancer and
  parts of Agave. Frankendancer uses the Firedancer networking stack and
  block production components to perform better while leader. Other
  functionality including execution and consensus is using the Agave
  validator code.
* **Firedancer** A full from-scratch Firedancer with no Agave code.

Both validators are built from this codebase.

## Developing
Firedancer currently only supports Linux and requires a relatively new
kernel, at least v4.18 to build.

```console
$ git clone --recursive https://github.com/allnodes/solana-firedancer.git
$ cd solana-firedancer
$ ./deps.sh
$ source activate  # enter build environment
$ make -j

# Run a new development cluster
$ firedancer-dev

# Join Solana testnet
$ firedancer-dev --testnet
```

`firedancer-dev` (without args) configures your system for validator
operation and creates a new lcoal development cluster. First it creates
a genesis block, some keys, a faucet, and then it starts a validator on
the local machine. `firedancer-dev` will use `sudo` to make privileged
changes to system configuration where needed. If `sudo` is not available,
you may need to run the command as root.

If you wish to join this cluster with other validators, you can define
`[gossip.entrypoints]` in the configuration file to point at your first
validator and join with `firedancer-dev run`.

## License
Firedancer is available under the [Apache 2
license](https://www.apache.org/licenses/LICENSE-2.0). Firedancer also
includes external libraries that are available under a variety of
licenses. See [LICENSE](LICENSE) for the full license text.
