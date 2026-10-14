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

### Enhanced voting logic modifications

✅ Only on [Allnodes Bare-Metal Servers](https://www.allnodes.com/hosting/solana)

Our validator implementation includes voting modifications developed by **Zantetsu | Shinobi Systems** that enhance the
original voting logic.

These modifications work by:

- Taking the next votable slot that the original codebase identifies as potentially ready for voting
- Applying additional criteria before casting the vote
- Providing more sophisticated voting decision-making

This enhancement improves validator consensus participation through more intelligent vote timing and slot evaluation.



## Documentation
If you are an operator or looking to run the validator, see the Getting
Started guide in the [Firedancer
docs](https://docs.firedancer.io/)

## Voting mod configuration

Voting mod (also known as "mostly confirmed threshold" voting patch) is enabled by default and comes with a predefined
configuration which should work for most users. If you wish to use a custom configuration:

1. create a configuration file (default filename is `mostly_confirmed_threshold` located in the current directory from
   where you run the validator). Values in this example are defaults, their meanings will be explained in the next
   section:

```bash
echo '0.45 4 0 24' > ./mostly_confirmed_threshold
```

2. optionally, you can provide a different filename and/or path for the config file in the validator configuration:

```toml
[tiles.tower]
    mostly_confirmed_threshold_config = "/path/to/config/file"
```

The file is checked for changes once a minute. Change it in place, as in the example above: a file that is replaced
(for example by an editor that saves to a new file) or deleted is not read again until the validator restarts.

> In order to disable the voting mod, set `mostly_confirmed_threshold = false` in the `[tiles.tower]` section of the
validator configuration.

## Mostly confirmed threshold configuration file format:

The `mostly_confirmed_threshold` file contains a simple whitespace-separated list of four values:

```
a b c d
```

### Parameters

#### *a* (float) - vote weight threshold
The minimum vote weight threshold required before voting on a slot. Slots that haven't achieved this vote weight will
not be voted on, except for:

- Slots within the "vote ahead of threshold" region
- When the escape hatch distance has been reached

#### *b* (integer) - vote ahead of threshold
The number of slots ahead of the threshold slot to vote on, regardless of vote weight. This parameter reduces vote
latency by allowing voting on recent slots even if they haven't met the threshold.

#### *c* (integer) - skip recovery mode
Controls the stake-weighted vote percentage required on a slot after skips have occurred. Must be one of:

- `0` - No restriction
- `1` - Slot after a skip must have `mostly_confirmed_threshold` before voting
- `2` - Slot after a skip must be confirmed before voting

#### *d* (integer) - escape hatch distance
The maximum number of slots to wait without voting while waiting for the threshold to be met. After this many slots of
non-voting, the validator will vote anyway.

**Purpose**: This escape hatch prevents network deadlock by ensuring progress even when the threshold isn't being
achieved. Without this mechanism, if multiple forks occur simultaneously and all have less than the threshold vote
weight, validators could become stuck waiting indefinitely.

### Default values

When the default configuration file is absent, it is created with the following default values, which are then used:

```
0.45 4 0 24
```

- Threshold: 45% vote weight
- Vote ahead: 4 slots
- Skip recovery: No restriction
- Escape hatch: 24 slots

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
$ git clone https://github.com/allnodes/solana-firedancer.git
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
