# sigchat

This is the skeleton of a Signal chat application.

The UI and local storage are provided by the xous chat library.

Contributions to development of apps/sigchat and libs/chat are most welcome.

## Build

### Environment Setup

- clone `xous-core`: `git clone https://github.com/betrusted-io/xous-core.git`
- clone `sigchat`: `git clone https://github.com/bunnie/sigchat.git`

This creates a directory structure like this:

build directory
├── xous-core
└── sigchat

### Manifest Setup

For now, the app manifest has to be set in xous-core by running this command in the `xous-core` tree:

`cargo xtask app-image sigchat`

Note: this will fail. That is fine. This is just a matter of creating the manifest entry in the `gam`. 
TODO: modify `dummy-template` to do the same thing without failing to avoid confustion. 

### Out of Tree Sigchat build

In the `sigchat` tree, build the binary:
- For hosted: `cargo build --release`
- For renode/hardware: `cargo build --release --target riscv32imac-unknown-xous-elf`

Note that you will need to have a GCC compiler installed to build the `ring` stuff.

When this completes, you should have the ELF executable in `target/release/sigchat` for hosted or `target/riscv32imac-unknown-xous-elf/release/sigchat` for renode/hardware

### Create a Disk Image

Back in the `xous-core` tree, finish linking in the binary:

- For hosted: `cargo xtask run sigchat:../sigchat/release/sigchat`
- For renode/hardware: `cargo xtask app-image sigchat:../sigchat/target/riscv32imac-unknown-xous-elf/release/sigchat`

Note: for development you may want to clean a copy of the pddb each time you run the app which can be done by running

`cp tools/pddb-images/hosted_backup.bin tools/pddb-images/hosted.bin` 

This should pull the `sigchat` ELF into the disk image, and attempt to launch it.

## Prerequisites:


## Functionality

sigchat provides the following basic functionality:
* 


## Structure

The `sigchat` code is primarily concerned with the Signal specific protocols, while the Chat library handles the UI and pddb storage.

The Chat library provides the UI to display a series of Signal post (Posts) in a Signal group (Dialogue) stored in the pddb. Each Dialogue is stored in the `pddb:dict` `sigchat.dialogue` under a descriptive `pddb:key` (ie ``).

`sigchat` passes a menu to the Chat UI:
* `register` to register a new Signal account with a phone number
* `link` this device to an existing Signal account.

The `sigchat` servers is set to receive:
* `SigchatOp::Post` A memory msg containing an outbount user post
* `SigchatOp::Event` A scalar msg containing important Chat UI events
* `sigchat::Menu` A scalar msg containing click on a sigchat MenuItem
* `SigchatOp::Rawkeys` A scalar msg for each keystroke  


## Troubleshooting