# mtxchat

This is the skeleton of a Signal chat application.

The UI and local storage are provided by the xous chat library.

Contributions to development of apps/sigchat and libs/chat are most welcome.


## Build

### Environment Setup

- clone `xous-core`: git clone https://github.com/betrusted-io/xous-core.git
- clone `sigchat`: git clone https://github.com/bunnie/sigchat.git

This creates a directory structure like this:

```
build directory
├── xous-core
└── sigchat
```

### Manifest Setup

For now, the app manifest has to be set in xous-core by running this command in the `xous-core` tree:

`cargo xtask app-image sigchat`

This is just a matter of creating the manifest entry in the `gam`, if this flow generally works this will be worked around with a better solution.

### Out of Tree Sigchat build

In the `sigchat` tree, run this command:

`cargo build --release --target riscv32imac-unknown-xous-elf`

Note that you will need to have a GCC compiler installed to build the `ring` stuff.

When this completes, you should have the ELF executable in `target/riscv32imac-unknown-xous-elf/release/sigchat`

### Create a Disk Image

Back in the `xous-core` tree, run this command:

`cargo xtask app-image ../sigchat/target/riscv32imac-unknown-xous-elf/release/sigchat`

This should pull the `sigchat` ELF into the disk image, and attempt to launch it.

I *think* because of the bodge on the app manifest, it may fail to launch because the `app-image` command would reconfigure the system to not have the `sigchat` context anymore. But if you can get to this point, I'll fix that...


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

