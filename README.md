# WireGuard Configurator

This project makes it easier to configure a fleet of servers interconnected via
the [WireGuard](https://wireguard.com) point-to-point virtual private network.

## License

Copyright (c) 2021 Caleb L. Power. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for specific language governing permissions and
limitations under the License.

## About

This project came about for two reasons. First, I needed to add the Go and Rust
programming languages to my toolbox, and I tend to learn languages quickly when
I apply the to something that's actually useful-- I don't like busy work.
Second, I really wanted to stop manually reconfiguring WireGuard's
configuration files for each individual machine when I could automate the
process. Sure, I could probably work some NAT magic, and I still might in the
future, but this seemed quicker, more useful (see reason #1), and ultimately,
more fun. So, keep that in mind when reviewing the code quality-- it'll be
cleaned up in the future (probably).

## Disclaimer

This product should not be used in a production environment at this time.

## Contributions

Contributions of good quality are welcome. However, please do not assume that
pull requets will be automatically accepted.

# Build and Execution

This repository contains `wgconfig-server` (written in Go) and `wgconfig-agent`
(written in Rust). The former serves to manage the various configurations for
all machines in a particular environment, and the latter serves to update its
respective host. Therefore, building requires that your environment contain
both `go` and `rustc` (and `cargo` for the latter, for that matter).

## wgconfig-server

You can build this out by entering the `wgconfig-server` directory and
executing `go install` or `go build` (the latter for portable builds). Then,
execute the binary directly to see the various command-line arguments. Data is
stored in a SQLite database (not my first choice, but I wanted to learn to use
that as well), and the name of the SQLite database file corresponds to the
environment that is specified. (An environment, in this case, corresponds to a
WireGuard interface.)

## wgconfig-agent

You can build this one by entering the `wgconfig-agent` directory and
executing `cargo build --release`. If you do that, the release binary will end
up in the `target/release` folder.

This one should probably run on a cron job, so here are some exit codes to
assist with that:

- 0 indicates that the job ran successfully, but no configs were changed
- 1 indicates that the job ran, but could not retrieve the new config
- 2 indicates that the job ran successfully and the configs were updated
- 101 indicates that the user should read the instructions or something
