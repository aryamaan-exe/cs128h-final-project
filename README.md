# cs128h-final-project — Simplified Surfshark

**Team Members:** Ari, Aidan, Sabona

## Project Introduction

The following project will implement a simplified version of Surfshark's VPN service. This is a simplified CLI tool in Rust that allows the user to use  through the OpenVPN protocol. We have chosen to work on this project primarily for pedagogical reasons to learn the basics of computer networking.

### Goals and Objectives

* Create something that makes a simplified encrypted calls via the OpenVPN protocol.

## Technical Overview

Overall the project will need to be able to:
* Create a secure tunnel to the OpenVPN server
* Encrypt outgoing signals
* Decrypt incoming signals

### Checkpoint 1

* The project should be able to use the OpenVPN daemon.

### Checkpoint 2

* The project should be in full working capacity minus minor bugs and details.

## Possible Challenges

* This is the first time most of us are working with any networking service.
* OpenVPN / Rust interoperability issues.

## References

* https://tokio.rs/
* https://docs.rs/tun/latest/tun/
* https://github.com/cloudflare/boringtun
* Computer Networking, a Top Down Approach (Kurose, Ross) isbn: 9780133594140
* TCP/IP Illustrated (ISBN 9780201633467)
* https://www.shshell.com/blog/linux-module-11-lesson-5-vpn
