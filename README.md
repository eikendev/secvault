# About

This repository contains my first Linux kernel module.
It was created as a project in the lecture "Operating Systems" at [TU Wien](https://www.tuwien.at/).

The basic idea is that users can have secure storage.
The storage is managed by the kernel, and encrypted using a very basic encryption scheme.
Note that the implemented scheme is not meant to be secure, and serves simple demonstration purposes.

# Usage

The project consists of two parts, the kernel module and a user program.
When the kernel module is loaded, it creates a device with which the vaults can be managed.
This device is located at `/dev/sv_ctl`.
The user program uses this device to control the vaults over an `ioctl` API.

This API allows the user to
- create a new vault with a specified size and encryption key,
- query the size of the vault,
- change the key of the vault,
- clear the data in the vault, i.e., set the content to zero, and
- remove the vault.

The number of vaults is limited to `4`, which could be increased easily.
When a vault is created, a new character devices is made accessible as `/dev/sv_data[0-3]`.
This device can be used like any normal character device via `open()`, `release()`, `seek()`, `read()` and `write()`.
