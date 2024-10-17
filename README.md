# Linux Kernel Module: Path Protection Reference Monitor

This Linux kernel module implements a **Reference Monitor** to protect specific filesystem paths. It monitors and intercepts access to particular paths, preventing unauthorized access to sensitive directories or files in a Linux system. The protection works by hooking into system calls and performing checks against a defined set of paths.

## Features

- **Path Monitoring**: Hooks into system calls to monitor access to specific filesystem paths.
- **Deferred Work**: Utilizes workqueues for deferred work execution, allowing for non-blocking path verification.
- **Parent Path Check**: Verifies the entire path hierarchy, ensuring that access control applies to parent directories as well.
- **Efficient Design**: Lightweight module with minimal overhead on system performance.

## Requirements

- Linux Kernel version < 6, otherwise the module which search and change the system call table doesn't work

## Installation

1. Clone the repository:
   ```bash
   git clone [<repository-url>](https://github.com/andreaxdf/Reference_monitor.git)
   ```
2. Compile and mount the kernel modules:
   ```bash
   make
   ```

## Usage

1. Once the module is loaded, the monitor state, like the paths to protect, can be changed using the cli interface.
2. The cli interface can be executed with the following instructions:
   ```bash
   cd user_interface
   make
   sudo ./cli_interface
   ```
3. In the cli interface 4 different commands are available:
  - show monitor state, to see the protected paths, if the monitor is active and/or reconfigurable.
  - change monitor state, to change the current monitor state to one of the following:
    - ON
    - OFF
    - REC-ON
    - REC-OFF
  - add a protected path, to add a new path to protect.
  - remove a protected path, to remove a protected path.
4. The reference monitor will log and prevent access to the protected paths.
5. You can inspect the logs in `/tmp/refmon_log/the-file` or using the following command:
   ```bash
   make show-log_file
   ```

### Prevented actions

The reference monitor prevent all the access that try to:
1. write on a protected file.
2. create a new hard link of a protected file or in a protected directory.
3. create a new symbolic link of the file or in a protected directory.
4. remove a protected file, protected directory or any file in a protected directory.
5. create a new directory in a protected one.
6. remove a protected directory.
7. rename a protected file or a protected directory.

### Example

To monitor and protect access to `/home/sensitive_data`:
1. Compile and load the module
2. Using the cli interface, add the path to the module
3. Change the status from REC-OFF - the default - to ON or REC-ON, if you still want to change something else.
4. Now on any non-reading access to that path will be denied and logged in the file log.

The module will now monitor access to `/home/sensitive_data`.

## Uninstallation

To remove the module from the kernel:

```bash
make clean
```
