# FTPNet
Simple implementation of the FTP protocol (client side) using .NET 3.5

This repository is not actively maintained; but maybe this is still helpful for someone trying to implement the FTP protocol on their own.

The repository contains two implementations of the protocol:

- a very basic version for classic .NET 3.5 (for Desktop applications), no advanced features
- a extended version which can be compiled as a portable library with advanced features

To use the portable library who might have to update the *Bouncy Castle* library inside the project which is responsible for the SSL/TLS encryption. Look [here](http://www.bouncycastle.org/csharp/) for a suitable replacement.

![Top half of class diagram](https://github.com/FlashTek/FTPNet/raw/master/class_diagram_top.png)
![Bottom half of class diagram](https://github.com/FlashTek/FTPNet/raw/master/class_diagram_bottom.png)
