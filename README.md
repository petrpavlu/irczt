# IRCZT testing server

## Overview

IRCZT is a testing IRC server. It operates as a simple IRC server and implements
a set of local bots with randomized behaviour. The bots are able to join+leave
channels and send "Lorem ipsum"-style messages to joined channels.

The server is intended as a traffic generator for testing IM clients. It was
primarily created for testing chat support in [CenterIM 5][CenterIM5]. The
server implements a subset of [RFC 1459][RFC1459] and [RFC 2812][RFC2812],
mostly what is used by libpurple of [the Pidgin project][Pidgin].

## Usage

IRCZT is written in [the Zig programming language][Zig]. Pre-compiled Zig
binaries can be obtained from [its download page][ZigDownload]. The IRCZT code
has been tested with Zig 0.7.0.

To start IRCZT, run the following command from the project's top directory:

```
zig build run
```

The server by default listens on 127.0.0.1:6667. This can be changed in
`src/config.zig`.

The program can be gracefully terminated by pressing `<Enter>`.

## License

This project is released under the terms of [the MIT License](COPYING).

[CenterIM5]: http://centerim.org/
[RFC1459]: https://tools.ietf.org/html/rfc1459
[RFC2812]: https://tools.ietf.org/html/rfc2812
[Pidgin]: https://pidgin.im/
[Zig]: https://ziglang.org/
[ZigDownload]: https://ziglang.org/download/
