// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.os.posix;
const time = std.os.time;

const Allocator = std.mem.Allocator;
const LinkedList = std.LinkedList;
const assert = std.debug.assert;

// TODO Add a format wrapper to escape non-printable characters in received commands.
// TODO Prefix "protected/private" variables with an underscore.
// TODO Replace create() with createOne().
// TODO Use full std. prefix to avoid name clashes.

const bind_ip4_addr = "127.0.0.1";
const bind_port: u16 = 6667;

const timestamp_str_width = "[18446744073709551.615]".len;

/// Convert a timestamp to a string.
fn formatTimeStamp(output: *[timestamp_str_width]u8, milliseconds: u64) void {
    var rem = milliseconds;
    var i = timestamp_str_width;
    while (i > 0) : (i -= 1) {
        if (i == timestamp_str_width) {
            output[i - 1] = ']';
        } else if (i == timestamp_str_width - 4) {
            output[i - 1] = '.';
        } else if (i == 1) {
            output[i - 1] = '[';
        } else if (rem == 0) {
            if (i > timestamp_str_width - 6) {
                output[i - 1] = '0';
            } else
                output[i - 1] = ' ';
        } else {
            output[i - 1] = '0' + @intCast(u8, rem % 10);
            rem /= 10;
        }
    }
}

test "format timestamp" {
    var buffer: [timestamp_str_width]u8 = undefined;

    formatTimeStamp(&buffer, 0);
    assert(mem.eql(u8, buffer, "[                0.000]"));

    formatTimeStamp(&buffer, 1);
    assert(mem.eql(u8, buffer, "[                0.001]"));

    formatTimeStamp(&buffer, 100);
    assert(mem.eql(u8, buffer, "[                0.100]"));

    formatTimeStamp(&buffer, 1000);
    assert(mem.eql(u8, buffer, "[                1.000]"));

    formatTimeStamp(&buffer, 10000);
    assert(mem.eql(u8, buffer, "[               10.000]"));

    formatTimeStamp(&buffer, 1234567890);
    assert(mem.eql(u8, buffer, "[          1234567.890]"));

    formatTimeStamp(&buffer, 18446744073709551615);
    assert(mem.eql(u8, buffer, "[18446744073709551.615]"));
}

var stdout_file_out_stream: os.File.OutStream = undefined;
var stdout_stream: ?*io.OutStream(os.File.WriteError) = null;

var stderr_file_out_stream: os.File.OutStream = undefined;
var stderr_stream: ?*io.OutStream(os.File.WriteError) = null;

/// Initialize stdout and stderr streams.
fn initOutput() void {
    if (stdout_stream == null) {
        if (io.getStdOut()) |stdout_file| {
            stdout_file_out_stream = stdout_file.outStream();
            stdout_stream = &stdout_file_out_stream.stream;
        } else |err| {}
    }

    if (stderr_stream == null) {
        if (io.getStdOut()) |stderr_file| {
            stderr_file_out_stream = stderr_file.outStream();
            stderr_stream = &stderr_file_out_stream.stream;
        } else |err| {}
    }
}

/// Print a message on the standard output.
fn info(comptime fmt: []const u8, args: ...) void {
    assert(stdout_stream != null);
    var timestamp: [timestamp_str_width]u8 = undefined;
    formatTimeStamp(&timestamp, time.milliTimestamp());
    stdout_stream.?.print("{} " ++ fmt, timestamp, args) catch return;
}

/// Print a message on the standard error output.
fn warn(comptime fmt: []const u8, args: ...) void {
    assert(stderr_stream != null);
    var timestamp: [timestamp_str_width]u8 = undefined;
    formatTimeStamp(&timestamp, time.milliTimestamp());
    stderr_stream.?.print("\x1b[31m{} " ++ fmt ++ "\x1b[0m", timestamp, args) catch return;
}

/// Thin wrapper around net.Address to provide integration with std.fmt.
const NetAddress = struct {
    // TODO Replace NetAddress with the plain net.Address when it gains proper support for std.fmt.
    addr: net.Address,

    fn formatU16(output: *[5]u8, value: u16) []const u8 {
        var rem = value;
        var i = output.len;
        while (rem > 0 or i == output.len) {
            i -= 1;
            output[i] = '0' + @intCast(u8, rem % 10);
            rem /= 10;
        }
        return output[i..];
    }

    fn format(
        self: NetAddress,
        comptime fmt: []const u8,
        context: var,
        comptime FmtError: type,
        output: fn (@typeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        assert(self.addr.os_addr.in.family == posix.AF_INET);

        const native_endian_port = std.mem.endianSwapIfLe(u16, self.addr.os_addr.in.port);
        const bytes = @sliceToBytes((*[1]u32)(&self.addr.os_addr.in.addr)[0..]);

        var tmp: [5]u8 = undefined;
        try output(context, formatU16(&tmp, bytes[0]));
        try output(context, ".");
        try output(context, formatU16(&tmp, bytes[1]));
        try output(context, ".");
        try output(context, formatU16(&tmp, bytes[2]));
        try output(context, ".");
        try output(context, formatU16(&tmp, bytes[3]));
        try output(context, ":");
        return output(context, formatU16(&tmp, native_endian_port));
    }
};

const Lexer = struct {
    message: []const u8,
    pos: usize,

    fn getCurPos(self: *Lexer) usize {
        return self.pos;
    }

    fn getCurChar(self: *Lexer) u8 {
        if (self.pos < self.message.len)
            return self.message[self.pos];
        return 0;
    }

    fn nextChar(self: *Lexer) void {
        if (self.pos < self.message.len)
            self.pos += 1;
    }

    fn getWord(self: *Lexer) []const u8 {
        const begin = self.pos;

        var end = begin;
        while (self.getCurChar() != '\x00' and self.getCurChar() != ' ') : (end += 1)
            self.nextChar();

        while (self.getCurChar() == ' ')
            self.nextChar();

        return self.message[begin..end];
    }

    fn getParam(self: *Lexer) []const u8 {
        if (self.getCurChar() == ':') {
            const begin = self.pos + 1;
            self.pos = self.message.len;
            return self.message[begin..self.pos];
        }
        return self.getWord();
    }
};

const Client = struct {
    parent: ?*ClientList.Node,
    allocator: *Allocator,
    fd: i32,
    addr: NetAddress,

    write_file_out_stream: os.File.OutStream,
    write_stream: ?*io.OutStream(os.File.WriteError),

    const InputState = enum {
        Normal,
        Normal_CR,
        Invalid,
        Invalid_CR,
    };
    input_state: InputState,
    input_buffer: [512]u8,
    input_received: usize,

    /// Flag indicating whether the initial USER and NICK pair was already received and the client
    /// is fully joined.
    joined: bool,

    const RealNameType = [512]u8;
    realname: RealNameType,
    realname_end: usize,
    const NickNameType = [9]u8;
    nickname: NickNameType,
    nickname_end: usize,

    /// Create a new client instance, which takes ownership for the passed client descriptor. If
    /// constructing the client fails, the file descriptor gets closed.
    fn create(fd: i32, sockaddr: posix.sockaddr, allocator: *Allocator) !*Client {
        errdefer os.close(fd);

        const addr = NetAddress{ .addr = net.Address.initPosix(sockaddr) };
        info("{}: Accepted a new client connection.\n", addr);

        const init_node = ClientList.Node.init(Client{
            .parent = null,
            .allocator = allocator,
            .fd = fd,
            .addr = addr,
            .write_file_out_stream = os.File.openHandle(fd).outStream(),
            .write_stream = null,
            .input_state = Client.InputState.Normal,
            .input_buffer = undefined,
            .input_received = 0,
            .joined = false,
            .realname = []u8{0} ** Client.RealNameType.len,
            .realname_end = 0,
            .nickname = []u8{0} ** Client.NickNameType.len,
            .nickname_end = 0,
        });
        const dyn_node = allocator.create(init_node) catch |err| {
            warn("{}: Failed to allocate a client node: {}.\n", addr, @errorName(err));
            return err;
        };
        dyn_node.data.parent = dyn_node;
        dyn_node.data.write_stream = &dyn_node.data.write_file_out_stream.stream;
        return &dyn_node.data;
    }

    /// Close connection to a client and destroy the client data.
    fn destroy(self: *Client) void {
        os.close(self.fd);
        self._info("Closed the client connection.\n");
        self.allocator.destroy(self.parent);
    }

    /// Get a slice with the client's real name.
    fn _getRealName(self: *Client) []const u8 {
        return self.realname[0..self.realname_end];
    }

    /// Get a slice with the client's nick name.
    fn _getNickName(self: *Client) []const u8 {
        return self.nickname[0..self.nickname_end];
    }

    fn _info(self: *Client, comptime fmt: []const u8, args: ...) void {
        info("{}: " ++ fmt, self.addr, args);
    }

    fn _warn(self: *Client, comptime fmt: []const u8, args: ...) void {
        warn("{}: " ++ fmt, self.addr, args);
    }

    fn _acceptParamMax(self: *Client, lexer: *Lexer, param: []const u8, maxlen: usize) ![]const u8 {
        const begin = lexer.getCurPos();
        const res = lexer.getParam();
        if (res.len == 0) {
            self._warn("Position {}, expected parameter {}.\n", begin + 1, param);
            return error.NeedsMoreParams;
        }
        if (res.len > maxlen) {
            self._warn("Position {}, parameter {} is too long (maximum: {}, actual: {}).\n", begin + 1, param, maxlen, res.len);
            // IRC has no error reply for too long parameters, so cut-off the value.
            return res[0..maxlen];
        }
        return res;
    }

    fn _acceptParam(self: *Client, lexer: *Lexer, param: []const u8) ![]const u8 {
        return self._acceptParamMax(lexer, param, math.maxInt(usize));
    }

    /// Process the USER command.
    /// Parameters: <username> <hostname> <servername> <realname>
    fn _processCommand_USER(self: *Client, lexer: *Lexer) !void {
        if (self.realname_end != 0)
            return error.AlreadyRegistred;

        const username = try self._acceptParam(lexer, "<username>");
        const hostname = try self._acceptParam(lexer, "<hostname>");
        const servername = try self._acceptParam(lexer, "<servername>");

        const realname = try self._acceptParamMax(lexer, "<realname>", self.realname.len);
        mem.copy(u8, self.realname[0..], realname);
        self.realname_end = realname.len;

        // TODO Check there no more unexpected parameters.

        // Complete the join if the initial USER and NICK pair was already received.
        if (!self.joined and self.nickname_end != 0)
            try self._join();
    }

    /// Process the NICK command.
    /// Parameters: <nickname>
    fn _processCommand_NICK(self: *Client, lexer: *Lexer) !void {
        const nickname = self._acceptParamMax(lexer, "<nickname>", self.nickname.len) catch |err| {
            if (err == error.NeedsMoreParams) {
                return error.NoNickNameGiven;
            } else
                return err;
        };
        mem.copy(u8, self.nickname[0..], nickname);
        self.nickname_end = nickname.len;

        // TODO
        // ERR_ERRONEUSNICKNAME
        // ERR_NICKNAMEINUSE

        // TODO Check there no more unexpected parameters.

        // Complete the join if the initial USER and NICK pair was already received.
        if (!self.joined and self.realname_end != 0)
            try self._join();
    }

    /// Complete the client join after the initial USER and NICK pair is received.
    fn _join(self: *Client) !void {
        assert(!self.joined);
        assert(self.realname_end != 0);
        assert(self.nickname_end != 0);

        // TODO Get the IP address by referencing the server struct.
        // TODO RPL_LUSERCLIENT
        const nickname = self._getNickName();
        try self._sendMessage(":{} 251 {} :There are {} users and 0 invisible on 1 servers", bind_ip4_addr, nickname, i32(1));
        // TODO Send motd.
        try self._sendMessage(":irczt-connect PRIVMSG {} :Hello", nickname);
        self.joined = true;
    }

    /// Send a message to the client.
    fn _sendMessage(self: *Client, comptime fmt: []const u8, args: ...) !void {
        self._info("> " ++ fmt ++ "\n", args);
        try self.write_stream.?.print(fmt ++ "\r\n", args);
    }

    /// Process a single message from the client.
    fn _processMessage(self: *Client, message: []const u8) void {
        self._info("< {}\n", message);

        var lexer = Lexer{ .message = message, .pos = 0 };

        // Parse any prefix.
        if (lexer.getCurChar() == ':') {
            // TODO Error.
        }

        // Parse the command name.
        const command = lexer.getWord();
        // TODO Error handling.
        var res: anyerror!void = {};
        if (mem.eql(u8, command, "USER")) {
            res = self._processCommand_USER(&lexer);
        } else if (mem.eql(u8, command, "NICK")) {
            res = self._processCommand_NICK(&lexer);
        } else
            self._warn("Unrecognized command: {}\n", command);

        if (res) {} else |err| {
            self._warn("Error: {}!\n", command);
            // TODO
        }
    }

    fn processInput(self: *Client) !void {
        assert(self.input_received < self.input_buffer.len);
        var pos = self.input_received;
        // TODO Use io.InStream.
        const read = try os.posixRead(self.fd, self.input_buffer[pos..]);
        if (read == 0) {
            // TODO read = 0 -> EOF. Report any unhandled data.
        }
        self.input_received += read;

        var message_begin: usize = 0;
        while (pos < self.input_received) : (pos += 1) {
            const char = self.input_buffer[pos];
            switch (self.input_state) {
                Client.InputState.Normal => {
                    if (char == '\r')
                        self.input_state = Client.InputState.Normal_CR;
                    // TODO Check for invalid chars.
                },
                Client.InputState.Normal_CR => {
                    if (char == '\n') {
                        self._processMessage(self.input_buffer[message_begin .. pos - 1]);
                        self.input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else {
                        // TODO Print an error message.
                        self.input_state = Client.InputState.Invalid;
                    }
                },
                Client.InputState.Invalid => {
                    if (char == '\r')
                        self.input_state = Client.InputState.Invalid_CR;
                },
                Client.InputState.Invalid_CR => {
                    if (char == '\n') {
                        self.input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else
                        self.input_state = Client.InputState.Invalid;
                },
            }
        }

        switch (self.input_state) {
            Client.InputState.Normal, Client.InputState.Normal_CR => {
                if (message_begin >= self.input_received) {
                    assert(message_begin == self.input_received);
                    self.input_received = 0;
                } else if (message_begin == 0) {
                    // TODO Message overflow.
                    if (self.input_state == Client.InputState.Normal) { // TODO Remove braces.
                        self.input_state = Client.InputState.Invalid;
                    } else
                        self.input_state = Client.InputState.Invalid_CR;
                } else {
                    mem.copy(u8, self.input_buffer[0..], self.input_buffer[message_begin..self.input_received]);
                    self.input_received -= message_begin;
                }
            },
            Client.InputState.Invalid, Client.InputState.Invalid_CR => {
                self.input_received = 0;
            },
        }
    }
};

const ClientList = LinkedList(Client);

const Server = struct {
    allocator: *Allocator,

    sockaddr: net.Address,
    host: []const u8,
    port: []const u8,

    clients: ClientList,

    fn create(address: []const u8, allocator: *Allocator) !*Server {
        // Parse the address.
        var host_end: usize = address.len;
        var port_start: usize = address.len;
        for (address) |char, i| {
            if (char == ':') {
                host_end = i;
                port_start = i + 1;
                break;
            }
        }

        const host = address[0..host_end];
        const port = address[port_start..address.len];

        const parsed_host = net.parseIp4(host) catch |err| {
            warn("Failed to parse IP address '{}': {}.\n", host, @errorName(err));
            return err;
        };
        const parsed_port = std.fmt.parseUnsigned(u16, port, 10) catch |err| {
            warn("Failed to parse port number '{}': {}.\n", port, @errorName(err));
            return err;
        };

        // Make a copy of the host and port strings.
        const host_copy = allocator.alloc(u8, host.len) catch |err| {
            warn("Failed to allocate a host string buffer: {}.\n", @errorName(err));
            return err;
        };
        errdefer allocator.free(host_copy);
        mem.copy(u8, host_copy, host);

        const port_copy = allocator.alloc(u8, port.len) catch |err| {
            warn("Failed to allocate a port string buffer: {}.\n", @errorName(err));
            return err;
        };
        errdefer allocator.free(port_copy);
        mem.copy(u8, port_copy, port);

        // Allocate the server struct.
        const server = allocator.createOne(Server) catch |err| {
            warn("Failed to allocate a server instance: {}.\n", @errorName(err));
            return err;
        };
        server.* = Server{
            .allocator = allocator,
            .sockaddr = net.Address.initIp4(parsed_host, parsed_port),
            .host = host_copy,
            .port = port_copy,
            .clients = ClientList.init(),
        };
        return server;
    }

    fn destroy(self: *Server) void {
        self.allocator.free(self.host);
        self.allocator.free(self.port);
        self.allocator.destroy(self);
    }

    fn run(self: *Server) !void {
        // Create the server socket.
        const listenfd = os.posixSocket(posix.AF_INET, posix.SOCK_STREAM | posix.SOCK_CLOEXEC, posix.PROTO_tcp) catch |err| {
            warn("Failed to create a server socket: {}.\n", @errorName(err));
            return err;
        };
        defer os.close(listenfd);

        os.posixBind(listenfd, &self.sockaddr.os_addr) catch |err| {
            warn("Failed to bind to address {}:{}: {}.\n", self.host, self.port, @errorName(err));
            return err;
        };

        os.posixListen(listenfd, posix.SOMAXCONN) catch |err| {
            warn("Failed to listen on {}:{}: {}.\n", self.host, self.port, @errorName(err));
            return err;
        };

        // Create an epoll instance and register the server socket with it.
        const epfd = os.linuxEpollCreate(posix.EPOLL_CLOEXEC) catch |err| {
            warn("Failed to create an epoll instance: {}.\n", @errorName(err));
            return err;
        };
        defer os.close(epfd);

        var listenfd_event = posix.epoll_event{
            .events = posix.EPOLLIN,
            .data = posix.epoll_data{ .ptr = 0 },
        };
        os.linuxEpollCtl(epfd, posix.EPOLL_CTL_ADD, listenfd, &listenfd_event) catch |err| {
            warn("Failed to add the server socket to the epoll instance: {}.\n", @errorName(err));
            return err;
        };

        // Destroy at the end all clients that will be created.
        defer {
            while (self.clients.pop()) |client_node| {
                // Destroy the client and its LinkedList node.
                client_node.data.destroy();
            }
        }

        // Listen for events.
        info("Listening on {}:{}.\n", self.host, self.port);
        while (true) {
            var events: [1]posix.epoll_event = undefined;
            const ep = os.linuxEpollWait(epfd, events[0..], -1);
            if (ep == 0)
                continue;

            // Check for a new connection and accept it.
            if (events[0].data.ptr == 0) {
                var client_sockaddr: posix.sockaddr = undefined;
                const clientfd = os.posixAccept(listenfd, &client_sockaddr, posix.SOCK_CLOEXEC) catch |err| {
                    warn("Failed to accept a new client connection: {}.\n", @errorName(err));
                    continue;
                };

                // Create a new client. This transfers ownership of the clientfd to the Client
                // instance.
                const client = Client.create(clientfd, client_sockaddr, self.allocator) catch continue;

                // Listen for the client.
                // FIXME .events
                var clientfd_event = posix.epoll_event{
                    .events = posix.EPOLLIN,
                    .data = posix.epoll_data{ .ptr = @ptrToInt(client) },
                };
                os.linuxEpollCtl(epfd, posix.EPOLL_CTL_ADD, clientfd, &clientfd_event) catch |err| {
                    warn("Failed to add a client socket to the epoll instance: {}.\n", @errorName(err));
                    client.destroy();
                    continue;
                };

                self.clients.append(client.parent.?);
            } else {
                const client = @intToPtr(*Client, events[0].data.ptr);
                // TODO
                try client.processInput();
            }
        }
    }
};

pub fn main() u8 {
    // Initialize stdout and stderr streams.
    initOutput();

    // Get an allocator.
    const allocator = std.heap.c_allocator;

    // Create and run the server.
    const server = Server.create("127.0.0.1:6667", allocator) catch return 1;
    defer server.destroy();
    server.run() catch return 1;

    return 0;
}
