// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;
const net = std.net;
const os = std.os;

const Allocator = std.mem.Allocator;
const LinkedList = std.LinkedList;
const assert = std.debug.assert;

const config = @import("config.zig");

const timestamp_str_width = "[18446744073709551.615]".len;

/// Convert timestamp to a string.
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
    formatTimeStamp(&timestamp, os.time.milliTimestamp());
    stdout_stream.?.print("{} " ++ fmt, timestamp, args) catch return;
}

/// Print a message on the standard error output.
fn warn(comptime fmt: []const u8, args: ...) void {
    assert(stderr_stream != null);
    var timestamp: [timestamp_str_width]u8 = undefined;
    formatTimeStamp(&timestamp, os.time.milliTimestamp());
    stderr_stream.?.print("\x1b[31m{} " ++ fmt ++ "\x1b[0m", timestamp, args) catch return;
}

/// Thin wrapper around net.Address to provide integration with std.fmt.
const NetAddress = struct {
    // TODO Replace NetAddress with the plain net.Address when it gains proper support for std.fmt.
    _addr: net.Address,

    fn init(addr: net.Address) NetAddress {
        return NetAddress{ ._addr = addr };
    }

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
        assert(self._addr.os_addr.in.family == os.posix.AF_INET);

        const native_endian_port = mem.endianSwapIfLe(u16, self._addr.os_addr.in.port);
        const bytes = @sliceToBytes((*[1]u32)(&self._addr.os_addr.in.addr)[0..]);

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

/// Thin wrapper for character slices to output non-printable characters as escaped values with
/// std.fmt.
const EscapeFormatter = struct {
    _slice: []const u8,

    fn init(slice: []const u8) EscapeFormatter {
        return EscapeFormatter{ ._slice = slice };
    }

    fn getSlice(self: *const EscapeFormatter) []const u8 {
        return self._slice;
    }

    fn format(
        self: EscapeFormatter,
        comptime fmt: []const u8,
        context: var,
        comptime FmtError: type,
        output: fn (@typeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        if (fmt.len > 0)
            @compileError("Unknown format character: " ++ []u8{fmt[0]});

        for (self._slice) |char| {
            if (char == '\\') {
                try output(context, "\\\\");
            } else if (char >= ' ' and char <= '~') {
                try output(context, []u8{char});
            } else {
                try output(context, "\\x");
                try output(context, []u8{'0' + (char / 10)});
                try output(context, []u8{'0' + (char % 10)});
            }
        }
        return {};
    }
};

/// Alias for EscapeFormatter.init().
fn Protect(slice: []const u8) EscapeFormatter {
    return EscapeFormatter.init(slice);
}

/// Conditional escape provider.
const ConditionalEscapeFormatter = struct {
    _escape: EscapeFormatter,
    _cond: *bool,

    fn init(slice: []const u8, cond: *bool) ConditionalEscapeFormatter {
        return ConditionalEscapeFormatter{
            ._escape = EscapeFormatter.init(slice),
            ._cond = cond,
        };
    }

    fn format(
        self: ConditionalEscapeFormatter,
        comptime fmt: []const u8,
        context: var,
        comptime FmtError: type,
        output: fn (@typeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        if (fmt.len > 0)
            @compileError("Unknown format character: " ++ []u8{fmt[0]});

        if (self._cond.*) {
            try self._escape.format(fmt, context, FmtError, output);
        } else
            try output(context, self._escape.getSlice());
    }
};

/// Alias for ConditionalEscapeFormatter.init().
fn CProtect(slice: []const u8, cond: *bool) ConditionalEscapeFormatter {
    return ConditionalEscapeFormatter.init(slice, cond);
}

const Lexer = struct {
    _message: []const u8,
    _pos: usize,

    /// Construct a Lexer.
    fn init(message: []const u8) Lexer {
        return Lexer{
            ._message = message,
            ._pos = 0,
        };
    }

    /// Return the current position in the input message.
    fn getCurPos(self: *const Lexer) usize {
        return self._pos;
    }

    /// Return the current character.
    fn getCurChar(self: *const Lexer) u8 {
        if (self._pos < self._message.len)
            return self._message[self._pos];
        return 0;
    }

    /// Skip to a next character in the message.
    fn nextChar(self: *Lexer) void {
        if (self._pos < self._message.len)
            self._pos += 1;
    }

    /// Read one word from the message.
    fn readWord(self: *Lexer) []const u8 {
        const begin = self._pos;

        var end = begin;
        while (self.getCurChar() != '\x00' and self.getCurChar() != ' ') : (end += 1)
            self.nextChar();

        while (self.getCurChar() == ' ')
            self.nextChar();

        return self._message[begin..end];
    }

    /// Read one parameter from the message.
    fn readParam(self: *Lexer) []const u8 {
        if (self.getCurChar() == ':') {
            const begin = self._pos + 1;
            self._pos = self._message.len;
            return self._message[begin..self._pos];
        }
        return self.readWord();
    }
};

const Client = struct {
    _parent: *ClientList.Node,
    _server: *Server,
    _allocator: *Allocator,
    _fd: i32,
    _addr: NetAddress,

    _write_file_out_stream: os.File.OutStream,
    _write_stream: ?*io.OutStream(os.File.WriteError),

    const InputState = enum {
        Normal,
        Normal_CR,
        Invalid,
        Invalid_CR,
    };
    _input_state: InputState,
    _input_buffer: [512]u8,
    _input_received: usize,

    /// Flag indicating whether the initial USER and NICK pair was already received and the client
    /// is fully joined.
    _joined: bool,

    const RealNameType = [512]u8;
    _realname: RealNameType,
    _realname_end: usize,
    const NickNameType = [9]u8;
    _nickname: NickNameType,
    _nickname_end: usize,

    /// Create a new client instance, which takes ownership for the passed client descriptor. If
    /// constructing the client fails, the file descriptor gets closed.
    fn create(fd: i32, sockaddr: os.posix.sockaddr, server: *Server, allocator: *Allocator) !*Client {
        errdefer os.close(fd);

        const addr = NetAddress.init(net.Address.initPosix(sockaddr));
        info("{}: Accepted a new client.\n", addr);

        const client_node = allocator.createOne(ClientList.Node) catch |err| {
            warn("{}: Failed to allocate a client node: {}.\n", addr, @errorName(err));
            return err;
        };
        client_node.* = ClientList.Node.init(Client{
            ._parent = client_node,
            ._server = server,
            ._allocator = allocator,
            ._fd = fd,
            ._addr = addr,
            ._write_file_out_stream = os.File.openHandle(fd).outStream(),
            ._write_stream = &client_node.data._write_file_out_stream.stream,
            ._input_state = Client.InputState.Normal,
            ._input_buffer = undefined,
            ._input_received = 0,
            ._joined = false,
            ._realname = []u8{0} ** Client.RealNameType.len,
            ._realname_end = 0,
            ._nickname = []u8{0} ** Client.NickNameType.len,
            ._nickname_end = 0,
        });
        return &client_node.data;
    }

    /// Close connection to a client and destroy the client data.
    fn destroy(self: *Client) void {
        os.close(self._fd);
        self._info("Closed client connection.\n");
        self._allocator.destroy(self._parent);
    }

    /// Get a pointer to the parent LinkedList node. This must be used only by the server.
    fn getNodePointer(self: *const Client) *ClientList.Node {
        return self._parent;
    }

    /// Get the clien file descriptor.
    fn getFileDescriptor(self: *const Client) i32 {
        return self._fd;
    }

    /// Get a slice with the client's real name.
    fn _getRealName(self: *const Client) []const u8 {
        return self._realname[0..self._realname_end];
    }

    /// Get a slice with the client's nick name.
    fn _getNickName(self: *const Client) []const u8 {
        return self._nickname[0..self._nickname_end];
    }

    fn _info(self: *Client, comptime fmt: []const u8, args: ...) void {
        info("{}: " ++ fmt, self._addr, args);
    }

    fn _warn(self: *Client, comptime fmt: []const u8, args: ...) void {
        warn("{}: " ++ fmt, self._addr, args);
    }

    fn _acceptParamMax(self: *Client, lexer: *Lexer, param: []const u8, maxlen: usize) ![]const u8 {
        const begin = lexer.getCurPos();
        const res = lexer.readParam();
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
        if (self._realname_end != 0) {
            // TODO Log an error.
            return error.AlreadyRegistred;
        }

        const username = try self._acceptParam(lexer, "<username>");
        const hostname = try self._acceptParam(lexer, "<hostname>");
        const servername = try self._acceptParam(lexer, "<servername>");

        const realname = try self._acceptParamMax(lexer, "<realname>", self._realname.len);
        mem.copy(u8, self._realname[0..], realname);
        self._realname_end = realname.len;

        // TODO Check there no more unexpected parameters.

        // Complete the join if the initial USER and NICK pair was already received.
        if (!self._joined and self._nickname_end != 0)
            try self._join();
    }

    /// Process the NICK command.
    /// Parameters: <nickname>
    fn _processCommand_NICK(self: *Client, lexer: *Lexer) !void {
        const nickname = self._acceptParamMax(lexer, "<nickname>", self._nickname.len) catch |err| {
            if (err == error.NeedsMoreParams) {
                return error.NoNickNameGiven;
            } else
                return err;
        };
        mem.copy(u8, self._nickname[0..], nickname);
        self._nickname_end = nickname.len;

        // TODO
        // ERR_ERRONEUSNICKNAME
        // ERR_NICKNAMEINUSE

        // TODO Check there no more unexpected parameters.

        // Complete the join if the initial USER and NICK pair was already received.
        if (!self._joined and self._realname_end != 0)
            try self._join();
    }

    /// Complete the client join after the initial USER and NICK pair is received.
    fn _join(self: *Client) !void {
        assert(!self._joined);
        assert(self._realname_end != 0);
        assert(self._nickname_end != 0);

        const nickname = self._getNickName();
        var ec: bool = undefined;

        // Send RPL_LUSERCLIENT.
        // TODO Fix user count.
        try self._sendMessage(&ec, ":{} 251 {} :There are {} users and 0 invisible on 1 servers", self._server.getHostName(), CProtect(nickname, &ec), i32(1));

        // TODO Send motd.
        try self._sendMessage(&ec, ":irczt-connect PRIVMSG {} :Hello", CProtect(nickname, &ec));

        self._joined = true;
    }

    /// Check that the user has fully joined. If not then send ERR_NOTREGISTERED to the client and
    /// return error.NotRegistered.
    fn _checkJoined(self: *Client) !void {
        if (self._joined)
            return;
        try self._sendMessage(null, ":{} 451 * :You have not registered", self._server.getHostName());
        return error.NotRegistered;
    }

    /// Process the LIST command.
    /// Parameters: [<channel>{,<channel>} [<server>]]
    fn _processCommand_LIST(self: *Client, lexer: *Lexer) !void {
        try self._checkJoined();

        // TODO Parse the parameters.

        const nickname = self._getNickName();
        var ec: bool = undefined;

        // Send RPL_LISTSTART.
        try self._sendMessage(&ec, ":{} 321 {} Channel :Users  Name", self._server.getHostName(), CProtect(nickname, &ec));

        // Send RPL_LIST for each channel.
        const channels = self._server.getChannels();
        var it = channels.first;
        while (it) |node| : (it = node.next) {
            const channel = &node.data;
            try self._sendMessage(&ec, ":{} 322 {} {} {} :", self._server.getHostName(), CProtect(nickname, &ec), CProtect(channel.getName(), &ec), channel.getUserCount());
        }

        // Send RPL_LISTEND.
        try self._sendMessage(&ec, ":{} 323 {} :End of /LIST", self._server.getHostName(), CProtect(nickname, &ec));
    }

    /// Send a message to the client.
    fn _sendMessage(self: *Client, escape_cond: ?*bool, comptime fmt: []const u8, args: ...) !void {
        if (escape_cond != null)
            escape_cond.?.* = true;
        self._info("> " ++ fmt ++ "\n", args);
        if (escape_cond != null)
            escape_cond.?.* = false;
        try self._write_stream.?.print(fmt ++ "\r\n", args);
    }

    /// Process a single message from the client.
    fn _processMessage(self: *Client, message: []const u8) void {
        self._info("< {}\n", Protect(message));

        var lexer = Lexer.init(message);

        // Parse any prefix.
        if (lexer.getCurChar() == ':') {
            // TODO Error.
        }

        // Parse the command name.
        const command = lexer.readWord();
        // TODO Error handling.
        var res: anyerror!void = {};
        if (mem.eql(u8, command, "USER")) {
            res = self._processCommand_USER(&lexer);
        } else if (mem.eql(u8, command, "NICK")) {
            res = self._processCommand_NICK(&lexer);
        } else if (mem.eql(u8, command, "LIST")) {
            res = self._processCommand_LIST(&lexer);
        } else
            self._warn("Unrecognized command: {}\n", Protect(command));

        if (res) {} else |err| {
            self._warn("Error: {}!\n", Protect(command));
            // TODO
        }
    }

    fn processInput(self: *Client) !void {
        assert(self._input_received < self._input_buffer.len);
        var pos = self._input_received;
        // TODO Use io.InStream.
        const read = try os.posixRead(self._fd, self._input_buffer[pos..]);
        if (read == 0) {
            // End of file reached.
            self._info("Client disconnected.\n");
            // TODO Report any unhandled data.
            return error.ClientDisconnected;
        }
        self._input_received += read;

        var message_begin: usize = 0;
        while (pos < self._input_received) : (pos += 1) {
            const char = self._input_buffer[pos];
            switch (self._input_state) {
                Client.InputState.Normal => {
                    if (char == '\r')
                        self._input_state = Client.InputState.Normal_CR;
                    // TODO Check for invalid chars.
                },
                Client.InputState.Normal_CR => {
                    if (char == '\n') {
                        self._processMessage(self._input_buffer[message_begin .. pos - 1]);
                        self._input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else {
                        // TODO Print an error message.
                        self._input_state = Client.InputState.Invalid;
                    }
                },
                Client.InputState.Invalid => {
                    if (char == '\r')
                        self._input_state = Client.InputState.Invalid_CR;
                },
                Client.InputState.Invalid_CR => {
                    if (char == '\n') {
                        self._input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else
                        self._input_state = Client.InputState.Invalid;
                },
            }
        }

        switch (self._input_state) {
            Client.InputState.Normal, Client.InputState.Normal_CR => {
                if (message_begin >= self._input_received) {
                    assert(message_begin == self._input_received);
                    self._input_received = 0;
                } else if (message_begin == 0) {
                    // TODO Message overflow.
                    if (self._input_state == Client.InputState.Normal) { // TODO Remove braces.
                        self._input_state = Client.InputState.Invalid;
                    } else
                        self._input_state = Client.InputState.Invalid_CR;
                } else {
                    mem.copy(u8, self._input_buffer[0..], self._input_buffer[message_begin..self._input_received]);
                    self._input_received -= message_begin;
                }
            },
            Client.InputState.Invalid, Client.InputState.Invalid_CR => {
                self._input_received = 0;
            },
        }
    }
};

const ClientList = LinkedList(Client);

const Channel = struct {
    _parent: *ChannelList.Node,
    _server: *Server,
    _allocator: *Allocator,
    _name: []const u8,

    /// Create a new channel with the given name.
    fn create(name: []const u8, server: *Server, allocator: *Allocator) !*Channel {
        // Make a copy of the name string.
        const name_copy = allocator.alloc(u8, name.len) catch |err| {
            warn("Failed to allocate a channel name string buffer: {}.\n", @errorName(err));
            return err;
        };
        errdefer allocator.free(name_copy);
        mem.copy(u8, name_copy, name);

        // Allocate a channel node.
        const channel_node = allocator.createOne(ChannelList.Node) catch |err| {
            warn("Failed to allocate a channel node: {}.\n", @errorName(err));
            return err;
        };
        channel_node.* = ChannelList.Node.init(Channel{
            ._parent = channel_node,
            ._server = server,
            ._allocator = allocator,
            ._name = name,
        });
        return &channel_node.data;
    }

    fn destroy(self: *Channel) void {
        self._allocator.free(self._name);
        self._allocator.destroy(self);
    }

    /// Get a pointer to the parent LinkedList node. This must be used only by the server.
    fn getNodePointer(self: *const Channel) *ChannelList.Node {
        return self._parent;
    }

    fn getName(self: *const Channel) []const u8 {
        return self._name;
    }

    fn getUserCount(self: *const Channel) usize {
        // TODO Implement.
        return 0;
    }
};

const ChannelList = LinkedList(Channel);

const Server = struct {
    _allocator: *Allocator,

    _sockaddr: net.Address,
    _host: []const u8,
    _port: []const u8,

    _clients: ClientList,
    _channels: ChannelList,

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
            ._allocator = allocator,
            ._sockaddr = net.Address.initIp4(parsed_host, parsed_port),
            ._host = host_copy,
            ._port = port_copy,
            ._clients = ClientList.init(),
            ._channels = ChannelList.init(),
        };
        return server;
    }

    fn destroy(self: *Server) void {
        // Destroy all clients/channels and their LinkedList nodes.
        while (self._clients.pop()) |client_node|
            client_node.data.destroy();
        while (self._channels.pop()) |channel_node|
            channel_node.data.destroy();

        self._allocator.free(self._host);
        self._allocator.free(self._port);
        self._allocator.destroy(self);
    }

    fn getHostName(self: *const Server) []const u8 {
        return self._host;
    }

    fn getChannels(self: *const Server) *const ChannelList {
        return &self._channels;
    }

    fn run(self: *Server) !void {
        // Create the server socket.
        const listenfd = os.posixSocket(os.posix.AF_INET, os.posix.SOCK_STREAM | os.posix.SOCK_CLOEXEC, os.posix.PROTO_tcp) catch |err| {
            warn("Failed to create a server socket: {}.\n", @errorName(err));
            return err;
        };
        defer os.close(listenfd);

        os.posixBind(listenfd, &self._sockaddr.os_addr) catch |err| {
            warn("Failed to bind to address {}:{}: {}.\n", self._host, self._port, @errorName(err));
            return err;
        };

        os.posixListen(listenfd, os.posix.SOMAXCONN) catch |err| {
            warn("Failed to listen on {}:{}: {}.\n", self._host, self._port, @errorName(err));
            return err;
        };

        // Create an epoll instance and register the server socket with it.
        const epfd = os.linuxEpollCreate(os.posix.EPOLL_CLOEXEC) catch |err| {
            warn("Failed to create an epoll instance: {}.\n", @errorName(err));
            return err;
        };
        defer os.close(epfd);

        var listenfd_event = os.posix.epoll_event{
            .events = os.posix.EPOLLIN,
            .data = os.posix.epoll_data{ .ptr = 0 },
        };
        os.linuxEpollCtl(epfd, os.posix.EPOLL_CTL_ADD, listenfd, &listenfd_event) catch |err| {
            warn("Failed to add the server socket (file descriptor {}) to the epoll instance: {}.\n", listenfd, @errorName(err));
            return err;
        };

        // Listen for events.
        info("Listening on {}:{}.\n", self._host, self._port);
        while (true) {
            var events: [1]os.posix.epoll_event = undefined;
            const ep = os.linuxEpollWait(epfd, events[0..], -1);
            if (ep == 0)
                continue;

            // Check for a new connection and accept it.
            if (events[0].data.ptr == 0) {
                var client_sockaddr: os.posix.sockaddr = undefined;
                const clientfd = os.posixAccept(listenfd, &client_sockaddr, os.posix.SOCK_CLOEXEC) catch |err| {
                    warn("Failed to accept a new client connection: {}.\n", @errorName(err));
                    continue;
                };

                // Create a new client. This transfers ownership of the clientfd to the Client
                // instance.
                const client = Client.create(clientfd, client_sockaddr, self, self._allocator) catch continue;

                // Listen for the client.
                var clientfd_event = os.posix.epoll_event{
                    .events = os.posix.EPOLLIN,
                    .data = os.posix.epoll_data{ .ptr = @ptrToInt(client) },
                };
                os.linuxEpollCtl(epfd, os.posix.EPOLL_CTL_ADD, clientfd, &clientfd_event) catch |err| {
                    warn("Failed to add a client socket (file descriptor {}) to the epoll instance: {}.\n", clientfd, @errorName(err));
                    client.destroy();
                    continue;
                };

                self._clients.append(client.getNodePointer());
            } else {
                const client = @intToPtr(*Client, events[0].data.ptr);
                client.processInput() catch {
                    const clientfd = client.getFileDescriptor();
                    os.linuxEpollCtl(epfd, os.posix.EPOLL_CTL_DEL, clientfd, undefined) catch |err| {
                        warn("Failed to remove a client socket (file descriptor {}) from the epoll instance: {}.\n", clientfd, @errorName(err));
                        return err;
                    };

                    self._clients.remove(client.getNodePointer());
                    client.destroy();
                };
            }
        }
    }

    /// Create a new channel with the given name.
    fn createChannel(self: *Server, name: []const u8) !void {
        const channel = try Channel.create(name, self, self._allocator);
        self._channels.append(channel.getNodePointer());
    }

    fn createAutoUser(self: *Server, name: []const u8) void {
        // TODO
    }
};

pub fn main() u8 {
    // Initialize stdout and stderr streams.
    initOutput();

    // Get an allocator.
    const allocator = std.heap.c_allocator;

    // Create the server.
    const server = Server.create(config.address, allocator) catch return 1;
    defer server.destroy();

    // Create pre-defined channels and automatic users.
    for (config.channels) |channel|
        server.createChannel(channel) catch return 1;
    for (config.auto_users) |auto_user|
        server.createAutoUser(auto_user);

    // Run the server.
    server.run() catch return 1;
    return 0;
}
