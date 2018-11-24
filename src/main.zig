// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.os.posix;

const Allocator = std.mem.Allocator;
const LinkedList = std.LinkedList;
const assert = std.debug.assert;
const warn = std.debug.warn;

const bind_ip4_addr = "127.0.0.1";
const bind_port: u16 = 6667;

var stdout_file_out_stream: os.File.OutStream = undefined;
var stdout_stream: ?*io.OutStream(os.File.WriteError) = null;

/// Print a message on the standard output.
fn info(comptime fmt: []const u8, args: ...) void {
    if (stdout_stream == null) {
        const stdout_file = io.getStdOut() catch return;
        stdout_file_out_stream = stdout_file.outStream();
        stdout_stream = &stdout_file_out_stream.stream;
    }
    stdout_stream.?.print(fmt, args) catch return;
}

const Lexer = struct {
    message: []const u8,
    pos: usize,

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
        while (self.getCurChar() != 0 and self.getCurChar() != ' ') : (end += 1)
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

    fn acceptParam(self: *Lexer) ![]const u8 {
        const res = self.getParam();
        if (res.len == 0) {
            // TODO Error message.
            warn("Param missing\n");
            return error.NeedsMoreParams;
        }
        return res;
    }
};

const Client = struct {
    parent: ?*ClientList.Node,
    allocator: *Allocator,
    fd: i32,
    addr: net.Address,

    const InputState = enum {
        Normal,
        Normal_CR,
        Invalid,
        Invalid_CR,
    };
    input_state: InputState,
    input_buffer: [512]u8,
    input_received: usize,

    /// Accept a new client connection and allocate client data.
    fn accept(listenfd: i32, allocator: *Allocator) !*Client {
        var sockaddr: posix.sockaddr = undefined;
        const clientfd = os.posixAccept(listenfd, &sockaddr, posix.SOCK_CLOEXEC) catch |err| {
            warn("Failed to accept a new client connection: {}.\n", @errorName(err));
            return err;
        };

        // TODO Output client address.
        info("Accepted a new client connection.\n");

        const addr = net.Address.initPosix(sockaddr);
        const init_node = ClientList.Node.init(Client{
            .parent = null,
            .allocator = allocator,
            .fd = clientfd,
            .addr = addr,
            .input_state = Client.InputState.Normal,
            .input_buffer = undefined,
            .input_received = 0,
        });
        const dyn_node = allocator.create(init_node) catch |err| {
            // TODO Output client address.
            warn("Failed to allocate a client node: {}.\n", @errorName(err));
            return err;
        };
        dyn_node.data.parent = dyn_node;
        return &dyn_node.data;
    }

    /// Close connection to a client and destroy the client data.
    fn destroy(client: *Client) void {
        os.close(client.fd);
        // TODO Output client address.
        info("Closed a client connection.\n");
        client.allocator.destroy(client.parent);
    }

    /// Process the USER command.
    /// Parameters: <username> <hostname> <servername> <realname>
    fn _processCommand_USER(client: *Client, lexer: *Lexer) !void {
        const username = try lexer.acceptParam();
        const hostname = try lexer.acceptParam();
        const servername = try lexer.acceptParam();
        const realname = try lexer.acceptParam();
    }

    /// Process a single message from a client.
    fn _processMessage(client: *Client, message: []const u8) void {
        info("< {}\n", message);

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
            res = client._processCommand_USER(&lexer);
        } else
            warn("Unrecognized command: {}\n", command);

        if (res) {} else |err| {
            // TODO
        }
    }

    fn processInput(client: *Client) !void {
        assert(client.input_received < client.input_buffer.len);
        var pos = client.input_received;
        const read = try os.posixRead(client.fd, client.input_buffer[pos..]);
        if (read == 0) {
            // TODO read = 0 -> EOF. Report any unhandled data.
        }
        client.input_received += read;

        var message_begin: usize = 0;
        while (pos < client.input_received) : (pos += 1) {
            const char = client.input_buffer[pos];
            switch (client.input_state) {
                Client.InputState.Normal => {
                    if (char == '\r')
                        client.input_state = Client.InputState.Normal_CR;
                    // TODO Check for invalid chars.
                },
                Client.InputState.Normal_CR => {
                    if (char == '\n') {
                        client._processMessage(client.input_buffer[message_begin .. pos - 1]);
                        client.input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else {
                        // TODO Print an error message.
                        client.input_state = Client.InputState.Invalid;
                    }
                },
                Client.InputState.Invalid => {
                    if (char == '\r')
                        client.input_state = Client.InputState.Invalid_CR;
                },
                Client.InputState.Invalid_CR => {
                    if (char == '\n') {
                        client.input_state = Client.InputState.Normal;
                        message_begin = pos + 1;
                    } else
                        client.input_state = Client.InputState.Invalid;
                },
            }
        }

        switch (client.input_state) {
            Client.InputState.Normal, Client.InputState.Normal_CR => {
                if (message_begin >= client.input_received) {
                    assert(message_begin == client.input_received);
                    client.input_received = 0;
                } else if (message_begin == 0) {
                    // TODO Message overflow.
                    if (client.input_state == Client.InputState.Normal) { // TODO Remove braces.
                        client.input_state = Client.InputState.Invalid;
                    } else
                        client.input_state = Client.InputState.Invalid_CR;
                } else {
                    mem.copy(u8, client.input_buffer[0..], client.input_buffer[message_begin..client.input_received]);
                    client.input_received -= message_begin;
                }
            },
            Client.InputState.Invalid, Client.InputState.Invalid_CR => {
                client.input_received = 0;
            },
        }
    }
};

const ClientList = LinkedList(Client);

pub fn main() u8 {
    // Create the server socket.
    const listenfd = os.posixSocket(posix.AF_INET, posix.SOCK_STREAM | posix.SOCK_CLOEXEC, posix.PROTO_tcp) catch |err| {
        warn("Failed to create a server socket: {}.\n", @errorName(err));
        return 1;
    };
    defer os.close(listenfd);

    const parsed_addr = net.parseIp4(bind_ip4_addr) catch unreachable;
    const addr = net.Address.initIp4(parsed_addr, bind_port);
    os.posixBind(listenfd, &addr.os_addr) catch |err| {
        warn("Failed to bind to address {}:{}: {}.\n", bind_ip4_addr, bind_port, @errorName(err));
        return 1;
    };

    os.posixListen(listenfd, posix.SOMAXCONN) catch |err| {
        warn("Failed to listen on {}:{}: {}.\n", bind_ip4_addr, bind_port, @errorName(err));
        return 1;
    };

    // Create an epoll instance and register the server socket with it.
    const epfd = os.linuxEpollCreate(posix.EPOLL_CLOEXEC) catch |err| {
        warn("Failed to create an epoll instance: {}.\n", @errorName(err));
        return 1;
    };
    defer os.close(epfd);

    var listenfd_event = posix.epoll_event{
        .events = posix.EPOLLIN,
        .data = posix.epoll_data{ .ptr = 0 },
    };
    os.linuxEpollCtl(epfd, posix.EPOLL_CTL_ADD, listenfd, &listenfd_event) catch |err| {
        warn("Failed to add the server socket to the epoll instance: {}.\n", @errorName(err));
        return 1;
    };

    // Create a list of clients.
    var allocator = std.heap.c_allocator;
    var clients = ClientList.init();
    defer {
        while (clients.pop()) |client_node| {
            // Destroy the client and its LinkedList node.
            client_node.data.destroy();
        }
    }

    // Listen for events.
    info("Listening on {}:{}.\n", bind_ip4_addr, bind_port);
    while (true) {
        var events: [1]posix.epoll_event = undefined;
        const ep = os.linuxEpollWait(epfd, events[0..], -1);
        if (ep == 0)
            continue;

        // Check for a new connection and accept it.
        if (events[0].data.ptr == 0) {
            const client = Client.accept(listenfd, allocator) catch continue;

            // Listen for the client.
            var clientfd = client.fd;
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

            clients.append(client.parent.?);
        } else {
            const client = @intToPtr(*Client, events[0].data.ptr);
            // TODO
            client.processInput() catch return 1;
        }
    }

    return 0;
}
