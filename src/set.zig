// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const std = @import("std");
const mem = std.mem;
const rb = std.rb;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub fn PtrCmp(comptime T: type) fn (*const T, *const T) mem.Compare {
    const Ptr = struct {
        fn cmp(lhs: *const T, rhs: *const T) mem.Compare {
            const lval = @ptrToInt(lhs);
            const rval = @ptrToInt(rhs);

            if (lval < rval) {
                return mem.Compare.LessThan;
            } else if (lval == rval) {
                return mem.Compare.Equal;
            } else {
                return mem.Compare.GreaterThan;
            }
        }
    };
    return Ptr.cmp;
}

pub fn StrCmp(comptime T: type, comptime field_name: []const u8) fn (*const T, *const T) mem.Compare {
    const Str = struct {
        fn cmp(lhs: *const T, rhs: *const T) mem.Compare {
            const lval = @field(lhs, field_name);
            const rval = @field(rhs, field_name);

            return mem.compare(u8, lval, rval);
        }
    };
    return Str.cmp;
}

pub fn Set(comptime T: type, compare_fn: fn (*const T, *const T) mem.Compare) type {
    return struct {
        const Self = @This();

        _tree: rb.Tree,
        _allocator: *Allocator,

        const Node = struct {
            _data: *T,
            _rbnode: rb.Node,

            fn _init(d: *T) Node {
                return Node{
                    ._data = d,
                    ._rbnode = undefined,
                };
            }

            fn _create(d: *T, allocator: *Allocator) !*Node {
                const payload_node = try allocator.create(Node);
                payload_node.* = _init(d);
                return payload_node;
            }

            fn _destroy(self: *Node, allocator: *Allocator) void {
                allocator.destroy(self);
            }

            fn _from(rbnode: *rb.Node) *Node {
                return @fieldParentPtr(Node, "_rbnode", rbnode);
            }

            pub fn data(self: *Node) *T {
                return self._data;
            }

            pub fn next(self: *Node) ?*Node {
                return if (self._rbnode.next()) |next_rbnode| _from(next_rbnode) else null;
            }
        };

        pub fn init(allocator: *Allocator) Self {
            var set = Self{
                ._tree = undefined,
                ._allocator = allocator,
            };
            set._tree.init(_compare);
            return set;
        }

        pub fn deinit(self: *Self) void {
            // Free all allocated nodes.
            var maybe_rbnode = self._tree.first();
            while (maybe_rbnode) |rbnode| {
                const node = Node._from(rbnode);
                maybe_rbnode = rbnode.next();
                node._destroy(self._allocator);
            }
        }

        fn _compare(lhs: *rb.Node, rhs: *rb.Node) mem.Compare {
            return compare_fn(Node._from(lhs)._data, Node._from(rhs)._data);
        }

        pub fn first(self: *Self) ?*Node {
            return if (self._tree.first()) |rbnode| Node._from(rbnode) else null;
        }

        pub fn last(self: *Self) ?*Node {
            return if (self._tree.last()) |rbnode| Node._from(rbnode) else null;
        }

        pub fn insert(self: *Self, data: *T) !*Node {
            const node = try Node._create(data, self._allocator);
            const rbnode = self._tree.insert(&node._rbnode);
            assert(rbnode == null);
            return node;
        }

        pub fn lookup(self: *Self, data: *T) ?*Node {
            var node = Node._init(data);
            return if (self._tree.lookup(&node._rbnode)) |rbnode| Node._from(rbnode) else null;
        }

        pub fn remove(self: *Self, node: *Node) ?*Node {
            const next_node: ?*Node = if (node._rbnode.next()) |next_rbnode| Node._from(next_rbnode) else null;
            self._tree.remove(&node._rbnode);
            node._destroy(self._allocator);
            return next_node;
        }
    };
}
