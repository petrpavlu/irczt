// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const std = @import("std");
const mem = std.mem;
const rb = std.rb;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub fn Set(comptime T: type) type {
    return struct {
        const Self = @This();

        _tree: rb.Tree,
        _allocator: *Allocator,

        const Node = struct {
            data: *T,
            _rbnode: rb.Node,

            fn _init(data: *T) Node {
                return Node{
                    .data = data,
                    ._rbnode = undefined,
                };
            }

            fn _create(data: *T, allocator: *Allocator) !*Node {
                const payload_node = try allocator.createOne(Node);
                payload_node.* = _init(data);
                return payload_node;
            }

            fn _destroy(self: *Node, allocator: *Allocator) void {
                allocator.destroy(self);
            }

            fn _from(rbnode: *rb.Node) *Node {
                return @fieldParentPtr(Node, "_rbnode", rbnode);
            }

            fn _compare(lhs: *rb.Node, rhs: *rb.Node) mem.Compare {
                var lval = @ptrToInt(_from(lhs).data);
                var rval = @ptrToInt(_from(rhs).data);

                if (lval < rval) {
                    return mem.Compare.LessThan;
                } else if (lval == rval) {
                    return mem.Compare.Equal;
                } else {
                    return mem.Compare.GreaterThan;
                }
            }

            fn next(self: *Node) ?*Node {
                return if (self._rbnode.next()) |next_rbnode| _from(next_rbnode) else null;
            }
        };

        pub fn init(allocator: *Allocator) Self {
            var set = Self{
                ._tree = undefined,
                ._allocator = allocator,
            };
            set._tree.init(Node._compare);
            return set;
        }

        pub fn deinit(set: *Self) void {
            // Free all allocated nodes.
            var rbnode = self._tree.first();
            while (rbnode != null) {
                const node = Node._from(rbnode);
                rbnode = rbnode.next();
                node._destroy(self._allocator);
            }
        }

        pub fn first(set: *Self) ?*Node {
            return if (set._tree.first()) |rbnode| Node._from(rbnode) else null;
        }

        pub fn last(set: *Self) ?*Node {
            return if (set._tree.last()) |rbnode| Node._from(rbnode) else null;
        }

        pub fn insert(set: *Self, data: *T) !*Node {
            const node = try Node._create(data, set._allocator);
            const rbnode = set._tree.insert(&node._rbnode);
            assert(rbnode == null);
            return node;
        }

        pub fn lookup(set: *Self, data: *T) ?*Node {
            var node = Node._init(data);
            return if (set._tree.lookup(&node._rbnode)) |rbnode| Node._from(rbnode) else null;
        }

        pub fn remove(set: *Self, node: *Node) ?*Node {
            const next_node: ?*Node = if (node._rbnode.next()) |next_rbnode| Node._from(next_rbnode) else null;
            set._tree.remove(&node._rbnode);
            node._destroy(set._allocator);
            return next_node;
        }
    };
}
