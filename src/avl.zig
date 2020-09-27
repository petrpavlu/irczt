// Copyright (C) 2019 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const builtin = @import("builtin");
const std = @import("std");
const mem = std.mem;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expect = std.testing.expect;

pub fn Map(comptime Key: type, comptime Value: type, lessThan: fn (Key, Key) bool) type {
    return struct {
        const Self = @This();

        _allocator: *Allocator,
        _root: ?*_Node,
        _size: usize,

        const KeyValue = struct {
            _key: Key,
            _value: Value,

            pub fn key(self: KeyValue) Key {
                return self._key;
            }

            pub fn value(self: KeyValue) Value {
                return self._value;
            }
        };

        const _Node = struct {
            _kv: KeyValue,
            _parent: ?*_Node,
            _left: ?*_Node,
            _right: ?*_Node,
            _balance: i2,
        };

        const Iterator = struct {
            _node: ?*_Node,

            /// Return the current value and increment the iterator.
            pub fn next(self: *Iterator) ?*KeyValue {
                if (self._node == null) {
                    return null;
                }

                const res = &self._node.?._kv;
                if (self._node.?._right) |right_node| {
                    var successor_node = right_node;
                    while (successor_node._left) |left_node| successor_node = left_node;
                    self._node = successor_node;
                    return res;
                }

                var child_node = self._node.?;
                while (true) {
                    if (child_node._parent == null) {
                        self._node = null;
                        return res;
                    }

                    const parent_node = child_node._parent.?;
                    if (parent_node._left == child_node) {
                        self._node = parent_node;
                        return res;
                    }
                    child_node = parent_node;
                }
            }

            /// Return whether the iterator is valid, i.e. it currently points to a valid node.
            pub fn valid(self: Iterator) bool {
                return self._node != null;
            }

            pub fn key(self: Iterator) Key {
                assert(self._node != null);
                return self._node.?._kv._key;
            }

            pub fn value(self: Iterator) Value {
                assert(self._node != null);
                return self._node.?._kv._value;
            }
        };

        pub fn init(allocator: *Allocator) Self {
            return Self{
                ._allocator = allocator,
                ._root = null,
                ._size = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self._root == null) {
                return;
            }

            // Deallocate all nodes.
            var node = self._root.?;
            while (true) {
                // Perform post-order traversal.
                if (node._left) |left_node| {
                    node = left_node;
                    continue;
                }
                if (node._right) |right_node| {
                    node = right_node;
                    continue;
                }

                // Disconnect the node from the parent.
                const maybe_parent_node = node._parent;
                if (maybe_parent_node) |parent_node| {
                    if (parent_node._left == node) {
                        parent_node._left = null;
                    } else {
                        parent_node._right = null;
                    }
                }

                // Destroy the node.
                self._allocator.destroy(node);

                // Continue the traversal.
                if (maybe_parent_node) |parent_node| {
                    node = parent_node;
                } else {
                    break;
                }
            }
        }

        pub fn insert(self: *Self, key: Key, value: Value) !Iterator {
            // Allocate a new node.
            const node = try self._allocator.create(_Node);
            node.* = _Node{
                ._kv = KeyValue{ ._key = key, ._value = value },
                ._parent = null,
                ._left = null,
                ._right = null,
                ._balance = 0,
            };

            // Find the insertion point.
            if (self._root == null) {
                self._root = node;
            } else {
                var insert_node = self._root.?;
                while (true) {
                    if (lessThan(key, insert_node._kv._key)) {
                        if (insert_node._left) |left_node| {
                            insert_node = left_node;
                            continue;
                        }
                        // Insert the node and rebalance the tree.
                        insert_node._left = node;
                        node._parent = insert_node;
                        self._insertBalance(insert_node, -1);
                        break;
                    } else {
                        assert(lessThan(insert_node._kv._key, key));

                        if (insert_node._right) |right_node| {
                            insert_node = right_node;
                            continue;
                        }
                        insert_node._right = node;
                        node._parent = insert_node;
                        self._insertBalance(insert_node, 1);
                        break;
                    }
                }
            }
            self._size += 1;
            return Iterator{ ._node = node };
        }

        pub fn remove(self: *Self, iter: Iterator) void {
            const node = iter._node.?;
            const maybe_left_node = node._left;
            const maybe_right_node = node._right;
            const maybe_parent_node = node._parent;

            if (maybe_left_node) |left_node| {
                if (maybe_right_node) |right_node| {
                    // Find the successor and use it to replace the deleted node.
                    var successor_node = right_node;
                    while (successor_node._left) |successor_left_node| {
                        successor_node = successor_left_node;
                    }

                    const parent_node = node._parent;
                    const successor_parent_node = successor_node._parent.?;
                    const maybe_successor_right_node = successor_node._right;

                    if (successor_parent_node != node) {
                        assert(successor_parent_node._left == successor_node);
                        assert(successor_node._left == null);

                        successor_parent_node._left = maybe_successor_right_node;

                        if (maybe_successor_right_node) |successor_right_node| {
                            successor_right_node._parent = successor_parent_node;
                        }
                    }

                    successor_node._parent = parent_node;
                    successor_node._left = left_node;
                    left_node._parent = successor_node;
                    if (successor_parent_node != node) {
                        successor_node._right = right_node;
                        right_node._parent = successor_node;
                    }
                    successor_node._balance = node._balance;

                    if (node == self._root) {
                        self._root = successor_node;
                    } else if (maybe_parent_node.?._right == node) {
                        maybe_parent_node.?._right = successor_node;
                    } else {
                        maybe_parent_node.?._left = successor_node;
                    }

                    // Rebalance the tree.
                    if (successor_parent_node != node) {
                        self._removeBalance(successor_parent_node, 1);
                    } else {
                        self._removeBalance(successor_node, -1);
                    }
                } else {
                    // Use the left child to replace the deleted node.
                    left_node._parent = maybe_parent_node;

                    if (node == self._root) {
                        self._root = left_node;
                    } else if (maybe_parent_node.?._right == node) {
                        maybe_parent_node.?._right = left_node;
                    } else {
                        maybe_parent_node.?._left = left_node;
                    }

                    self._removeBalance(left_node, 0);
                }
            } else {
                if (maybe_right_node) |right_node| {
                    // Use the right child to replace the deleted node.
                    right_node._parent = maybe_parent_node;

                    if (node == self._root) {
                        self._root = right_node;
                    } else if (maybe_parent_node.?._right == node) {
                        maybe_parent_node.?._right = right_node;
                    } else {
                        maybe_parent_node.?._left = right_node;
                    }

                    self._removeBalance(right_node, 0);
                } else {
                    // Remove the leaf node.
                    if (node == self._root) {
                        self._root = null;
                    } else if (maybe_parent_node.?._right == node) {
                        maybe_parent_node.?._right = null;
                        self._removeBalance(maybe_parent_node.?, -1);
                    } else {
                        maybe_parent_node.?._left = null;
                        self._removeBalance(maybe_parent_node.?, 1);
                    }
                }
            }

            self._size -= 1;
            self._allocator.destroy(node);
        }

        pub fn find(self: *const Self, key: Key) Iterator {
            var maybe_node = self._root;
            while (maybe_node) |node| {
                if (lessThan(key, node._kv._key)) {
                    maybe_node = node._left;
                } else if (lessThan(node._kv._key, key)) {
                    maybe_node = node._right;
                } else {
                    return Iterator{ ._node = node };
                }
            }
            return Iterator{ ._node = null };
        }

        pub fn iterator(self: *const Self) Iterator {
            if (self._root == null) {
                return Iterator{ ._node = null };
            }

            var node = self._root.?;
            while (node._left) |left_node| {
                node = left_node;
            }
            return Iterator{ ._node = node };
        }

        pub fn count(self: *const Self) usize {
            return self._size;
        }

        fn _insertBalance(self: *Self, insert_node: *_Node, balance: i2) void {
            var maybe_node: ?*_Node = insert_node;
            var change_balance = balance;
            while (maybe_node) |node| {
                const new_balance = @as(i3, node._balance) + change_balance;
                if (new_balance == 0) {
                    node._balance = 0;
                    return;
                }
                if (new_balance == -2) {
                    if (node._left.?._balance == -1) {
                        _ = self._rotateRight(node);
                    } else {
                        _ = self._rotateLeftRight(node);
                    }
                    return;
                }
                if (new_balance == 2) {
                    if (node._right.?._balance == 1) {
                        _ = self._rotateLeft(node);
                    } else {
                        _ = self._rotateRightLeft(node);
                    }
                    return;
                }

                node._balance = @intCast(i2, new_balance);
                const maybe_parent_node = node._parent;
                if (maybe_parent_node) |parent_node| {
                    change_balance = if (parent_node._left == node) -1 else 1;
                }
                maybe_node = maybe_parent_node;
            }
        }

        fn _removeBalance(self: *Self, remove_node: *_Node, balance: i2) void {
            var maybe_node: ?*_Node = remove_node;
            var change_balance = balance;
            while (maybe_node) |node| {
                const new_balance = @as(i3, node._balance) + change_balance;
                var next_node: *_Node = undefined;
                if (new_balance == 0) {
                    node._balance = 0;
                    next_node = node;
                } else if (new_balance == -2) {
                    if (node._left.?._balance <= 0) {
                        next_node = self._rotateRight(node);
                        if (next_node._balance == 1) {
                            return;
                        }
                    } else {
                        next_node = self._rotateLeftRight(node);
                    }
                } else if (new_balance == 2) {
                    if (node._right.?._balance >= 0) {
                        next_node = self._rotateLeft(node);
                        if (next_node._balance == -1) {
                            return;
                        }
                    } else {
                        next_node = self._rotateRightLeft(node);
                    }
                } else {
                    node._balance = @intCast(i2, new_balance);
                    return;
                }

                const maybe_parent_node = next_node._parent;
                if (maybe_parent_node) |parent_node| {
                    change_balance = if (parent_node._left == next_node) 1 else -1;
                }
                maybe_node = maybe_parent_node;
            }
        }

        fn _rotateLeft(self: *Self, node: *_Node) *_Node {
            const right_node = node._right.?;
            const maybe_right_left_node = right_node._left;
            const maybe_parent_node = node._parent;

            right_node._parent = maybe_parent_node;
            right_node._left = node;
            node._right = maybe_right_left_node;
            node._parent = right_node;
            if (maybe_right_left_node) |right_left_node| {
                right_left_node._parent = node;
            }

            if (node == self._root) {
                self._root = right_node;
            } else if (maybe_parent_node.?._right == node) {
                maybe_parent_node.?._right = right_node;
            } else {
                maybe_parent_node.?._left = right_node;
            }

            if (right_node._balance == 1) {
                node._balance = 0;
                right_node._balance = 0;
            } else {
                assert(right_node._balance == 0);
                node._balance = 1;
                right_node._balance = -1;
            }

            return right_node;
        }

        fn _rotateRight(self: *Self, node: *_Node) *_Node {
            const left_node = node._left.?;
            const maybe_left_right_node = left_node._right;
            const maybe_parent_node = node._parent;

            left_node._parent = maybe_parent_node;
            left_node._right = node;
            node._parent = left_node;
            node._left = maybe_left_right_node;
            if (maybe_left_right_node) |left_right_node| {
                left_right_node._parent = node;
            }

            if (node == self._root) {
                self._root = left_node;
            } else if (maybe_parent_node.?._left == node) {
                maybe_parent_node.?._left = left_node;
            } else {
                maybe_parent_node.?._right = left_node;
            }

            if (left_node._balance == -1) {
                node._balance = 0;
                left_node._balance = 0;
            } else {
                assert(left_node._balance == 0);
                node._balance = -1;
                left_node._balance = 1;
            }

            return left_node;
        }

        fn _rotateLeftRight(self: *Self, node: *_Node) *_Node {
            const left_node = node._left.?;
            const left_right_node = left_node._right.?;
            const maybe_parent_node = node._parent;
            const maybe_left_right_right_node = left_right_node._right;
            const maybe_left_right_left_node = left_right_node._left;

            left_right_node._parent = maybe_parent_node;
            left_right_node._left = left_node;
            left_right_node._right = node;
            left_node._parent = left_right_node;
            left_node._right = maybe_left_right_left_node;
            node._parent = left_right_node;
            node._left = maybe_left_right_right_node;

            if (maybe_left_right_right_node) |left_right_right_node| {
                left_right_right_node._parent = node;
            }
            if (maybe_left_right_left_node) |left_right_left_node| {
                left_right_left_node._parent = left_node;
            }

            if (node == self._root) {
                self._root = left_right_node;
            } else if (maybe_parent_node.?._left == node) {
                maybe_parent_node.?._left = left_right_node;
            } else {
                maybe_parent_node.?._right = left_right_node;
            }

            if (left_right_node._balance == 1) {
                node._balance = 0;
                left_node._balance = -1;
            } else if (left_right_node._balance == 0) {
                node._balance = 0;
                left_node._balance = 0;
            } else {
                assert(left_right_node._balance == -1);
                node._balance = 1;
                left_node._balance = 0;
            }
            left_right_node._balance = 0;

            return left_right_node;
        }

        fn _rotateRightLeft(self: *Self, node: *_Node) *_Node {
            const right_node = node._right.?;
            const right_left_node = right_node._left.?;
            const maybe_parent_node = node._parent;
            const maybe_right_left_left_node = right_left_node._left;
            const maybe_right_left_right_node = right_left_node._right;

            right_left_node._parent = maybe_parent_node;
            right_left_node._right = right_node;
            right_left_node._left = node;
            right_node._parent = right_left_node;
            right_node._left = maybe_right_left_right_node;
            node._parent = right_left_node;
            node._right = maybe_right_left_left_node;

            if (maybe_right_left_left_node) |right_left_left_node| {
                right_left_left_node._parent = node;
            }
            if (maybe_right_left_right_node) |right_left_right_node| {
                right_left_right_node._parent = right_node;
            }

            if (node == self._root) {
                self._root = right_left_node;
            } else if (maybe_parent_node.?._right == node) {
                maybe_parent_node.?._right = right_left_node;
            } else {
                maybe_parent_node.?._left = right_left_node;
            }

            if (right_left_node._balance == -1) {
                node._balance = 0;
                right_node._balance = 1;
            } else if (right_left_node._balance == 0) {
                node._balance = 0;
                right_node._balance = 0;
            } else {
                assert(right_left_node._balance == 1);
                node._balance = -1;
                right_node._balance = 0;
            }
            right_left_node._balance = 0;

            return right_left_node;
        }
    };
}

pub fn getLessThanFn(comptime T: type) fn (T, T) bool {
    return struct {
        fn lessThan(lhs: T, rhs: T) bool {
            switch (@typeInfo(T)) {
                builtin.TypeId.Pointer => |ptr_info| switch (ptr_info.size) {
                    builtin.TypeInfo.Pointer.Size.One => {
                        return @ptrToInt(lhs) < @ptrToInt(rhs);
                    },
                    builtin.TypeInfo.Pointer.Size.Slice => {
                        return mem.lessThan(ptr_info.child, lhs, rhs);
                    },
                    else => {},
                },
                else => {},
            }
            return lhs < rhs;
        }
    }.lessThan;
}

const IntToStrMap = Map(i32, []const u8, getLessThanFn(i32));
const IntSet = Map(i32, void, getLessThanFn(i32));

test "insert - left rotation" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(node0._kv._key == 0);
    expect(mem.eql(u8, node0._kv._value, "0"));
    expect(ismap._root == node0);
    expect(ismap._size == 1);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(node1._kv._key == 1);
    expect(mem.eql(u8, node1._kv._value, "1"));
    expect(ismap._root == node0);
    expect(ismap._size == 2);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == node1);
    expect(node0._balance == 1);
    expect(node1._parent == node0);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(node2._kv._key == 2);
    expect(mem.eql(u8, node2._kv._value, "2"));
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "insert - right rotation" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(node2._kv._key == 2);
    expect(mem.eql(u8, node2._kv._value, "2"));
    expect(ismap._root == node2);
    expect(ismap._size == 1);
    expect(node2._parent == null);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(node1._kv._key == 1);
    expect(mem.eql(u8, node1._kv._value, "1"));
    expect(ismap._root == node2);
    expect(ismap._size == 2);
    expect(node1._parent == node2);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == null);
    expect(node2._balance == -1);

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(node0._kv._key == 0);
    expect(mem.eql(u8, node0._kv._value, "0"));
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "insert - left right rotation" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(node2._kv._key == 2);
    expect(mem.eql(u8, node2._kv._value, "2"));
    expect(ismap._root == node2);
    expect(ismap._size == 1);
    expect(node2._parent == null);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(node0._kv._key == 0);
    expect(mem.eql(u8, node0._kv._value, "0"));
    expect(ismap._root == node2);
    expect(ismap._size == 2);
    expect(node0._parent == node2);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node0);
    expect(node2._right == null);
    expect(node2._balance == -1);

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(node1._kv._key == 1);
    expect(mem.eql(u8, node1._kv._value, "1"));
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "insert - right left rotation" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(node0._kv._key == 0);
    expect(mem.eql(u8, node0._kv._value, "0"));
    expect(ismap._root == node0);
    expect(ismap._size == 1);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(node2._kv._key == 2);
    expect(mem.eql(u8, node2._kv._value, "2"));
    expect(ismap._root == node0);
    expect(ismap._size == 2);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == node2);
    expect(node0._balance == 1);
    expect(node2._parent == node0);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(node1._kv._key == 1);
    expect(mem.eql(u8, node1._kv._value, "1"));
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "remove - 2 children - immediate successor" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 1);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == node3);
    expect(node2._balance == 1);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);

    ismap.remove(iter1);
    expect(ismap._root == node2);
    expect(ismap._size == 3);
    expect(node0._parent == node2);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node0);
    expect(node2._right == node3);
    expect(node2._balance == 0);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);
}

test "remove - 2 children - non-immediate successor" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node3);
    expect(node1._balance == 1);
    expect(node2._parent == node3);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == node1);
    expect(node3._left == node2);
    expect(node3._right == null);
    expect(node3._balance == -1);

    ismap.remove(iter1);
    expect(ismap._root == node2);
    expect(ismap._size == 3);
    expect(node0._parent == node2);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node0);
    expect(node2._right == node3);
    expect(node2._balance == 0);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);
}

test "remove - 1 child - left" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 2);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == null);
    expect(node1._balance == -1);

    ismap.remove(iter1);
    expect(ismap._root == node0);
    expect(ismap._size == 1);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
}

test "remove - 1 child - right" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(ismap._root == node0);
    expect(ismap._size == 2);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == node1);
    expect(node0._balance == 1);
    expect(node1._parent == node0);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == node1);
    expect(ismap._size == 1);
    expect(node1._parent == null);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
}

test "remove - 0 children" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(ismap._root == node0);
    expect(ismap._size == 1);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == null);
    expect(ismap._size == 0);
}

test "remove - rebalance - new=-2, left=-1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(ismap._root == node2);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == node2);
    expect(node1._left == node0);
    expect(node1._right == null);
    expect(node1._balance == -1);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == node3);
    expect(node2._balance == -1);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);

    ismap.remove(iter3);
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "remove - rebalance - new=-2, left=0" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter4 = try ismap.insert(4, "4");
    const node4 = iter4._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(ismap._root == node3);
    expect(ismap._size == 5);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == node3);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == null);
    expect(node3._left == node1);
    expect(node3._right == node4);
    expect(node3._balance == -1);
    expect(node4._parent == node3);
    expect(node4._left == null);
    expect(node4._right == null);
    expect(node4._balance == 0);

    ismap.remove(iter4);
    expect(ismap._root == node1);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node3);
    expect(node1._balance == 1);
    expect(node2._parent == node3);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == node1);
    expect(node3._left == node2);
    expect(node3._right == null);
    expect(node3._balance == -1);
}

test "remove - rebalance - new=-2, left=1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    expect(ismap._root == node2);
    expect(ismap._size == 4);
    expect(node0._parent == node2);
    expect(node0._left == null);
    expect(node0._right == node1);
    expect(node0._balance == 1);
    expect(node1._parent == node0);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node0);
    expect(node2._right == node3);
    expect(node2._balance == -1);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);

    ismap.remove(iter3);
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "remove - rebalance - new=2, right=1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 1);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == node3);
    expect(node2._balance == 1);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == node2);
    expect(ismap._size == 3);
    expect(node1._parent == node2);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == node3);
    expect(node2._balance == 0);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);
}

test "remove - rebalance - new=2, right=0" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter4 = try ismap.insert(4, "4");
    const node4 = iter4._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 5);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node3);
    expect(node1._balance == 1);
    expect(node2._parent == node3);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == node1);
    expect(node3._left == node2);
    expect(node3._right == node4);
    expect(node3._balance == 0);
    expect(node4._parent == node3);
    expect(node4._left == null);
    expect(node4._right == null);
    expect(node4._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == node3);
    expect(ismap._size == 4);
    expect(node1._parent == node3);
    expect(node1._left == null);
    expect(node1._right == node2);
    expect(node1._balance == 1);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == null);
    expect(node3._left == node1);
    expect(node3._right == node4);
    expect(node3._balance == -1);
    expect(node4._parent == node3);
    expect(node4._left == null);
    expect(node4._right == null);
    expect(node4._balance == 0);
}

test "remove - rebalance - new=2, right=-1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node3);
    expect(node1._balance == 1);
    expect(node2._parent == node3);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
    expect(node3._parent == node1);
    expect(node3._left == node2);
    expect(node3._right == null);
    expect(node3._balance == -1);

    ismap.remove(iter0);
    expect(ismap._root == node2);
    expect(ismap._size == 3);
    expect(node1._parent == node2);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == node3);
    expect(node2._balance == 0);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);
}

test "remove - rebalance - new=-1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);

    ismap.remove(iter2);
    expect(ismap._root == node1);
    expect(ismap._size == 2);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == null);
    expect(node1._balance == -1);
}

test "remove - rebalance - new=1" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    expect(ismap._root == node1);
    expect(ismap._size == 3);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == null);
    expect(node1._left == node0);
    expect(node1._right == node2);
    expect(node1._balance == 0);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == node1);
    expect(ismap._size == 2);
    expect(node1._parent == null);
    expect(node1._left == null);
    expect(node1._right == node2);
    expect(node1._balance == 1);
    expect(node2._parent == node1);
    expect(node2._left == null);
    expect(node2._right == null);
    expect(node2._balance == 0);
}

test "remove - rebalance - new=0" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    const iter1 = try ismap.insert(1, "1");
    const node1 = iter1._node.?;
    const iter3 = try ismap.insert(3, "3");
    const node3 = iter3._node.?;
    const iter0 = try ismap.insert(0, "0");
    const node0 = iter0._node.?;
    expect(ismap._root == node2);
    expect(ismap._size == 4);
    expect(node0._parent == node1);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
    expect(node1._parent == node2);
    expect(node1._left == node0);
    expect(node1._right == null);
    expect(node1._balance == -1);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == node3);
    expect(node2._balance == -1);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);

    ismap.remove(iter0);
    expect(ismap._root == node2);
    expect(ismap._size == 3);
    expect(node1._parent == node2);
    expect(node1._left == null);
    expect(node1._right == null);
    expect(node1._balance == 0);
    expect(node2._parent == null);
    expect(node2._left == node1);
    expect(node2._right == node3);
    expect(node2._balance == 0);
    expect(node3._parent == node2);
    expect(node3._left == null);
    expect(node3._right == null);
    expect(node3._balance == 0);
}

test "iterate" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    var iter: IntToStrMap.Iterator = undefined;
    var maybe_kv: ?*IntToStrMap.KeyValue = null;

    iter = ismap.iterator();
    expect(!iter.valid());
    maybe_kv = iter.next();
    expect(maybe_kv == null);
    expect(!iter.valid());

    _ = try ismap.insert(3, "3");
    iter = ismap.iterator();
    expect(iter.valid());
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 3);
    expect(!iter.valid());
    maybe_kv = iter.next();
    expect(maybe_kv == null);
    expect(!iter.valid());

    _ = try ismap.insert(5, "5");
    iter = ismap.iterator();
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 3);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 5);
    maybe_kv = iter.next();
    expect(maybe_kv == null);

    _ = try ismap.insert(1, "1");
    iter = ismap.iterator();
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 1);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 3);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 5);
    maybe_kv = iter.next();
    expect(maybe_kv == null);

    _ = try ismap.insert(2, "2");
    iter = ismap.iterator();
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 1);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 2);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 3);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 5);
    maybe_kv = iter.next();
    expect(maybe_kv == null);

    _ = try ismap.insert(4, "4");
    iter = ismap.iterator();
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 1);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 2);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 3);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 4);
    maybe_kv = iter.next();
    expect(maybe_kv != null);
    expect(maybe_kv.?.key() == 5);
    maybe_kv = iter.next();
    expect(maybe_kv == null);
}

test "find" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var ismap = IntToStrMap.init(&arena_allocator.allocator);
    defer ismap.deinit();

    _ = try ismap.insert(3, "3");
    _ = try ismap.insert(5, "5");
    _ = try ismap.insert(1, "1");
    const iter2 = try ismap.insert(2, "2");
    const node2 = iter2._node.?;
    _ = try ismap.insert(4, "4");

    const iter = ismap.find(2);
    expect(iter._node == node2);
    expect(iter.valid());
    expect(iter.key() == 2);
    expect(mem.eql(u8, iter.value(), "2"));
}

test "set" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();

    var iset = IntSet.init(&arena_allocator.allocator);
    defer iset.deinit();

    const iter0 = try iset.insert(0, {});
    const node0 = iter0._node.?;
    expect(node0._kv._key == 0);
    expect(iset._root == node0);
    expect(iset._size == 1);
    expect(node0._parent == null);
    expect(node0._left == null);
    expect(node0._right == null);
    expect(node0._balance == 0);
}
