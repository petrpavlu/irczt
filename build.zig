// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("irczt", "src/main.zig");
    exe.setBuildMode(mode);
    exe.linkSystemLibrary("c");

    const run_step = b.step("run", "Run the app");
    const run_cmd = exe.run();
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run all the tests");
    const test_test = b.addTest("src/main.zig");
    test_step.dependOn(&test_test.step);

    b.default_step.dependOn(&exe.step);
    b.installArtifact(exe);
}
