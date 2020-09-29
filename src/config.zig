// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

/// Listen address for the server.
pub const address = "127.0.0.1:6667";

/// Pre-defined channels.
pub const channels = [_][]const u8{
    "#future",
    "#movies",
    "#music",
    "#nature",
    "#news",
};

/// Configuration for a local bot.
pub const LocalBotConfig = struct {
    nickname: []const u8,
    channels: []const []const u8,
};

/// Artificial local users.
pub const local_bots = [_]LocalBotConfig{
    LocalBotConfig{
        .nickname = "Abigail",
        .channels = &[_][]const u8{ "#future", "#news" },
    },
    LocalBotConfig{
        .nickname = "Albert",
        .channels = &[_][]const u8{ "#movies", "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Alice",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Anna",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Arthur",
        .channels = &[_][]const u8{ "#future", "#news" },
    },
    LocalBotConfig{
        .nickname = "Austin",
        .channels = &[_][]const u8{ "#movies", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Bella",
        .channels = &[_][]const u8{ "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Bobby",
        .channels = &[_][]const u8{ "#movies", "#news" },
    },
    LocalBotConfig{
        .nickname = "Charlie",
        .channels = &[_][]const u8{ "#future", "#music", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Charlotte",
        .channels = &[_][]const u8{ "#movies", "#news" },
    },
    LocalBotConfig{
        .nickname = "Clara",
        .channels = &[_][]const u8{ "#movies", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Daisy",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Daniel",
        .channels = &[_][]const u8{ "#future", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "David",
        .channels = &[_][]const u8{ "#future", "#news" },
    },
    LocalBotConfig{
        .nickname = "Eliza",
        .channels = &[_][]const u8{ "#movies", "#music" },
    },
    LocalBotConfig{
        .nickname = "Ella",
        .channels = &[_][]const u8{ "#future", "#movies", "#music" },
    },
    LocalBotConfig{
        .nickname = "Elliot",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Emma",
        .channels = &[_][]const u8{ "#movies", "#music", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Ethan",
        .channels = &[_][]const u8{ "#future", "#movies", "#music" },
    },
    LocalBotConfig{
        .nickname = "Finn",
        .channels = &[_][]const u8{ "#movies", "#news" },
    },
    LocalBotConfig{
        .nickname = "George",
        .channels = &[_][]const u8{ "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Hannah",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "Harry",
        .channels = &[_][]const u8{ "#future", "#music" },
    },
    LocalBotConfig{
        .nickname = "Henry",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Holly",
        .channels = &[_][]const u8{ "#future", "#movies", "#news" },
    },
    LocalBotConfig{
        .nickname = "Isabella",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Jack",
        .channels = &[_][]const u8{ "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Jackson",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "Jacob",
        .channels = &[_][]const u8{ "#future", "#movies" },
    },
    LocalBotConfig{
        .nickname = "Jake",
        .channels = &[_][]const u8{ "#music", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "James",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Jasmine",
        .channels = &[_][]const u8{ "#music", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Jessica",
        .channels = &[_][]const u8{ "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "John",
        .channels = &[_][]const u8{ "#future", "#music" },
    },
    LocalBotConfig{
        .nickname = "Joseph",
        .channels = &[_][]const u8{ "#movies", "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Lily",
        .channels = &[_][]const u8{ "#future", "#music", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Lucas",
        .channels = &[_][]const u8{ "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Max",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Nathan",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "Olivia",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Phoebe",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Sarah",
        .channels = &[_][]const u8{ "#movies", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Scarlett",
        .channels = &[_][]const u8{ "#movies", "#news" },
    },
    LocalBotConfig{
        .nickname = "Sophie",
        .channels = &[_][]const u8{ "#future", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "Summer",
        .channels = &[_][]const u8{ "#future", "#movies", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "Tyler",
        .channels = &[_][]const u8{ "#music", "#nature" },
    },
    LocalBotConfig{
        .nickname = "Violet",
        .channels = &[_][]const u8{ "#future", "#music", "#news" },
    },
    LocalBotConfig{
        .nickname = "William",
        .channels = &[_][]const u8{ "#future", "#movies", "#nature", "#news" },
    },
    LocalBotConfig{
        .nickname = "Zara",
        .channels = &[_][]const u8{ "#future", "#music" },
    },
    LocalBotConfig{
        .nickname = "Zoe",
        .channels = &[_][]const u8{ "#future", "#music", "#nature", "#news" },
    },
};
