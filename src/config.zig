// Copyright (C) 2018 Petr Pavlu <setup@dagobah.cz>
// SPDX-License-Identifier: MIT

/// Listen address for the server.
pub const address = "127.0.0.1:6667";

/// Word bank for use by local bots.
pub const word_bank = [_][]const u8{
    "lorem",     "ipsum",     "dolor",    "sit",       "amet",    "consectetur",  "adipiscing",
    "elit",      "sed",       "do",       "eiusmod",   "tempor",  "incididunt",   "ut",
    "labore",    "et",        "dolore",   "magna",     "aliqua",  "ut",           "enim",
    "ad",        "minim",     "veniam",   "quis",      "nostrud", "exercitation", "ullamco",
    "laboris",   "nisi",      "ut",       "aliquip",   "ex",      "ea",           "commodo",
    "consequat", "duis",      "aute",     "irure",     "dolor",   "in",           "reprehenderit",
    "in",        "voluptate", "velit",    "esse",      "cillum",  "dolore",       "eu",
    "fugiat",    "nulla",     "pariatur", "excepteur", "sint",    "occaecat",     "cupidatat",
    "non",       "proident",  "sunt",     "in",        "culpa",   "qui",          "officia",
    "deserunt",  "mollit",    "anim",     "id",        "est",     "laborum",
};

/// Pre-defined channels.
pub const channels = [_][]const u8{
    "#future",
    "#movies",
    "#music",
    "#nature",
    "#news",
};

/// Artificial local users.
pub const local_bots = [_][]const u8{
    "Abigail",
    "Albert",
    "Alice",
    "Anna",
    "Arthur",
    "Austin",
    "Bella",
    "Bobby",
    "Charlie",
    "Charlotte",
    "Clara",
    "Daisy",
    "Daniel",
    "David",
    "Eliza",
    "Ella",
    "Elliot",
    "Emma",
    "Ethan",
    "Finn",
    "George",
    "Hannah",
    "Harry",
    "Henry",
    "Holly",
    "Isabella",
    "Jack",
    "Jackson",
    "Jacob",
    "Jake",
    "James",
    "Jasmine",
    "Jessica",
    "John",
    "Joseph",
    "Lily",
    "Lucas",
    "Max",
    "Nathan",
    "Olivia",
    "Phoebe",
    "Sarah",
    "Scarlett",
    "Sophie",
    "Summer",
    "Tyler",
    "Violet",
    "William",
    "Zara",
    "Zoe",
};

pub fn Range(comptime T: type) type {
    return struct {
        min: T,
        max: T,
    };
}

/// Number of channels that a bot should try to be in.
pub const bot_channels_target = Range(u8){ .min = 2, .max = 5 };

/// Probability that a bot leaves a channel at each tick.
pub const bot_channels_leave_rate = Range(f32){ .min = 0.0005, .max = 0.0010 };

/// Number of sent messages per each tick in every joined channel.
pub const bot_message_rate = Range(f32){ .min = 0.001, .max = 0.005 };

/// Average message length.
pub const bot_message_length = Range(u8){ .min = 10, .max = 20 };
