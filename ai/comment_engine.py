def generate_comment(activity):
    comments = {
        "streaming":       "Someone is binge watching again 🍿",
        "gaming":          "Gaming traffic detected 🎮",
        "heavy_download":  "Downloading the internet again? 😭",
        "suspicious":      "Bro is definitely up to something 👀",
        "port_scan":       "Someone is knocking on ALL the doors 🚪",
        "normal":          "All quiet on the network front 😴",
    }
    return comments.get(activity, "Normal activity detected 🔍")
