from passthrough_addon import Passthrough
from uplynk_addon import Uplynk
from unicornmedia_addon import UnicornMedia
from youtube_addon import YouTube

sitm=[
  "uplynk\\.com",
  "unicornmedia\\.com",
  "youtube\\.com"
]

passthrough_addon = Passthrough(sitm)
addons = [
    passthrough_addon,
    Uplynk(),
    UnicornMedia(),
    YouTube()
]
