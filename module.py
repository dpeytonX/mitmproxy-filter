from passthrough_addon import Passthrough
from uplynk_addon import Uplynk

passthrough_addon = Passthrough()
passthrough_addon.filter.restApp.start()
addons = [
    passthrough_addon,
    Uplynk()
]
