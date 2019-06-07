from passthrough_addon import Passthrough

passthrough_addon = Passthrough()
passthrough_addon.filter.restApp.start()
addons = [
    passthrough_addon,
]
