-- disk cell: random segment across the working set (viewers spread over
-- channels x segment index)
local segs = tonumber(os.getenv("TS_FILES") or "600")
math.randomseed(math.floor((os.time() + os.clock()) * 1e6) % 2147483647)
request = function()
    return wrk.format("GET", string.format("/ts/seg%04d.ts", math.random(segs) - 1))
end
