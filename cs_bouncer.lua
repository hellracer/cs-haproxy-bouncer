local _author = "Ronald Chan <loloski@protonmail.com>"
local _version = "0.1"
local _config_dir = "/etc/haproxy/"
local _config_file = "config.json"

local http = require("http")
local data = require("json")
local config = {}

local function init()
  
  local conf = _config_dir .. "/" .. _config_file
  local f = assert(io.open(conf, "r"))
  local t = f:read("*all")
  f:close()
  config = json.decode(t)

end

local function main(txn)

local ip = tostring(txn.f:src())

-- don't put hostname in base_url because lua in haproxy does not perform DNS resolution
-- please generate api_key by adding bouncer in cscli


local url = config.base_url.."/v1/decisions?ip="..ip

local res, err = http.get{url=url,
	headers={
		['User-Agent']={config.user_agent},
		['X-Api-Key']={config.api_key}
		}
	}
    
    if res then
        data = json.decode(res.content)
        if type(data) == "table" then
		local rem = data[1]["type"]
		if (rem == "ban") then
		       core.Info("Potential Threat IP = " .. ip .. " stopped by crowdsec")
		       return act.DENY
		end
	end
    else
	core.Info("CS Bouncer Error : " .. err)
    end

end

core.register_init(init)
core.register_action("crowdsec", {'http-req'}, main, 0)
