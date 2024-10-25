local Driver = require "st.driver"
local log = require "log"
local socket = require "socket"
local caps = require "st.capabilities"

local COLOLIGHT_PORT = 8900
local POLL_INTERVAL = 300

local FILLER = "00000000000000000000000000000000010000000000000000000"

local CMD_PREFIX = "535a30300000000000"
local CONF_PREFIX = "20" .. FILLER .. "4010301c"
local EFCT_PREFIX = "23" .. FILLER .. "4010602ff"
local STAT_PREFIX = "1e" .. FILLER .. "3020101"

local SUPPORTED_MODES = {
  "LifeSmart",
  "Peach blossom",
  "Aurora",
  "Christmas",
  "Macaron",
  "Rainbow",
  "Quick rainbow",
  "Sunrise",
  "Ice cream",
  "Laser",
  "Circus",
  "Music"
}

local MODE_CODES = {
  ["LifeSmart"] = "04970400",
  ["Peach blossom"] = "04940800",
  ["Aurora"] = "04c40600",
  ["Christmas"] = "068b0900",
  ["Macaron"] = "049a0e00",
  ["Rainbow"] = "05bd0690",
  ["Quick rainbow"] = "03810690",
  ["Sunrise"] = "01c10a00",
  ["Ice cream"] = "03bc0190",
  ["Laser"] = "049a0000",
  ["Circus"] = "04810130",
  ["Music"] = "07bd0990"
}


local function hex_to_bytes(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
      local byte = hex:sub(i, i+1)
      table.insert(bytes, string.char(tonumber(byte, 16)))
  end
  return table.concat(bytes)
end

local function to_hex2(value)
  return string.format("%02X", value)
end

local function is_device_on(device)
  local switch_state = device:get_latest_state("main", caps.switch.ID, "switch")
  return switch_state and switch_state.value == "on"
end

local function send_command(addr, command)
  local udp = socket.udp()
  log.debug("Sending command (" .. command .. ") to " .. addr["ip"] .. ":" .. addr["port"])
  udp:settimeout(1)
  udp:setpeername(addr["ip"], addr["port"])
  udp:send(hex_to_bytes(command))

  local response, err = udp:receive()
  if response then
    log.debug("Device responded: " .. response)
    return response
  else
    log.debug("No response received/Error has occurred: " .. tostring(err))
  end

  udp:close()
end

local function discover(ntwrk_id, driver)
  local udp = socket.udp()
  udp:settimeout(5)
  udp:setoption('broadcast', true)
  udp:setsockname('*', 0)
  local discovery_message = string.char(0x43, 0x4c, 0x49, 0x4e, 0x51)

  udp:sendto(discovery_message, "255.255.255.255", COLOLIGHT_PORT)

  while true do
    local data, ip, port = udp:receivefrom()
    if data then
      log.info("Received response from " .. ip .. ":" .. port)

      --[[ for i = 1, #data do
        local byte = string.byte(data, i)
        log.debug(string.format("Byte %d: 0x%X (%d)", i, byte, byte))
      end ]]

      local start_pos = math.max(#data - 11, 1)
      local ascii_bytes = data:sub(start_pos, #data)

      local mac_address = ""
      for i = 1, #ascii_bytes do
        local byte = string.byte(ascii_bytes, i)
        mac_address = mac_address .. string.char(byte)
      end

      if mac_address then
        
        if not ntwrk_id then
          local device_name = "Cololight Hexagon"

          log.info("Discovered Cololight with MAC: " .. mac_address)

          local device_metadata = {
            type = "LAN",
            device_network_id = mac_address,
            label = device_name,
            profile = "cololight.hexagon.v1",
            manufacturer = "Cololight",
            model = "Hexagon",
            vendor_provided_label = device_name,
          }

          local existing_device = driver:get_device_info(device_metadata.device_network_id)
          if not existing_device then
            driver:try_create_device(device_metadata)
          end
        end

        driver.datastore[mac_address] = {
          ["ip"] = ip,
          ["port"] = port
        }

        log.info("Set device network information")

        return true
      else
        log.error("Unexpected response format")
      end
    else
      break
    end
  end
  udp:close()
end

local function discovery_handler(driver, opts, cont)
  log.info("Starting device discovery")

  discover(nil, driver)
end

-- Capability Handlers

local function switch_on_handler(driver, device, command)
  local ntwrk = driver.datastore[device.device_network_id]
  local cmd = CMD_PREFIX .. CONF_PREFIX .. "f35"
  local res = send_command(ntwrk, cmd)
  cmd = CMD_PREFIX .. CONF_PREFIX .. "f" .. to_hex2(device:get_latest_state("main", "switchLevel", "level"))
  send_command(ntwrk, cmd)

  if res then
    device:emit_event(caps.switch.switch.on())
  end
end


local function switch_off_handler(driver, device, command)
  local ntwrk = driver.datastore[device.device_network_id]
  local cmd = CMD_PREFIX .. CONF_PREFIX .. "e1e"
  local res = send_command(ntwrk, cmd)

  if res then
    device:emit_event(caps.switch.switch.off())
  end
end


local function set_level_handler(driver, device, command)
  local ntwrk = driver.datastore[device.device_network_id]

  if command.args.level == 0 then
    switch_off_handler(driver, device, command)
    return
  end

  local cmd = CMD_PREFIX .. CONF_PREFIX .. "f" .. to_hex2(command.args.level)
  local res = send_command(ntwrk, cmd)

  if res then
    device:emit_event(caps.switchLevel.level(command.args.level))
    if not is_device_on(device) then
      device:emit_event(caps.switch.switch.on())
    end
  end
end


local function set_color_handler(driver, device, command)
  local ip = driver.datastore[device.device_network_id]
  local hue_g = command.args.color.hue
  local saturation_g = command.args.color.saturation

  local function hsv_to_rgb(hue, saturation, value)

    if saturation > 1 then
      saturation = 1
    end

    if hue > 360 then
      hue = 360
    end

    local c = value * saturation
    local x = c * (1 - math.abs((hue / 60) % 2 - 1))
    local m = value - c

    local r, g, b
    if hue >= 0 and hue < 60 then
        r, g, b = c, x, 0
    elseif hue >= 60 and hue < 120 then
        r, g, b = x, c, 0
    elseif hue >= 120 and hue < 180 then
        r, g, b = 0, c, x
    elseif hue >= 180 and hue < 240 then
        r, g, b = 0, x, c
    elseif hue >= 240 and hue < 300 then
        r, g, b = x, 0, c
    elseif hue >= 300 and hue <= 360 then
        r, g, b = c, 0, x
    else
        r, g, b = 1, 1, 1 -- default to white if hue is out of range
    end

    local r_final = (r + m) * 255
    local g_final = (g + m) * 255
    local b_final = (b + m) * 255

    return math.floor(r_final), math.floor(g_final), math.floor(b_final)
  end

  local r, g, b = hsv_to_rgb(hue_g * 3.6, saturation_g / 100, 1)
  local cmd = CMD_PREFIX .. EFCT_PREFIX .. "00" .. to_hex2(r) .. to_hex2(g) .. to_hex2(b)
  local res = send_command(ip, cmd)

  if res then
    device:emit_event(caps.colorControl.hue(hue_g))
    device:emit_event(caps.colorControl.saturation(saturation_g))
    device:emit_event(caps.mode.mode("None"))
    if not is_device_on(device) then
      switch_on_handler(driver, device, nil)
    end
  end
end

local function set_mode_handler(driver, device, command)
  local ntwrk = driver.datastore[device.device_network_id]
  local mode_name = command.args.mode

  local mode_cmd = MODE_CODES[mode_name]
  if not mode_cmd then
    log.error("Unsupported mode: " .. mode_name)
    return
  end

  local cmd = CMD_PREFIX .. EFCT_PREFIX .. mode_cmd
  local res = send_command(ntwrk, cmd)

  if res then
    device:emit_event(caps.mode.mode(mode_name))
    if not is_device_on(device) then
      switch_on_handler(driver, device, nil)
    end
  end
end

local function refresh_handler(driver, device)
  local ntwrk = driver.datastore[device.device_network_id]
  local res = send_command(ntwrk, CMD_PREFIX .. STAT_PREFIX)

  if res then

    device:online()

    local state_byte = string.sub(res, 41, 41)

    if state_byte == "\xcf" then
      if not is_device_on(device) then
        device:emit_event(caps.switch.switch.on())
      end

      local level_byte = string.sub(res, 42, 42)
      device:emit_event(caps.switchLevel.level(string.byte(level_byte)))

    elseif state_byte == "\xce" then
      if is_device_on(device) then
        device:emit_event(caps.switch.switch.off())
      end
    end
  else
    if not discover(device.device_network_id, driver) then
      device:offline()
    end
  end
end

local function device_init(driver, device)
  log.info("Initializing device: " .. device.device_network_id)
  local device_info = driver.datastore[device.device_network_id]
  if not device_info then
    log.error("IP address not found for device: " .. device.device_network_id)
  end

  device:emit_event(caps.mode.supportedModes(SUPPORTED_MODES))
  device:emit_event(caps.mode.mode("None"))

  device.thread:call_on_schedule(POLL_INTERVAL, function()
    refresh_handler(driver, device)
  end, 'polling')
end

local function device_added(driver, device)
  log.info("Device added: " .. device.device_network_id)

  switch_off_handler(driver, device, nil)

  device:emit_event(caps.switchLevel.level(50))
end

local driver_template = {
  discovery = discovery_handler,
  lifecycle_handlers = {
    init = device_init,
    added = device_added,
  },
  supported_capabilities = {
    caps.switch,
    caps.switchLevel,
    caps.mode,
    caps.colorControl,
    caps.refresh,
  },
  capability_handlers = {
    [caps.switch.ID] = {
      [caps.switch.commands.on.NAME] = switch_on_handler,
      [caps.switch.commands.off.NAME] = switch_off_handler,
    },
    [caps.switchLevel.ID] = {
      [caps.switchLevel.commands.setLevel.NAME] = set_level_handler,
    },
    [caps.colorControl.ID] = {
      [caps.colorControl.commands.setColor.NAME] = set_color_handler,
    },
    [caps.mode.ID] = {
      [caps.mode.commands.setMode.NAME] = set_mode_handler,
    },
    [caps.refresh.ID] = {
      [caps.refresh.commands.refresh.NAME] = refresh_handler,
    },
  },
}

Driver("cololight-hexagons", driver_template):run()
