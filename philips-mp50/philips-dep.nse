local stdnse = require "stdnse"
local io = require "io"
local shortport = require "shortport"

description = [[
Attempts to idenify a UDP service running the Philips Data Export Protocol (DEP).
Sends a malformed DEP request, looking for the expected "REFUSE" datagram.
]]

author = "Conor Walsh"

license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

HUAWEI_UDP_PORT = 43690
PAYLOAD_LOCATION = "nselib/data/huawei-udp-info"

function portrule(host, port)
  if port.protocol == "udp"
  then
    return true
  end
end


load_udp_payload = function()
  local payload_l = nmap.fetchfile(PAYLOAD_LOCATION)
  if (not(payload_l)) then
    stdnse.print_debug(1, "%s:Couldn't locate payload %s", SCRIPT_NAME, PAYLOAD_LOCATION)
    return
  end
  local payload_h = io.open(payload_l, "rb")
  local payload = payload_h:read("*a")
  if (not(payload)) then
    stdnse.print_debug(1, "%s:Couldn't load payload %s", SCRIPT_NAME, payload_l)
    if nmap.verbosity()>=2 then
      return "[Error] Couldn't load payload"
    end
    return
  end

  payload_h:flush()
  payload_h:close()
  return payload
end

---
-- send_udp_payload(ip, timeout)
-- Sends the payload to port and returns the response
---
send_udp_payload = function(ip, port, timeout, payload)
  local data
  stdnse.print_debug(2, "%s:Sending UDP payload", SCRIPT_NAME)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(tonumber(timeout))
  local status = socket:connect(ip, port.number, "udp")
  if (not(status)) then return end
  status = socket:send(payload)
  if (not(status)) then return end

  status, data = socket:receive()
  if (not(status)) then
    stdnse.debug(1,"No response")
    socket:close()
    return
  end
  socket:close()
  return data
end

---
-- Parses response to extract information.
-- Only removes null bytes now.
---
parse_resp = function(resp)
  local abort_msg = "\x0c\x03\x32\x01\x00"
  if resp == abort_msg
  then
    return "Detected: Philips Data Export Protocol Server"
  end
end

---
--MAIN
---
action = function(host, port)
  local timeout = stdnse.get_script_args(SCRIPT_NAME..".timeout") or 3000
  --local payload = load_udp_payload()
  local payload = "\x0d\xec\x05\x08"
  local response = send_udp_payload(host.ip, port, timeout, payload)
  if response then
    return parse_resp(response)
  end
end
