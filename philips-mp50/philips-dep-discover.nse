description = [[
Attempts to idenify a UDP service running the Philips Data Export Protocol (DEP).
Sends a malformed DEP request, looking for the expected "REFUSE" datagram.
]]

author = "Conor Walsh"

license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

function portrule(host, port)
  port.protocol == "udp"
end

function action(host, port)
  local poke = "\x00"

  local status, recv = comm.exchange(host, port, poke, {timeout=10000})

  if not status then
    return
  end
  
  if (#recv) == 12 then
    local bytes = string.byte(recv,12,15)
    if (bytes == [6,4])
    then
      nmap.set_port_state(host, port, "open")
      port.version.name = "phillips-dep"
      nmap.set_port_version(host, port)
    end
  end
end