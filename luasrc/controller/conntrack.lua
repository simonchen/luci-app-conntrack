module("luci.controller.conntrack", package.seeall)

function index()
	if not nixio.fs.access("/proc/net/nf_conntrack") then
		return
	end
	entry({"admin", "network", "conntrack"}, template("conntrack/conntrack"), _("ConnTrack"), 90).dependent = true
	entry({"admin", "network", "conntrack_stream"}, call("action_stream")).dependent = true
end

function action_stream()
	local nixio = require "nixio"
	local jsonc = require "luci.jsonc"
	local http = require "luci.http"

	local interval = tonumber(http.formvalue("interval")) or 1000
	local max_rows = tonumber(http.formvalue("rows")) or 50

	if interval < 500 then interval = 500 end
	if interval > 10000 then interval = 10000 end

	http.header("Content-Type", "text/event-stream; charset=utf-8")
	http.header("Cache-Control", "no-cache")
	http.header("Connection", "keep-alive")
	http.context.redirect = false

	http.write("retry: 1000\n\n")
	io.flush()

	local function get_current_time()
		local sec, usec = nixio.gettimeofday()
		return sec + (usec / 1000000)
	end

	local last_connections = {}
	local last_timestamp = get_current_time()

	while true do
		local sec = math.floor(interval / 1000)
		local nsec = (interval % 1000) * 1000000
		nixio.nanosleep(sec, nsec)

		local current_timestamp = get_current_time()
		local current_connections = {}
		
		local f = io.open("/proc/net/nf_conntrack", "r")
		if not f then break end

		for line in f:lines() do
			local layer3, proto, remain = line:match("^(%w+)%s+%d+%s+(%w+)%s+(.*)$")
			if layer3 and (proto == "tcp" or proto == "udp") then
				local state = "UNTRACKED"
				if proto == "tcp" then
					state = remain:match("^%d+%s+%d+%s+(%w+)") or "UNKNOWN"
				end

				local src1, dst1, sport1, dport1, bytes1, src2, dst2, sport2, dport2, bytes2 = remain:match(
					"src=([%a%d%.%:]+).-dst=([%a%d%.%:]+).-sport=(%d+).-dport=(%d+).-bytes=(%d+).-src=([%a%d%.%:]+).-dst=([%a%d%.%:]+).-sport=(%d+).-dport=(%d+).-bytes=(%d+)"
				)

				if bytes1 and bytes2 then
					local display_proto = proto
					if proto == "udp" and (sport1 == "443" or dport1 == "443" or sport2 == "443" or dport2 == "443") then
						display_proto = "quic"
					end

					local key_orig = string.format("%s_%s_%s:%s->%s:%s_ORIG", layer3, display_proto, src1, sport1, dst1, dport1)
					current_connections[key_orig] = {
						l3 = layer3, proto = display_proto, state = state .. "(正向)",
						src = src1, sport = sport1, dst = dst1, dport = dport1, bytes = tonumber(bytes1), speed = 0
					}

					local key_repl = string.format("%s_%s_%s:%s->%s:%s_REPL", layer3, display_proto, src2, sport2, dst2, dport2)
					current_connections[key_repl] = {
						l3 = layer3, proto = display_proto, state = state .. "(反向)",
						src = src2, sport = sport2, dst = dst2, dport = dport2, bytes = tonumber(bytes2), speed = 0
					}
				end
			end
		end
		f:close()

		local delta_time = current_timestamp - last_timestamp
		if delta_time > 0 then
			for key, curr in pairs(current_connections) do
				local prev = last_connections[key]
				if prev then
					local diff = curr.bytes - prev.bytes
					curr.speed = diff >= 0 and math.floor(diff / delta_time) or 0
				else
					curr.speed = 0
				end
			end
		end

		local sorted_list = {}
		for _, conn in pairs(current_connections) do
			if conn.speed > 0 then
				table.insert(sorted_list, conn)
			end
		end

		table.sort(sorted_list, function(a, b) return a.speed > b.speed end)

		local output_list = {}
		for i = 1, math.min(#sorted_list, max_rows) do
			table.insert(output_list, sorted_list[i])
		end

		local response = {
			delta = string.format("%.4f", delta_time),
			connections = output_list
		}

		local json_str = jsonc.stringify(response)
		local ok = pcall(function()
			io.write("data: " .. json_str .. "\n\n")
			io.flush()
		end)

		if not ok then break end

		last_connections = current_connections
		last_timestamp = current_timestamp
	end
end
