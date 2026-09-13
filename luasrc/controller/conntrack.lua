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
	local filter_src = http.formvalue("filter_src") or "all"
	local filter_dst = http.formvalue("filter_dst") or "all"
	local filter_local = http.formvalue("filter_local") or "false"

	local lan_prefix = "192.168.1."
	local lan_ip = luci.util.exec("uci -q get network.lan.ipaddr"):gsub("%s+", "")
	if lan_ip and lan_ip ~= "" then
		if lan_ip:match("^192%.168%.") or lan_ip:match("^10%.") or lan_ip:match("^172%.") then
			lan_prefix = lan_ip:match("^([%d%.]+%.)%d+$") or "192.168.1."
		end
	end

        local function is_local_ip(ip)
                if not ip then return true end
                local clean_ip = ip:lower():gsub("%s+", ""):gsub("%[", ""):gsub("%]", "")
                if clean_ip == "127.0.0.1" or clean_ip == "0.0.0.0" or clean_ip == "::1" or clean_ip == "::" then return true end
                local no_zeros = clean_ip:gsub("0", "")
                if no_zeros == ":::::::1" or no_zeros == "::::::::" then return true end
                if clean_ip:find("^192%.168%.") or clean_ip:find("^10%.") or clean_ip:find("^172%.1[6-9]%.") or clean_ip:find("^172%.2%d%.") or clean_ip:find("^172%.3%.") then
                        return true
                end
                if clean_ip:find("^fc") or clean_ip:find("^fd") then
                        return true
                end
                if clean_ip:find("^fe[89ab]") then
                        return true
                end
                return false
        end

	local function normalize_ipv6(ip)
		if not ip or not ip:find(":") then return ip end
		local clean_ip = ip:lower():gsub("%s+", "")
		if clean_ip:find("::") then
			local _, count = clean_ip:gsub(":", "")
			local colons_to_add = 8 - count
			local replacement = ":"
			for i = 1, colons_to_add do replacement = replacement .. ":" end
			clean_ip = clean_ip:gsub("::", replacement)
		end
		local parts = {}
		for part in clean_ip:gmatch("([^:]+)") do
			while #part < 4 do part = "0" .. part end
			table.insert(parts, part)
		end
		while #parts < 8 do table.insert(parts, "0000") end
		return table.concat(parts, ":")
	end

	local lease_map = {}
	local mac_host_map = {}
	local ipv6_mac_map = {}

	local lf = io.open("/tmp/dhcp.leases", "r")
	if lf then
		for line in lf:lines() do
			local mac, ip, host = line:match("^%d+%s+([%a%d%:]+)%s+([%d%.%a%d%:]+)%s+([%w%-_]+)")
			if not mac or not host then
				ip, host = line:match("^%d+%s+[%a%d%:]+%s+([%d%.]+)%s+([%w%-_]+)")
			end
			if ip and host and host ~= "*" then
				lease_map[ip] = host
			end
			if mac and host and host ~= "*" then
				mac_host_map[mac:lower()] = host
			end
		end
		lf:close()
	end

	local sys_host = luci.util.exec("uci -q get system.@system[0].hostname"):gsub("%s+", "")
	if sys_host == "" then sys_host = "lan" end
	if lan_ip and lan_ip ~= "" then
		lease_map[lan_ip] = sys_host
	end

	-- adding ipv6 <-> host mapping
	local np = io.popen("ip -6 neighbor | grep -E -v 'FAILED'")
	if np then
		for line in np:lines() do
			local ip, mac = line:match("^([%a%d%:]+).-lladdr%s+([%a%d%:]+)")
			if ip and mac then
				local clean_ip = ip:lower():gsub("%s+", "")
				if not is_local_ip(clean_ip) then
					local norm_ip = normalize_ipv6(clean_ip)
					ipv6_mac_map[norm_ip] = mac:lower()
				end
			end
		end
		np:close()
	end

	for ipv6, mac in pairs(ipv6_mac_map) do
		local host = mac_host_map[mac]
		if host then
			lease_map[ipv6] = host
		end
	end

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
		local ip_map = {}
		
		local f = io.open("/proc/net/nf_conntrack", "r")
		if not f then break end

		for line in f:lines() do
			local layer3, proto, remain = line:match("^(%w+)%s+%d+%s+(%w+)%s+(.*)$")
			if layer3 and (proto == "tcp" or proto == "udp") then
				local state = "UNTRACKED"
				if proto == "tcp" then
					state = remain:match("^%d+%s+%d+%s+([%w_]+)") or "UNKNOWN"
				end

				local src1, dst1, sport1, dport1, bytes1, src2, dst2, sport2, dport2, bytes2, remain2 = remain:match(
					"src=([%a%d%.%:]+).-dst=([%a%d%.%:]+).-sport=(%d+).-dport=(%d+).-bytes=(%d+).-src=([%a%d%.%:]+).-dst=([%a%d%.%:]+).-sport=(%d+).-dport=(%d+).-bytes=(%d+)%s+(.*)$"
				)

				if bytes1 and bytes2 then
					-- NF_CONNTRACK module needs be patched for displaying payload
					local payload = ""
					if remain2 then payload = remain2:match("payload=(%x+)") or "" end

					local display_proto = proto
					if proto == "udp" and (sport1 == "443" or dport1 == "443" or sport2 == "443" or dport2 == "443") then
						display_proto = "quic"
					end

				      if filter_local == "true" and is_local_ip(src1) and is_local_ip(dst1) then
						-- do nothing
				      else
					if layer3 == "ipv4" then
						-- IPv4 DNAT revert --
						if src2 == lan_ip or src2 == '127.0.0.1' then src2 = dst1 end
						-- IPv4 SNAT revert --
						if dst2 ~= src1 then dst2 = src1 end
					end

					ip_map[src1] = true
					ip_map[dst1] = true
					ip_map[src2] = true
					ip_map[dst2] = true

					local pass_orig = true
					if filter_src ~= "all" and src1 ~= filter_src then pass_orig = false end
					if filter_dst ~= "all" and dst1 ~= filter_dst then pass_orig = false end

					if pass_orig then
						local key_orig = string.format("%s_%s_%s:%s->%s:%s_ORIG", layer3, display_proto, src1, sport1, dst1, dport1)
						current_connections[key_orig] = {
							l3 = layer3, proto = display_proto, state = state,
							src = src1, sport = sport1, dst = dst1, dport = dport1, bytes = tonumber(bytes1), speed = 0, payload = payload
						}
					end

					local pass_repl = true
					if filter_src ~= "all" and src2 ~= filter_src then pass_repl = false end
					if filter_dst ~= "all" and dst2 ~= filter_dst then pass_repl = false end

					if pass_repl then
						local key_repl = string.format("%s_%s_%s:%s->%s:%s_REPL", layer3, display_proto, src2, sport2, dst2, dport2)
						current_connections[key_repl] = {
							l3 = layer3, proto = display_proto, state = state,
							src = src2, sport = sport2, dst = dst2, dport = dport2, bytes = tonumber(bytes2), speed = 0, payload = payload
						}
					end
				      end
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
					if curr.proto == "udp" or curr.proto == "quic" then
						curr.speed = math.floor(curr.bytes / delta_time) or 0
					else
						curr.speed = 0
					end
				end
			end
		end

		local sorted_list = {}
		for _, conn in pairs(current_connections) do
			-- if conn.speed > 0 then
				table.insert(sorted_list, conn)
			-- end
		end

		table.sort(sorted_list, function(a, b) return a.speed > b.speed end)

		local output_list = {}
		for i = 1, math.min(#sorted_list, max_rows) do
			table.insert(output_list, sorted_list[i])
		end

		local lan_ips = {}
		local v4_ips = {}
		local v6_ips = {}
		local lan_pattern = "^" .. lan_prefix:gsub("%.", "%%.")

		for ip in pairs(ip_map) do
			if ip:find(":") then
				table.insert(v6_ips, ip)
			elseif ip:match(lan_pattern) then
				table.insert(lan_ips, ip)
			else
				table.insert(v4_ips, ip)
			end
		end
		table.sort(lan_ips)
		table.sort(v4_ips)
		table.sort(v6_ips)

		local unique_ips = {}
		for _, ip in ipairs(lan_ips) do table.insert(unique_ips, ip) end
		for _, ip in ipairs(v4_ips) do table.insert(unique_ips, ip) end
		for _, ip in ipairs(v6_ips) do table.insert(unique_ips, ip) end

		local response = {
			delta = string.format("%.2f", delta_time),
			connections = output_list,
			unique_ips = unique_ips,
			host_map = lease_map
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
