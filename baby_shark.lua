--[[References

[1] https://www.wireshark.org/

[2] https://go.respond-software.com/voice-of-the-analyst/

[3] https://www.malware-traffic-analysis.net/tutorials/wireshark/index.html

[4] https://twitter.com/malware_traffic 

[5] https://blog.didierstevens.com/2014/04/28/tcp-flags-for-wireshark/

[6] https://twitter.com/DidierStevens 

[7] https://www.wireshark.org/docs/wsug_html_chunked/ChCustConfigProfilesSection.html 
  
[8] https://blog.didierstevens.com/ 
--]]


 function url_decode(str)
    str = string.gsub (str, "+", " " )
    str = string.gsub (str, "%%(%x%x)",
        function(h) return string.char(tonumber(h,16)) end)
    str = string.gsub (str, "\r\n", "\n")
    return str
end 



local function check(packet)

    local result = url_decode(tostring(packet))
    result = string.match(result, "'Mozilla/5.0.*")
    if result ~= nil then
        return true
    else
        return false
    end
end

local function register_suspicious_postdissector()
    local proto = Proto('suspicious', 'suspicious dissector')

    exp_susp = ProtoExpert.new('suspicious.expert','Potential Attack', expert.group.SECURITY, expert.severity.WARN)
    proto.experts = {exp_susp}

    function proto.dissector(buffer, pinfo, tree)

        local range = buffer:range()

        if check(range:string()) then
            local stree = tree:add(proto, 'Suspicious')
            stree:add_proto_expert_info(exp_susp)

        end
    end

    register_postdissector(proto)

end
register_suspicious_postdissector()