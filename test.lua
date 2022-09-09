-- mtu_detect and handshake port
local Start_Port = 901
local End_Port = 903
-- define new_port
local New_Port

local switch = {
	cmd = {},
	handshake_code = {},
	reason = {}
}

switch.handshake_code = {
	[0x00] = "Hankshake Succ",
	[0x01] = "Error Request",
	[0x02] = "Refuse Service",
	[0x03] = "",
	[0x04] = "",
	[0x05] = "",
	[0x06] = "",
	[0x07] = "",
	[0xFC] = "",
	[0xFD] = "",
	[0xFE] = "",
	[0xFF] = "unknow error"
}

switch.hungup_reason = {
	[0x00] = "",
	[0x01] = "",
	[0x02] = "",
	[0x03] = "",
	[0x04] = "",
	[0x05] = "",
	[0x06] = ""
}





--读出位值
function Bitval(a,b)
    return bit.band(a, b)
end

--定义自己协议的字段
local VER = {[0x01] = "0x01"}
local PATH = {[0x00] = "single path", [0x01] = "main path", [0x02] = "vice path"}
local CMD = {[0x01] = "ACK", [0x02] = "SYN", [0x03] = "SYN_ACK", [0x04] = "FIN", 
    [0x05] = "FIN_ACK", [0x06] = "DATA_MEASURE", [0x07] = "DATA", [0x08] = "HANDSHAKE", 
    [0x09] = "HANDSHAKE_ACK", [0x0A] = "ECHO request", [0x0B] = "HANG_UP", [0x0C] = "AUTHORIZE"}
local Box_VER = ProtoField.uint8("Box_MtuDetect_version", "VER", base.DEC, VER, 0xC0)--2bit
local Box_PATH = ProtoField.uint8("Box_MtuDetect_path","PATH", base.DEC ,PATH, 0x30)--2bit
local Box_CMD = ProtoField.uint8("Box_MtuDetect_cmd", "CMD", base.DEC, CMD, 0x0F)--4bit
local Box_SN = ProtoField.uint32("Box_MtuDetect_sn", "SN", base.DEC)--32bit
local Box_Detect_TOTALSIZE = ProtoField.uint16("Box_MtuDetect_totalsize", "TOTALSIZE", base.DEC)--16bit
local Box_HandShake_NUM = ProtoField.uint8("Box_HandShake_num", "NUM", base.DEC)--8bit
local Box_HandShake_CODE = ProtoField.uint8("Box_HandShake_code", "CODE", base.DEC, switch.handshake_code, 0xFF)--8bit
local Box_HandShake_LPORT = ProtoField.uint16("Box_HandShake_lport", "LPORT", base.DEC)--16bit
local Box_HandShake_VIPSIZE = ProtoField.uint8("Box_HandShake_vipsize", "VIPSIZE", base.DEC)--8bit
local Box_Syn_NUM = ProtoField.uint8("Box_Syn_num", "NUM", base.DEC)--8bit
local Box_Syn_MAXSN = ProtoField.uint32("Box_Syn_maxsn", "MAXSN", base.DEC)--32bit
local Box_Syn_CODE = ProtoField.uint8("Box_Syn_code", "CODE", base.DEC)--8bit





--1.创建解析器对象
Box_Detect_Protocol = Proto("Mtu_Detect", "Mtu_Detect Protocol")

--2.添加字段
Box_Detect_Protocol.fields = {Box_VER, Box_PATH, Box_CMD, Box_SN, Box_Detect_TOTALSIZE}

--3.解析器函数，此函数由wireshark调用
function Box_Detect_Protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local subtree = tree:add(Box_Detect_Protocol, buffer(), "Mtu_Detect Data")
    
	function Head()
		local Msg_Head_Tree = subtree:add("HEAD", buffer(0, 5))--加一层HEAD，把固定的头部放在里面（前5个字节）
        Msg_Head_Tree:add(Box_VER, buffer(0, 1))
        Msg_Head_Tree:add(Box_PATH, buffer(0, 1))
        Msg_Head_Tree:add(Box_CMD, buffer(0, 1))
        Msg_Head_Tree:add(Box_SN, buffer(1, 4))
    end
	
	
	function Action(a,b)--输出当前所属动作，将协议列替换为动作
		local result = Bitval(a,b)
        if result == 1 then
            pinfo.cols.protocol = "Mtu_Detect Response"
        elseif result == 10 then
            pinfo.cols.protocol = "Mtu_Detect Request"
            subtree:add(Box_Detect_TOTALSIZE, buffer(5, 2))
		elseif result == 8 then
				pinfo.cols.protocol = "HandShake Request"
				subtree:add(Box_HandShake_NUM, buffer(5, 1))
		elseif result == 9 then
            pinfo.cols.protocol = "HandShake Response"
            subtree:add(Box_HandShake_CODE, buffer(5, 1))
            subtree:add(Box_HandShake_LPORT, buffer(6, 2))
			New_Port = Bitval(buffer(6, 2):uint(), 0xFFFF)
            subtree:add(Box_HandShake_VIPSIZE, buffer(9, 1))
        end
            
		--需要优化，if-else使用元表替代
		-- if result == 1 or result == 10 then--CMD为1或10是探测的动作
		-- 	pinfo.cols.protocol = "Box_Mtu_Detect"
		-- end
		-- if result == 8 or result == 9 then--CMD为8或9是握手的动作
		-- 	pinfo.cols.protocol = "Hand_Shake"
		-- end
		--后续增加
	end
	
    Head()
    Action(buffer(0, 1):uint(), 0x0F)
	--发往节点901-903端口
	-- if pinfo.dst_port >= Start_Port and pinfo.dst_port <= End_Port then 
	-- 	Head()
	-- 	Action(buffer(0,1):uint(),0x0F)
	-- end

	--来自节点901-903端口
	-- if pinfo.src_port >= Start_Port and pinfo.src_port <= End_Port then
	-- 	Head()
	-- 	Action(buffer(0,1):uint(),0x0F)
	-- 	--local a = buffer(0,1):uint()
	-- 	--local b = bit.band(a,0x0F)
	-- 	if Bitval(buffer(0,1):uint(),0x0F) == 1 then 
	-- 		subtree:add(Box_Detect_TOTALSIZE,buffer(5,2))
	-- 	end 
		
	-- end

end




-- Box_HandShake_Protocol = Proto("HandShake", "HandShake Protocol")

-- Box_HandShake_Protocol.fields = {Box_VER, Box_PATH, Box_CMD, Box_SN, Box_HandShake_NUM, Box_HandShake_CODE, Box_HandShake_LPORT, Box_HandShake_VIPSIZE}

-- function Box_HandShake_Protocol.dissector(buffer, pinfo, tree)
--     length = buffer:len()
--     if length == 0 then return end
--     local subtree = tree:add(Box_HandShake_Protocol, buffer(), "HandShake Data")
    
--     function Head()
--         local Msg_Head_Tree = subtree:add("HEAD", buffer(0, 5))--加一层HEAD，把固定的头部放在里面（前5个字节）
--         Msg_Head_Tree:add(Box_VER, buffer(0, 1))
--         Msg_Head_Tree:add(Box_PATH, buffer(0, 1))
--         Msg_Head_Tree:add(Box_CMD, buffer(0, 1))
--         Msg_Head_Tree:add(Box_SN, buffer(1, 4))
--     end
    
--     function Action(a, b) 
--         local result = Bitval(a, b)
--         if result == 8 then
--             pinfo.cols.protocol = "HandShake Request"
--             subtree:add(Box_HandShake_NUM, buffer(5, 1))
--         else result == 9 then
--             pinfo.cols.protocol = "HandShake Response"
--             subtree:add(Box_HandShake_CODE, buffer(5, 1))
--             subtree:add(Box_HandShake_LPORT, buffer(6, 2))
-- 			New_Port = Bitval(buffer(6, 2):uint(), 0xFFFF)
--             subtree:add(Box_HandShake_VIPSIZE, buffer(9, 1))
--         end
--     end

--     Head()
--     Action(buffer(0, 1):uint(), 0x0F)
-- end













--4.注册到wirshark解析表
DissectorTable.get("udp.port"):add("901-903", Box_Detect_Protocol)
-- DissectorTable.get("udp.port"):add("901-903", Box_HandShake_Protocol)



Box_VPNServer_Protocol = Proto("Box_VPNServer", "VPNServer Protocol")

Box_VPNServer_Protocol.fields = {Box_VER, Box_PATH, Box_CMD, Box_SN, Box_Syn_NUM, Box_Syn_MAXSN, Box_Syn_CODE}

function Box_VPNServer_Protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	local subtree = tree:add(Box_VPNServer_Protocol, buffer(), "VPNServer Data")

	function Head()
		local Msg_Head_Tree = subtree:add("HEAD", buffer(0, 5))--加一层HEAD，把固定的头部放在里面（前5个字节）
		Msg_Head_Tree:add(Box_VER, buffer(0, 1))
        Msg_Head_Tree:add(Box_PATH, buffer(0, 1))
        Msg_Head_Tree:add(Box_CMD, buffer(0, 1))
        -- Msg_Head_Tree:add(Box_SN, buffer(1, 4))
    end

	function Action(a, b) 
        local result = Bitval(a, b)
		if result == 2 then
			pinfo.cols.protocol = "Syn Request"
			subtree:add(Box_Syn_NUM, buffer(5, 1))
		elseif result == 3 then
			pinfo.cols.protocol = "Syn Response"
			subtree:add(Box_Syn_MAXSN, buffer(1, 4))
			subtree:add(Box_Syn_CODE, buffer(5, 1))
		end
	end

	Head()
	Action(buffer(0, 1):uint(), 0x0F)
end
DissectorTable.get("udp.port"):add(New_Port, Box_VPNServer_Protocol)