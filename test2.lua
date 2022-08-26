local Start_Port = 901
local End_Port = 903
--定义自己协议的字段
local New_Port
local Vals_Bit_1 = {[0x01] = "0x01"}
local Vals_Bit_2 = {[0x00] = "single path", [0x01] = "main path", [0x02] = "vice path"}
local Vals_Bit_3 = {[0x01] = "ACK", [0x02] = "SYN", [0x03] = "SYN_ACK", [0x04] = "FIN", [0x05] = "FIN_ACK", [0x06] = "DATA_MEASURE", [0x07] = "DATA", [0x08] = "HANDSHAKE", [0x09] = "HANDSHAKE_ACK", [0x0A] = "ECHO request", [0x0B] = "HANG_UP", [0x0C] = "AUTHORIZE"}


local Box_Detect_VER = ProtoField.uint8("Box_Detect.Message_version", "VER", base.DEC, Vals_Bit_1, 0xC0)--2bit
local Box_Detect_PATH = ProtoField.uint8("Box_Detect.Message_path", "PATH", base.DEC, Vals_Bit_2, 0x30)--2bit
local Box_Detect_CMD = ProtoField.uint8("Box_Detect.Message_cmd", "CMD", base.DEC, Vals_Bit_3, 0x0F)--4bit
local Box_Detect_SN = ProtoField.uint32("Box_Detect.Message_sn", "SN", base.DEC)--32bit
local Box_Detect_TOTALSIZE = ProtoField.uint16("Box_Detect.message_totalsize", "TOTALSIZE", base.DEC)--16bit
local Box_Detect_CODE = ProtoField.uint8("Box_Detect.Message_code", "CODE", base.DEC)--8bit
local Box_Detect_LPORT = ProtoField.uint16("Box_Detect.Message_lport", "LPORT", base.DEC)--16bit


local Port = {
	[901] = true,
	[902] = true,
	[903] = true
}
local switch = {
	[1] = "ACK",
	[2] = "SYN",
	[3] = "SYN_ACK",
	[4] = "FIN",
	[5] = "FIN_ACK",
	[6] = "DATA_MEASURE",
	[7] = "DATA",
	[8] = "HANDSHAKE",
	[9] = "HANDSHAKE_ACK",
	[10] = "MTU_ECHO",
	[11] = "HANG_UP",
	[12] = "AUTHORIZE"
}

--1.创建解析器对象
Box_Detect_Protocol = Proto("Box_Detect", "Box_Detect Protocol")
--2.添加字段
Box_Detect_Protocol.fields = {Box_Detect_VER, Box_Detect_PATH, Box_Detect_CMD, Box_Detect_SN, Box_Detect_TOTALSIZE}
--3.解析器函数，此函数由wireshark调用
function Box_Detect_Protocol.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then 
		return
	end
	local subtree = tree:add(Box_Detect_Protocol, buffer(), "Box_Detect_Protocol Data")

	function Head()
		local Msg_Head_Tree = subtree:add("HEAD", buffer(0, 5))--加一层HEAD，把固定的头部放在里面（前5个字节）
		Msg_Head_Tree:add(Box_Detect_VER,  buffer(0, 1))
		Msg_Head_Tree:add(Box_Detect_PATH, buffer(0, 1))
		Msg_Head_Tree:add(Box_Detect_CMD, buffer(0, 1))
		Msg_Head_Tree:add(Box_Detect_SN, buffer(1, 4))
		-- return Msg_Head_Tree
	end
	
	function Bitval(a, b)--读出位值
		return bit.band(a, b)
	end
	
	function Action(a, b)--输出当前所属动作，将协议列替换为动作
		local result = Bitval(a, b)
		-- get and set protocal name
		-- pinfo.cols.protocol = switch[result]
		-- shifou kekyi ba switch biancheng yige hanshu,yonglai juti chuli meige cmd yao zuo shenme 
		local switch = {
			[1] = function()
				pinfo.cols.protocal = "ACK"
			end,
			[2] = function()
				pinfo.cols.protocal = "SYN"
			end,
			-- 3 4 5 ....
			[3] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[4] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[5] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[6] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[7] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[8] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[9] = function()
				pinfo.cols.protocal = "HANDSHAKE_ACK"			
				subtree:add:(Box_Detect_LPORT, buffer(6,2))
				New_Port = Bitval(buffer(6, 2):uint16(), 0xFFFF)
				-- TODO 
				-- udp.port:add(New_Port,  Box_Detect_Protocol)
			end,
			[10] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[11] = function()
				pinfo.cols.protocal = "SYN"
			end,
			[12] = function()
				pinfo.cols.protocal = "SYN"
			end
		}
		local func = switch[result]
		if func == "table" then func() end
		-- if result == 9 then
		-- 	subtree:add(Box_Detect_LPORT, buffer(6, 2))
		-- 	New_Port = Bitval(buffer(6, 2):uint16(), 0xFFFF)
		-- 	Port[New_Port] = true
		-- 	-- udp.port:add(New_Port,  Box_Detect_Protocol)
		-- 	return New_Port
		-- end
		return nil
		--后续增加
	end
	-- pinfo.port == 
	--发往节点901-903端口
	-- TODO if Port[pinfo.port] then do something end
	-- if pinfo.dst_port >= Start_Port and pinfo.dst_port <= End_Port then 
	if Port[pinfo.dst_port] or Port[pinfo.src_port] then
		Head()
		if Bitval(buffer(0, 1):uint(), 0x0F) == 1 then 
			subtree:add(Box_Detect_TOTALSIZE, buffer(5, 2))
		end 
		local New_Port = Action(buffer(0, 1):uint(), 0x0F)
		-- TODO
		-- how to add a new updport
		-- udp_table:add(New_Port, Box_Detect_Protocol)
	end

	--来自节点901-903端口
	-- if pinfo.src_port >= Start_Port and pinfo.src_port <= End_Port then
	-- 	Head()
	-- 	local result = Action(buffer(0, 1):uint(), 0x0F)
	-- 	if result then
	-- 	udp.port:add(New_Port,  Box_Detect_Protocol)
	-- 	--local a = buffer(0, 1):uint()
	-- 	--local b = bit.band(a, 0x0F)
	-- 	if Bitval(buffer(0, 1):uint(), 0x0F) == 1 then 
	-- 		subtree:add(Box_Detect_TOTALSIZE, buffer(5, 2))
	-- 	end 
		
	-- end

end
--4.注册到wirshark解析表
local udp_table = DissectorTable.get("udp.port")
udp_table:add("901-903",  Box_Detect_Protocol)