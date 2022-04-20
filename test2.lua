local Start_Port = 901
local End_Port = 903
--定义自己协议的字段
local Vals_Bit_1 = {[0x01] = "0x01"}
local Vals_Bit_2 = {[0x00] = "single path",[0x01] = "main path",[0x02] = "vice path"}
local Vals_Bit_3 = {[0x01] = "ACK",[0x02] = "SYN",[0x03] = "SYN_ACK",[0x04] = "FIN",[0x05] = "FIN_ACK",[0x06] = "DATA_MEASURE",[0x07] = "DATA",[0x08] = "HANDSHAKE",[0x09] = "HANDSHAKE_ACK",[0x0A] = "ECHO request",[0x0B] = "HANG_UP",[0x0C] = "AUTHORIZE"}


local Box_Detect_VER = ProtoField.uint8("Box_Detect.Message_version","VER",base.DEC,Vals_Bit_1,0xC0)--2bit
local Box_Detect_PATH = ProtoField.uint8("Box_Detect.Message_path","PATH",base.DEC,Vals_Bit_2,0x30)--2bit
local Box_Detect_CMD = ProtoField.uint8("Box_Detect.Message_cmd","CMD",base.DEC,Vals_Bit_3,0x0F)--4bit
local Box_Detect_SN = ProtoField.uint32("Box_Detect.Message_sn","SN",base.DEC)
local Box_Detect_TOTALSIZE = ProtoField.uint16("Box_Detect.message_totalsize","TOTALSIZE",base.DEC)
--1.创建解析器对象
Box_Detect_Protocol = Proto("Box_Detect","Box_Detect Protocol")
--2.添加字段
Box_Detect_Protocol.fields = {Box_Detect_VER,Box_Detect_PATH,Box_Detect_CMD,Box_Detect_SN,Box_Detect_TOTALSIZE}
--3.解析器函数，此函数由wireshark调用
function Box_Detect_Protocol.dissector(buffer,pinfo,tree)
	length = buffer:len()
	if length == 0 then 
		return
	end
	local subtree = tree:add(Box_Detect_Protocol,buffer(),"Box_Detect_Protocol Data")

	function Head()
		local Msg_Head_Tree = subtree:add("HEAD",buffer(0,5))--加一层HEAD，把固定的头部放在里面（前5个字节）
			Msg_Head_Tree:add(Box_Detect_VER, buffer(0,1))
			Msg_Head_Tree:add(Box_Detect_PATH,buffer(0,1))
			Msg_Head_Tree:add(Box_Detect_CMD,buffer(0,1))
			Msg_Head_Tree:add(Box_Detect_SN,buffer(1,4))
	end
	
	function Bitval(a,b)--读出位值
		return bit.band(a,b)
	end
	
	function Action(a,b)--输出当前所属动作，将协议列替换为动作
		local result = Bitval(a,b)
		--需要优化，if-else使用元表替代
		if result == 1 or result == 10 then--CMD为1或10是探测的动作
			pinfo.cols.protocol = "Box_Mtu_Detect"
		end
		if result == 8 or result == 9 then--CMD为8或9是握手的动作
			pinfo.cols.protocol = "Hand_Shake"
		end
		--后续增加
	end
	
	--发往节点901-903端口
	if pinfo.dst_port >= Start_Port and pinfo.dst_port <= End_Port then 
		Head()
		Action(buffer(0,1):uint(),0x0F)
	end

	--来自节点901-903端口
	if pinfo.src_port >= Start_Port and pinfo.src_port <= End_Port then
		Head()
		Action(buffer(0,1):uint(),0x0F)
		--local a = buffer(0,1):uint()
		--local b = bit.band(a,0x0F)
		if Bitval(buffer(0,1):uint(),0x0F) == 1 then 
			subtree:add(Box_Detect_TOTALSIZE,buffer(5,2))
		end 
		
	end

end
--4.注册到wirshark解析表
DissectorTable.get("udp.port"):add("901-903", Box_Detect_Protocol)
