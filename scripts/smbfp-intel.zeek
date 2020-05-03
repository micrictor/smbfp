@load base/frameworks/intel

export {
	redef Intel::read_files += {
		@DIR + "/smbfp.intel",
	};

	redef enum Intel::Type += {
		Intel::SMBFP,
	};

	redef enum Intel::Where += {
		SMB::IN_FP,
	};
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=4 {
        if (c$smb_state$current_cmd$referenced_tree ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_cmd$referenced_tree$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=4 {
        if (c$smb_state$current_cmd$referenced_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_cmd$referenced_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

# SMB2
event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=4 {
        if (c$smb_state$current_tree ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_tree$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}            

event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_file_sattr(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_file_rename(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, dst_filename: string) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_file_delete(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, delete_pending: bool) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=4 {
        if (c$smb_state$current_file ?$ smbfp_cl) 
			Intel::seen([$indicator=c$smb_state$current_file$smbfp_cl, $indicator_type=Intel::SMBFP, $conn=c, $where=SMB::IN_FP]);
}
