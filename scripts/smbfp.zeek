@load base/protocols/smb

module smbfp;

redef record SMB::FileInfo += {
	smbfp_cl: string &log &optional;
};

redef record SMB::TreeInfo += {
	smbfp_cl: string &log &optional;
};

redef record SMB::State += {
	smbfp_cl_str: string &log &optional;
};


# SMB 1
# Fingerprint off of both the initial negotation and the AndX negotation (if present)

event smb1_negotiate_request(c: connection, hdr: SMB1::Header, dialects: string_vec) {
        if (!c$smb_state ?$ smbfp_cl_str)
                c$smb_state$smbfp_cl_str = to_json(dialects);
        else
                c$smb_state$smbfp_cl_str = string_cat(c$smb_state$smbfp_cl_str, ",", to_json(dialects));
}

event  smb1_session_setup_andx_request(c: connection, hdr: SMB1::Header, request: SMB1::SessionSetupAndXRequest) &priority=4 {
        local request_str = "";
        local sep = ",";

        # Create string based on values that are not payload dependent.
        if (request ?$ max_buffer_size)
                request_str = string_cat(request_str, sep, cat(request$max_buffer_size));
        if (request ?$ max_mpx_count)
                request_str = string_cat(request_str, sep, cat(request$max_mpx_count));
        if (request ?$ native_os)
                request_str = string_cat(request_str, sep, request$native_os);
        if (request ?$ native_lanman)
                request_str = string_cat(request_str, sep, request$native_lanman);
        if (request ?$ primary_domain)
                request_str = string_cat(request_str, sep, request$primary_domain);
        if (request ?$ capabilities) {
                if (request$capabilities ?$ unicode)
                        request_str = string_cat(request_str, sep, cat(request$capabilities$unicode));
                if (request$capabilities ?$ level_2_oplocks)
                        request_str = string_cat(request_str, sep, cat(request$capabilities$level_2_oplocks));
        }

        if (!c$smb_state ?$ smbfp_cl_str)
                c$smb_state$smbfp_cl_str = request_str;
        else
                c$smb_state$smbfp_cl_str = string_cat(c$smb_state$smbfp_cl_str, ",", request_str);

        c$smb_state$tid_map[hdr$tid]$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

# SMB 2
# Can only fingerprint off the initial negotiation
# TODO: Patch Zeek to pass a SMB2::NegotiateContextValues object alongside the dialects
event smb2_negotiate_request(c: connection, hdr: SMB2::Header, dialects: index_vec) {
	if (!c$smb_state ?$ smbfp_cl_str)
                c$smb_state$smbfp_cl_str = to_json(dialects);
        else
                c$smb_state$smbfp_cl_str = string_cat(c$smb_state$smbfp_cl_str, ",", to_json(dialects));
}

# We have to set the client fingerprint field after the tree/file record is actually initialized

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_cmd$referenced_tree$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_cmd$referenced_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb1_read_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, length: count) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb1_write_andx_request(c: connection, hdr: SMB1::Header, file_id: count, offset: count, data_len: count) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb1_close_request(c: connection, hdr: SMB1::Header, file_id: count) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

# SMB2

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) &priority=4 {
	if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_tree$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}            

event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_read_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_write_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, offset: count, length: count) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_file_sattr(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, times: SMB::MACTimes, attrs: SMB2::FileAttrs) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_file_rename(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, dst_filename: string) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_file_delete(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID, delete_pending: bool) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}

event smb2_close_request(c: connection, hdr: SMB2::Header, file_id: SMB2::GUID) &priority=4 {
        if (c$smb_state?$smbfp_cl_str) 
                c$smb_state$current_file$smbfp_cl = md5_hash(c$smb_state$smbfp_cl_str);
}