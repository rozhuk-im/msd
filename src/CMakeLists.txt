
set(MSD_BIN		msd.c
			msd_stat_text.c
			stream_hub.c
			stream_src.c
			stream_mpeg2ts.c
			liblcb/src/net/socket.c
			liblcb/src/net/socket_address.c
			liblcb/src/net/socket_options.c
			liblcb/src/net/utils.c
			liblcb/src/proto/http.c
			liblcb/src/proto/http_server.c
			liblcb/src/threadpool/threadpool.c
			liblcb/src/threadpool/threadpool_msg_sys.c
			liblcb/src/threadpool/threadpool_task.c
			liblcb/src/utils/cmd_line_daemon.c
			liblcb/src/utils/sys.c
			liblcb/src/utils/sys_res_limits_xml.c
			liblcb/src/utils/buf_str.c
			liblcb/src/utils/info.c
			liblcb/src/utils/ring_buffer.c
			liblcb/src/utils/log.c
			liblcb/src/utils/xml.c)

add_executable(msd ${MSD_BIN})
set_target_properties(msd PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(msd ${CMAKE_REQUIRED_LIBRARIES} ${CMAKE_EXE_LINKER_FLAGS})

install(TARGETS msd RUNTIME DESTINATION bin)
