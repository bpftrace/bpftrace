// clang-format off
#define __BPF_FUNC_MAPPER(FN)    \
	FN(unspec),                    \
	FN(map_lookup_elem),           \
	FN(map_update_elem),           \
	FN(map_delete_elem),           \
	FN(probe_read),                \
	FN(ktime_get_ns),              \
	FN(trace_printk),              \
	FN(get_prandom_u32),           \
	FN(get_smp_processor_id),      \
	FN(skb_store_bytes),           \
	FN(l3_csum_replace),           \
	FN(l4_csum_replace),           \
	FN(tail_call),                 \
	FN(clone_redirect),            \
	FN(get_current_pid_tgid),      \
	FN(get_current_uid_gid),       \
	FN(get_current_comm),          \
	FN(get_cgroup_classid),        \
	FN(skb_vlan_push),             \
	FN(skb_vlan_pop),              \
	FN(skb_get_tunnel_key),        \
	FN(skb_set_tunnel_key),        \
	FN(perf_event_read),           \
	FN(redirect),                  \
	FN(get_route_realm),           \
	FN(perf_event_output),         \
	FN(skb_load_bytes),            \
	FN(get_stackid),               \
	FN(csum_diff),                 \
	FN(skb_get_tunnel_opt),        \
	FN(skb_set_tunnel_opt),        \
	FN(skb_change_proto),          \
	FN(skb_change_type),           \
	FN(skb_under_cgroup),          \
	FN(get_hash_recalc),           \
	FN(get_current_task),          \
	FN(probe_write_user),          \
	FN(current_task_under_cgroup), \
	FN(skb_change_tail),           \
	FN(skb_pull_data),             \
	FN(csum_update),               \
	FN(set_hash_invalid),          \
	FN(get_numa_node_id),          \
	FN(skb_change_head),           \
	FN(xdp_adjust_head),           \
	FN(probe_read_str),            \
	FN(get_socket_cookie),         \
	FN(get_socket_uid),            \
	FN(set_hash),                  \
	FN(setsockopt),                \
	FN(skb_adjust_room),           \
	FN(redirect_map),              \
	FN(sk_redirect_map),           \
	FN(sock_map_update),           \
	FN(xdp_adjust_meta),           \
	FN(perf_event_read_value),     \
	FN(perf_prog_read_value),      \
	FN(getsockopt),                \
	FN(override_return),           \
	FN(sock_ops_cb_flags_set),     \
	FN(msg_redirect_map),          \
	FN(msg_apply_bytes),           \
	FN(msg_cork_bytes),            \
	FN(msg_pull_data),             \
	FN(bind),                      \
	FN(xdp_adjust_tail),           \
	FN(skb_get_xfrm_state),        \
	FN(get_stack),                 \
	FN(skb_load_bytes_relative),   \
	FN(fib_lookup),                \
	FN(sock_hash_update),          \
	FN(msg_redirect_hash),         \
	FN(sk_redirect_hash),          \
	FN(lwt_push_encap),            \
	FN(lwt_seg6_store_bytes),      \
	FN(lwt_seg6_adjust_srh),       \
	FN(lwt_seg6_action),           \
	FN(rc_repeat),                 \
	FN(rc_keydown),                \
	FN(skb_cgroup_id),             \
	FN(get_current_cgroup_id),     \
	FN(get_local_storage),         \
	FN(sk_select_reuseport),       \
	FN(skb_ancestor_cgroup_id),    \
	FN(sk_lookup_tcp),             \
	FN(sk_lookup_udp),             \
	FN(sk_release),                \
	FN(map_push_elem),             \
	FN(map_pop_elem),              \
	FN(map_peek_elem),             \
	FN(msg_push_data),             \
	FN(msg_pop_data),              \
	FN(rc_pointer_rel),            \
	FN(spin_lock),                 \
	FN(spin_unlock),               \
	FN(sk_fullsock),               \
	FN(tcp_sock),                  \
	FN(skb_ecn_set_ce),            \
	FN(get_listener_sock),         \
	FN(skc_lookup_tcp),            \
	FN(tcp_check_syncookie),       \
	FN(sysctl_get_name),           \
	FN(sysctl_get_current_value),  \
	FN(sysctl_get_new_value),      \
	FN(sysctl_set_new_value),      \
	FN(strtol),                    \
	FN(strtoul),                   \
	FN(sk_storage_get),            \
	FN(sk_storage_delete),         \
	FN(send_signal),               \
	FN(tcp_gen_syncookie),         \
	FN(skb_output),                \
	FN(probe_read_user),           \
	FN(probe_read_kernel),         \
	FN(probe_read_user_str),       \
	FN(probe_read_kernel_str),     \
	FN(tcp_send_ack),              \
	FN(send_signal_thread),        \
	FN(jiffies64),


/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN
// clang-format on
