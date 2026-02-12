#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h> /* bpf_core_type_id_local */
#include "xdp/parsing_helpers.h"

#define MAX_CHECKING 4
#define MAX_CSUM_WORDS 750

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

/*
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} time_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");
*/

static inline __u16 csum_fold_helper(__u64 csum) {
    __u32 sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum; // Retorna o complemento de um
}

static inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum = 0;
    __u16 *next_iph_u16 = (__u16 *)iph;

    // Cabeçalho IP padrão tem 5 palavras de 32 bits (10 palavras de 16 bits)
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        csum += *next_iph_u16++;
    }
    return csum_fold_helper(csum);
}

static __always_inline void tcp_checksum(struct tcphdr *tcph)
{
	struct tcphdr tcph_old;
	__u32 csum = tcph->check;
	tcph_old = *tcph;
	csum = bpf_csum_diff((__be32 *)&tcph_old, 4, (__be32 *)tcph, 4, ~csum);
	tcph->check = csum_fold_helper(csum);
}

static __always_inline int cut_packet(struct xdp_md* ctx, struct hdr_cursor* nh, int delta){
	__u16 new_size;
	int eth_type;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;

	if(bpf_xdp_adjust_tail(ctx, 0-delta) < 0){
		bpf_printk("Deu pau 1\n");
		return XDP_ABORTED;
	}
	// After Adjusting packet size, every check must be performed again!
	void* data = (void *)(long)ctx->data;
	void* data_end = (void *)(long)ctx->data_end;

	nh->pos = data;
	eth_type = parse_ethhdr(nh, data_end, &eth);

	if (eth_type == bpf_htons(ETH_P_IP)) {
		iph = nh->pos;
		if (iph + 1 > data_end) return -1;

		// Update IP total length
		new_size = bpf_ntohs(iph->tot_len) - delta;
		iph->tot_len = bpf_htons(new_size);
		iph->check = iph_csum(iph);

		int ip_type = parse_iphdr(nh, data_end, &iph);
		if (ip_type == IPPROTO_TCP) {
			if (parse_tcphdr(nh, data_end, &tcph) > 0) {
				tcp_checksum(tcph);
			}
			else return -1;
		}
		
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6)){
		ip6h = nh->pos;
		if (ip6h + 1 > data_end) return -1;

		//PRECISA DESCOBRIR COMO ATUALIZAR O TAMANHO DO	CABEÇALHO IPv6
		new_size = 1;
		ip6h->payload_len = bpf_htons(new_size);
	}
	return 1;
}

SEC("xdp")
int xdp_ids_func(struct xdp_md *ctx)
{
    //__u64 time;
    //time = bpf_ktime_get_ns();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct hdr_cursor nh;
    int eth_type = 0, ip_type = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;

    void* end_ip;
    void* end_ip6;

    nh.pos = data;
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iph);
	end_ip = nh.pos;
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        ip_type = parse_ip6hdr(&nh, data_end, &ip6h);
	end_ip6 = nh.pos;
    }
    else{
	//bpf_printk("Jesus");
        // Se não for nem IP nem IPv6 (ARP, por exemplo), descarta
        return XDP_DROP;
    }

    void *end_tcp = NULL;
    void *end_udp = NULL;
    char* letter;
    char method[3];
    int delta;
    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) > 0) {
                if (nh.pos + sizeof(tcph) > data_end){
                        return XDP_ABORTED;
                }
                end_tcp = nh.pos;
                letter = nh.pos + 1;
                if (*letter == 'E' || *letter == 'O'){
                        method[0] = *((char*)nh.pos);
                        method[1] = *letter;
                        method[2] = '\0';
                        //bpf_printk("Metodo do HTTP: %s\n", method);
                        char* new_content = (char*)end_tcp;
                        if (new_content + sizeof(method) > data_end)
                                return XDP_ABORTED;

                        #pragma unroll
                        for(int i = 1; i < sizeof(method); i++){
                                *(new_content + i) = *(method + i);
                        }

                        delta = data_end - (end_tcp + 3);
                        //bpf_printk("Delta: %d\n", delta);
			
			if(cut_packet(ctx, &nh, delta) < 0){
				bpf_printk("Failed while cutting packets - HTTP!");
				return XDP_ABORTED;
				
			}
			goto success;


                }
                else{
			// TCP but not HTTP packets!
                        delta = data_end - end_tcp;
			if(cut_packet(ctx, &nh, delta) < 0){
				bpf_printk("Failed while cutting packets - TCP without HTTP!");
				return XDP_ABORTED;
				
			}
			goto success;
                }
        }
	else{
		bpf_printk("Error while parsing!");
		return XDP_ABORTED;
	}
    }
    // UDP packet
    else if (ip_type == IPPROTO_UDP) {
	    if (parse_udphdr(&nh, data_end, &udph) > 0) {
		    if (nh.pos + sizeof(udph) > data_end){
			    return XDP_ABORTED;
		    }
		    end_udp = nh.pos;

		    delta = data_end - end_udp;
		    if(cut_packet(ctx, &nh, delta) < 0){
			    bpf_printk("Failed while cutting packets - TCP without HTTP!");
			    return XDP_ABORTED;

		    }
		    goto success;
	    }
    }
    // non TCP nor UDP packet
    else {
	    if (eth_type == bpf_htons(ETH_P_IP)) {
		    delta = data_end - end_ip;
		    if(cut_packet(ctx, &nh, delta) < 0){
			    bpf_printk("Failed while cutting packets - TCP without HTTP!");
			    return XDP_ABORTED;

		    }
		    goto success;
	    }
	    else if (eth_type == bpf_htons(ETH_P_IPV6)){
		    delta = data_end - end_ip6;
		    if(cut_packet(ctx, &nh, delta) < 0){
			    bpf_printk("Failed while cutting packets - TCP without HTTP!");
			    return XDP_ABORTED;

		    }
		    goto success;
	    }
		
	}
success:
	/*
    __u32 k = 0;
    __u64 *v, diff;
    v = bpf_map_lookup_elem(&time_map, &k);
    if (v) {
	*v = *v + 1;
    }
	*/
    return XDP_PASS;
}

char _license [] SEC ("license") = "GPL";

