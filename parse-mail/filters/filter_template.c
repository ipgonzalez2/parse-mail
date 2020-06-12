#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>


#define IP_TCP 	6
#define ETH_HLEN 14

int mail_filter_{{id}}(struct __sk_buff *skb) {

	u8 *cursor = 0;
	
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

	//filter TCP packets (ip next proocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

    //check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		goto DROP;
	}

    //shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	
	if(tcp->dst_port != 25){
		goto KEEP;
	}

	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;
	

	//search where de message begins
	char c1,prev=',';
	u32 i = 1;
	c1 = load_byte(skb,payload_offset);
	

	while (i<4000){
		prev=c1;
		c1 = load_byte(skb,payload_offset+i);
		if(c1 == prev && prev == '\n')
			goto BREAK;

		i++;
	}

	BREAK: ;

	//mail's start
	i++;

	//get message's size(total size - start)
    u32 size = payload_length - i;
    u32 tamanho = {{tam}};

    if(size != tamanho){
    	goto KEEP;
    }

	//Checks random characters
	int j = 0;
    char p[{{numCar}}];

	int x = {{x}};

	 for ( j = 0; j < sizeof(p); j++)
    {
        int desp = i + (x*j);
        p[j] = load_byte(skb, payload_offset+desp);
    }
    
    bool isSpam = true;
    char cars[{{numCar}}] = {{caracteres}};

    for (j = 0; j < sizeof(p); j++){
    	if(p[j] != cars[j]){
    		isSpam = false;
    	}
    }

	//match
    if(isSpam){
    	goto DROP;
    }

	//no match
	goto KEEP;

	//keep the packet and send it to userspace retruning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;


}
