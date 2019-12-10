#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>


#define IP_TCP 	6
#define ETH_HLEN 14

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/

struct char_1
{
    char c;
} BPF_PACKET_HEADER;

int http_filter(struct __sk_buff *skb) {

	u8 *cursor = 0;
	u8 *cursor2 = 0;
	
	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	void *v1 = cursor_advance(cursor2, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	void *v2 = cursor_advance(cursor2, sizeof(*ip));
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
	void *v3 = cursor_advance(cursor2, (ip_header_length-sizeof(*ip)));

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
	void *v4 = cursor_advance(cursor2, sizeof(*tcp));

	//DE momento pruebas no
	/*if(tcp->dst_port != 25){
		goto DROP;
	}*/

	/*if(!(tcp->offset == 0)){
		goto DROP;
	}*/

	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	//calculate payload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

	//http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	//minimum length of http request is always geater than 7 bytes
	//avoid invalid access memory
	//include empty payload
	
	struct char_1 *c;
	c = cursor_advance(cursor, sizeof(*c));

	while(c->c != '\n'){
		c = cursor_advance(cursor, 1);
	}

	c = cursor_advance(cursor, 1);



/*
	//Se pasa al crear el programa
	u32 tamañoMensaje = 804;


	//Se calcula aquí, ya que es variable
	int inicioMensaje = payload_length - tamañoMensaje;

	if(payload_length < tamañoMensaje) {
		goto DROP;
	}

	int i = 0;
	char p[4];

	int x =tamañoMensaje/4;

	for ( i = 0; i < sizeof(p); i++)
	{
		int desp = inicioMensaje + (x*i);
		p[i] = load_byte(skb, payload_offset+desp);
	}

	//Los carácteres concretos se pasan al crear el programa
	if ((p[0] == '<') && (p[1] == '"') && (p[2] == '4') && (p[3] == 'n')) {
		goto KEEP;
	}*/

	if(c->c == 'R'){
		goto KEEP;
	}
	
	//no HTTP match
	goto DROP;

	//keep the packet and send it to userspace retruning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;


}
