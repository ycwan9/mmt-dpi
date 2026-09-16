/* Generated with MMT Plugin Generator */
#include "mmt_core.h"
#include "plugin_defs.h"
#include "extraction_lib.h"
#include "../mmt_common_internal_include.h"

#include "arp.h"
#include "ip_session_id_management.h"

/////////////// PROTOCOL INTERNAL CODE GOES HERE ///////////////////

// ARP session keyed by SPA+TPA (IP pair), ordered like IP sessions
static void *arp_sessionizer(void *protocol_context, ipacket_t *ipacket, unsigned index, int *is_new_session) {
    int offset = get_packet_offset_at_index(ipacket, index);
    if (offset < 0) {
        *is_new_session = 0;
        return NULL;
    }
    // Only Ethernet/IPv4 ARP (hrd=1, pro=0x0800) is sessionized
    uint16_t hrd = ntohs(*(uint16_t *)&ipacket->data[offset + 0]);
    uint16_t pro = ntohs(*(uint16_t *)&ipacket->data[offset + 2]);
    if (hrd != 0x0001 || pro != 0x0800) {
        *is_new_session = 0;
        return NULL;
    }
    uint32_t spa, tpa;
    memcpy(&spa, &ipacket->data[offset + 14], sizeof(uint32_t));
    memcpy(&tpa, &ipacket->data[offset + 24], sizeof(uint32_t));


    mmt_session_key_t key;
    memset(&key, 0, sizeof(key));
    key.ip_type = 4;
    key.next_proto = 0;
    key.lower_ip_port = 0;
    key.higher_ip_port = 0;
    if (spa < tpa) {
        key.lower_ip = &spa;
        key.higher_ip = &tpa;
        key.is_lower_initiator = 0;
        key.is_lower_client = 0;
    } else if (spa == tpa) {
        key.lower_ip = &spa;
        key.higher_ip = &tpa;
        key.is_lower_initiator = 0;
        key.is_lower_client = 0;
    } else {
        key.lower_ip = &tpa;
        key.higher_ip = &spa;
        key.is_lower_initiator = 1;
        key.is_lower_client = 1;
    }
    // spa vs tpa determines this packet's direction relative to ordered key
    // If spa == lower, direction is L2H (0), else H2L (1)
    // For spa==tpa, direction 0
    uint8_t this_pkt_dir;
    if (spa == tpa) this_pkt_dir = 0;
    else if (spa < tpa) this_pkt_dir = 0;
    else this_pkt_dir = 1;
    // get_session will copy key and allocate persistent IP ids
    extern mmt_session_t *get_session(void *, mmt_session_key_t *, ipacket_t *, int *);
    mmt_session_t *session = get_session(protocol_context, &key, ipacket, is_new_session);
    if (session) {
        session->last_packet_direction = this_pkt_dir;
        // Also set setup direction for new sessions (mirrors IP)
        if (*is_new_session) session->setup_packet_direction = this_pkt_dir;
    }
    return session;
}
int arp_session_cleanup_on_timeout(void *protocol_context, mmt_session_t *timedout_session, void *args) {
    extern int delete_session_from_protocol_context(void *, void *);
    extern void free_session_data(void *, void *, void *);
    delete_session_from_protocol_context(protocol_context, timedout_session->session_key);
    free_session_data(timedout_session->session_key, timedout_session, ((protocol_instance_t *)protocol_context)->args);
    return 0;
}
static void *arp_setup_context(void *protocol_context, void *args) {
    (void)protocol_context;(void)args;
    extern internal_ip_proto_context_t *setup_ipv4_internal_context();
    return setup_ipv4_internal_context();
}
static void arp_cleanup_context(void *protocol_context, void *args) {
    (void)args;
    protocol_instance_t *pi = (protocol_instance_t *)protocol_context;
    if (pi && pi->args) {
        extern int cleanup_ipv4_internal_context(internal_ip_proto_context_t *);
        extern void close_ipv4_internal_context(protocol_instance_t *);
        cleanup_ipv4_internal_context((internal_ip_proto_context_t *)pi->args);
        close_ipv4_internal_context(pi);
    }
}


static uint16_t arp_ar_hrd_get_value     (const ipacket_t * packet, unsigned proto_index);
static uint16_t arp_ar_pro_get_value     (const ipacket_t * packet, unsigned proto_index);
static uint8_t  arp_ar_hln_get_value     (const ipacket_t * packet, unsigned proto_index);
static uint8_t  arp_ar_pln_get_value     (const ipacket_t * packet, unsigned proto_index);
/*
static uint32_t arp_ar_sha_get_offset    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_sha_get_length    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_sip_get_value     (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_sip_get_offset    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_sip_get_length    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_tha_get_offset    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_tha_get_length    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_tip_get_value     (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_tip_get_offset    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_ar_tip_get_length    (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_src_hard_get_offset  (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_src_hard_get_length  (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_src_proto_get_offset (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_src_proto_get_length (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_dst_hard_get_offset  (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_dst_hard_get_length  (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_dst_proto_get_offset (const ipacket_t * packet, unsigned proto_index);
static uint32_t arp_dst_proto_get_length (const ipacket_t * packet, unsigned proto_index);
*/

static int arp_ar_sha_extraction    (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_ar_sip_extraction    (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_ar_tha_extraction    (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_ar_tip_extraction    (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_src_hard_extraction  (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_src_proto_extraction (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_dst_hard_extraction  (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);
static int arp_dst_proto_extraction (const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data);


/*
 * ARP data extraction routines
 */

int arp_ar_sha_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        int attribute_offset = 8;
        int attribute_length = 6;
        memcpy((u_char *) extracted_data->data, (char *) & packet->data[proto_offset + attribute_offset], attribute_length);
        return 1;
    }

    return 0;
}

int arp_ar_sip_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        int attribute_offset = 14;
        //int attribute_length = 4;
        *((unsigned int *) extracted_data->data) = (*((unsigned int *) & packet->data[proto_offset + attribute_offset]));

        return 1;
    }

    return 0;
}

int arp_ar_tha_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        int attribute_offset = 18;
        int attribute_length = 6;
        memcpy((u_char *) extracted_data->data, (char *) & packet->data[proto_offset + attribute_offset], attribute_length);

        return 1;
    }

    return 0;
}

int arp_ar_tip_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        int attribute_offset = 24;
        //int attribute_length = 4;
        *((unsigned int *) extracted_data->data) = (*((unsigned int *) & packet->data[proto_offset + attribute_offset]));

        return 1;
    }

    return 0;
}

int arp_src_hard_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        ;
    } else {
        /* Get the attribute offset (relative the to protocol) */
        int attribute_offset = sizeof (struct arphdr);
        /* Get the attribute data length */
        int attribute_length = arp_ar_hln_get_value(packet, proto_index);

        *((unsigned int *) extracted_data->data) = attribute_length;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & packet->data[proto_offset + attribute_offset], attribute_length);

        return 1;
    }

    return 0;
}

int arp_src_proto_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        ;
    } else {
        /* Get the attribute offset (relative the to protocol) */
        int attribute_offset = sizeof (struct arphdr) +arp_ar_hln_get_value(packet, proto_index);
        /* Get the attribute data length */
        int attribute_length = arp_ar_pln_get_value(packet, proto_index);

        *((unsigned int *) extracted_data->data) = attribute_length;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & packet->data[proto_offset + attribute_offset], attribute_length);

        return 1;
    }

    return 0;
}

int arp_dst_hard_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        ;
    } else {
        /* Get the attribute offset (relative the to protocol) */
        int attribute_offset = sizeof (struct arphdr) +arp_ar_pln_get_value(packet, proto_index) + arp_ar_hln_get_value(packet, proto_index);
        /* Get the attribute data length */
        int attribute_length = arp_ar_hln_get_value(packet, proto_index);

        *((unsigned int *) extracted_data->data) = attribute_length;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & packet->data[proto_offset + attribute_offset], attribute_length);

        return 1;
    }

    return 0;
}

int arp_dst_proto_extraction(const ipacket_t * packet, unsigned proto_index, attribute_t * extracted_data)
{
    /* Get the protocol offset */
    int proto_offset = get_packet_offset_at_index(packet, proto_index);

    if (arp_ar_hrd_get_value(packet, proto_index) == 0x0001 && arp_ar_pro_get_value(packet, proto_index) == 0x0800) {
        ;
    } else {
        /* Get the attribute offset (relative the to protocol) */
        int attribute_offset = sizeof (struct arphdr) +arp_ar_pln_get_value(packet, proto_index) + 2 * arp_ar_hln_get_value(packet, proto_index);
        /* Get the attribute data length */
        int attribute_length = arp_ar_pln_get_value(packet, proto_index);

        *((unsigned int *) extracted_data->data) = attribute_length;
        memcpy(& ((u_char *) extracted_data->data)[sizeof (int) ], & packet->data[proto_offset + attribute_offset], attribute_length);

        return 1;
    }

    return 0;
}


static attribute_metadata_t arp_attributes_metadata[ARP_ATTRIBUTES_NB] = {
    { ARP_AR_HRD,    ARP_AR_HRD_ALIAS,    MMT_U16_DATA,      sizeof(uint16_t),        0, SCOPE_PACKET, general_short_extraction_with_ordering_change },
    { ARP_AR_PRO,    ARP_AR_PRO_ALIAS,    MMT_U16_DATA,      sizeof(uint16_t),        2, SCOPE_PACKET, general_short_extraction_with_ordering_change },
    { ARP_AR_HLN,    ARP_AR_HLN_ALIAS,    MMT_U8_DATA,       sizeof(uint8_t),         4, SCOPE_PACKET, general_char_extraction                       },
    { ARP_AR_PLN,    ARP_AR_PLN_ALIAS,    MMT_U8_DATA,       sizeof(uint8_t),         5, SCOPE_PACKET, general_char_extraction                       },
    { ARP_AR_OP,     ARP_AR_OP_ALIAS,     MMT_U16_DATA,      sizeof(uint16_t),        6, SCOPE_PACKET, general_short_extraction_with_ordering_change },
    { ARP_AR_SHA,    ARP_AR_SHA_ALIAS,    MMT_DATA_MAC_ADDR, sizeof(mac_addr_t),     -1, SCOPE_PACKET, arp_ar_sha_extraction                         },
    { ARP_AR_SIP,    ARP_AR_SIP_ALIAS,    MMT_DATA_IP_ADDR,  sizeof(uint32_t),       -1, SCOPE_PACKET, arp_ar_sip_extraction                         },
    { ARP_AR_THA,    ARP_AR_THA_ALIAS,    MMT_DATA_MAC_ADDR, sizeof(mac_addr_t),     -1, SCOPE_PACKET, arp_ar_tha_extraction                         },
    { ARP_AR_TIP,    ARP_AR_TIP_ALIAS,    MMT_DATA_IP_ADDR,  sizeof(uint32_t),       -1, SCOPE_PACKET, arp_ar_tip_extraction                         },
    { ARP_SRC_HARD,  ARP_SRC_HARD_ALIAS,  MMT_BINARY_DATA,   BINARY_64DATA_TYPE_LEN, -1, SCOPE_PACKET, arp_src_hard_extraction                       },
    { ARP_SRC_PROTO, ARP_SRC_PROTO_ALIAS, MMT_BINARY_DATA,   BINARY_64DATA_TYPE_LEN, -1, SCOPE_PACKET, arp_src_proto_extraction                      },
    { ARP_DST_HARD,  ARP_DST_HARD_ALIAS,  MMT_BINARY_DATA,   BINARY_64DATA_TYPE_LEN, -1, SCOPE_PACKET, arp_dst_hard_extraction                       },
    { ARP_DST_PROTO, ARP_DST_PROTO_ALIAS, MMT_BINARY_DATA,   BINARY_64DATA_TYPE_LEN, -1, SCOPE_PACKET, arp_dst_proto_extraction                      }
};

uint16_t arp_ar_hrd_get_value(const ipacket_t * packet, unsigned proto_index)
{
    uint16_t retval;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    retval = ntohs(*(uint16_t *) & packet->data[proto_offset + arp_attributes_metadata[0].position_in_packet]);
    return retval;
}

uint16_t arp_ar_pro_get_value(const ipacket_t * packet, unsigned proto_index)
{
    uint16_t retval;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    retval = ntohs(*(uint16_t *) & packet->data[proto_offset + arp_attributes_metadata[1].position_in_packet]);
    return retval;
}

uint8_t arp_ar_hln_get_value(const ipacket_t * packet, unsigned proto_index)
{
    uint8_t retval;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    retval = *(uint8_t *) & packet->data[proto_offset + arp_attributes_metadata[2].position_in_packet];
    return retval;
}

uint8_t arp_ar_pln_get_value(const ipacket_t * packet, unsigned proto_index)
{
    uint8_t retval;
    int proto_offset = get_packet_offset_at_index(packet, proto_index);
    retval = *(uint8_t *) & packet->data[proto_offset + arp_attributes_metadata[3].position_in_packet];
    return retval;
}


/////////////// END OF PROTOCOL INTERNAL CODE    ///////////////////

extern bool ipv4_session_comp(void *, void *);
int init_proto_arp_struct()
{
    protocol_t * protocol_struct = init_protocol_struct_for_registration(PROTO_ARP, PROTO_ARP_ALIAS);

    if (protocol_struct != NULL) {
        int i = 0;
        for (; i < ARP_ATTRIBUTES_NB; i++) {
            register_attribute_with_protocol(protocol_struct, &arp_attributes_metadata[i]);
        }
        register_sessionizer_function(protocol_struct, arp_sessionizer, arp_session_cleanup_on_timeout, ipv4_session_comp);
        register_proto_context_init_cleanup_function(protocol_struct, arp_setup_context, arp_cleanup_context, NULL);
        return register_protocol(protocol_struct, PROTO_ARP);
    } else {
        return -1;
    }
}

