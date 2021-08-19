#include <rte_thash.h>
#include <stdlib.h>

#define IPv4(a, b, c, d) ((uint32_t)(((a) & 0xff) << 24) |		\
	(((c) & 0xff) << 8) |						\
	((d) & 0xff))

int main() {
    uint8_t rss_key[40];
    uint8_t num_queues = 8;
    uint16_t queue_assignments[8];

    uint32_t i, q_i, ctr, sport, hash_result, target = 64512/num_queues;
    union rte_thash_tuple tuple;

    uint16_t errors, min_errors = 65535;

    for (i = 23149; i < 65536; i++)
    {
        for ( ctr = 0; ctr < 40; ctr += 2 )
        {
            rss_key[ctr] = i & 0xff;
            rss_key[ctr+1] = (i & 0xff00) >> 8;
        }

        for ( q_i = 0; q_i < num_queues; q_i++ )
            queue_assignments[q_i] = 0;

        for ( sport = 1024; sport < 65536; sport++ )
            {
            tuple.v4.src_addr = IPv4(142, 231, 1, 129);
            tuple.v4.dst_addr = IPv4(198, 128, 151, 17);
            tuple.v4.dport = 53;
            tuple.v4.sport = sport;
            hash_result = rte_softrss((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN, rss_key);

            queue_assignments[hash_result % num_queues] += 1;
            }

//        printf("key is 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x, q[0]=%d\n", rss_key[0], rss_key[1], rss_key[2], rss_key[3], rss_key[4], rss_key[5], rss_key[6], rss_key[7], queue_assignments[0]);

        errors = 0;
        for ( q_i = 0; q_i < num_queues; q_i++ )
            {
            //printf("queue[%d] = %d. Delta=%d\n", q_i, queue_assignments[q_i], abs((uint16_t)queue_assignments[q_i] - (uint16_t)target));
            errors += abs((uint16_t)queue_assignments[q_i] - (uint16_t)target);
            }

            printf("Winning key is 0x%x 0x%x, %d:%d:%d:%d:%d:%d:%d:%d with %d errors\n", 
            rss_key[0], rss_key[1], queue_assignments[0], queue_assignments[1], 
            queue_assignments[2], queue_assignments[3], queue_assignments[4], queue_assignments[5], 
            queue_assignments[6], queue_assignments[7], 
            errors);

        if ( errors < min_errors )
        {
            printf("Winning key is 0x%x 0x%x, %d:%d:%d:%d:%d:%d:%d:%d with %d errors\n", 
            rss_key[0], rss_key[1], queue_assignments[0], queue_assignments[1], 
            queue_assignments[2], queue_assignments[3], queue_assignments[4], queue_assignments[5], 
            queue_assignments[6], queue_assignments[7], 
            errors);
            min_errors = errors;
        }
    }

    return 0;
}