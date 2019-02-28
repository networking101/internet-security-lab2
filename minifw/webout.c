#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops webOutFilterHook;

unsigned int webOutFilter(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(80)
	&& (unsigned int)((unsigned char *)&iph->daddr)[0] == 104
	&& (unsigned int)((unsigned char *)&iph->daddr)[1] == 196
	&& (unsigned int)((unsigned char *)&iph->daddr)[2] == 201
	&& (unsigned int)((unsigned char *)&iph->daddr)[3] == 207) {
    printk(KERN_INFO "Dropping web packet to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  } else {
    return NF_ACCEPT;
  }
}


int setUpFilter(void) {
        printk(KERN_INFO "Registering a web filter.\n");
        webOutFilterHook.hook = webOutFilter; 
        webOutFilterHook.hooknum = NF_INET_POST_ROUTING;
        webOutFilterHook.pf = PF_INET;
        webOutFilterHook.priority = NF_IP_PRI_FIRST;

        // Register the hook.
        nf_register_hook(&webOutFilterHook);
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Web filter is being removed.\n");
        nf_unregister_hook(&webOutFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");


